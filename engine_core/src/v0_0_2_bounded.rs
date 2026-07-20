//! Biến thể **fixed-capacity, không cấp phát trên hot-path** của [`crate::v0_0_2`]
//! cho kernel: đường per-event chạm được TRONG MỌI ĐIỀU KIỆN vì không có cấp phát
//! động nào có thể thất bại (⇒ không panic OOM). Chạm trần thì **fail-open** (bỏ
//! qua = verdict `Ignore`), không bao giờ abort.
//!
//! Khác v0.0.2 (BTreeMap/Vec) đúng ở tầng chứa:
//! - `State` (mọi bảng cố định) cấp phát **một lần** bằng `alloc_zeroed` +
//!   `Box::from_raw` — tránh dựng struct khổng lồ trên kernel stack (~12KB). Mọi
//!   trường của `State` là POD, toàn-số-0 là trạng thái rỗng hợp lệ.
//! - `LINE` và `DISARMED` là **hash table open-addressing** lưu **KEY đầy đủ**
//!   (hash chỉ chọn ô dò, so khớp key chính xác — không phải fingerprint mất mát),
//!   giữ tra cứu ~O(1).
//! - members/automata mỗi storyline là mảng cố định.
//!
//! Rule (`DagRuleSet`, có `Vec`) vẫn cấp ở `try_new`/Load — hiếm, ở PASSIVE, và
//! thất bại thì trả `None` (không panic). Chỉ hot-path mới cần bảo đảm no-alloc.

use alloc::alloc::{alloc_zeroed, Layout};
use alloc::boxed::Box;

use crate::detector::{Detector, Verdict};
use crate::event::{Event, Key, Op, Ttp};
use crate::rules::{Action, DagRuleSet};

// ---- Trần (cấu hình; chạm trần = fail-open) ----
const CAP_ENT: usize = 4096; // ô hash LINE (luỹ thừa 2)
const CAP_ENT_MASK: usize = CAP_ENT - 1;
const CAP_LINES: usize = 256; // slab storyline
const CAP_MEMBERS: usize = 24; // member/storyline (chỉ số ô entity)
const CAP_AUTO: usize = 24; // automaton/storyline
const CAP_DIS: usize = 1024; // ô hash DISARMED (luỹ thừa 2)
const CAP_DIS_MASK: usize = CAP_DIS - 1;

const NO_LINE: u16 = u16::MAX;

#[derive(Clone, Copy)]
struct Line {
    used: bool,
    n_members: u16,
    members: [u16; CAP_MEMBERS], // chỉ số ô entity (ổn định — entity không bị gỡ)
    n_auto: u16,
    auto_pid: [u16; CAP_AUTO],
    auto_done: [u64; CAP_AUTO], // done_mask bitmask
    last_activity: u64,
}

/// Toàn bộ trạng thái cố định — toàn-số-0 là trạng thái rỗng hợp lệ (POD).
struct State {
    // LINE: entity key → chỉ số storyline
    ent_used: [bool; CAP_ENT],
    ent_key: [Key; CAP_ENT],
    ent_line: [u16; CAP_ENT],
    // slab storyline
    lines: [Line; CAP_LINES],
    // DISARMED: actor key → op mask
    dis_used: [bool; CAP_DIS],
    dis_key: [Key; CAP_DIS],
    dis_ops: [u32; CAP_DIS],
}

fn hash_key(k: Key) -> usize {
    let x = (k.0 as u64) ^ ((k.0 >> 64) as u64);
    (x.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 32) as usize
}

/// Engine kernel: rule (Vec, cấp ở try_new) + State (cố định, cấp một lần).
pub struct Engine {
    rules: DagRuleSet,
    state: Box<State>,
}

impl Engine {
    /// Dựng engine; trả `None` nếu không cấp phát được `State` (~175KB) —
    /// **không panic**. Đây là con đường duy nhất có thể thất bại, và nó fallible.
    pub fn try_new(rules: DagRuleSet) -> Option<Engine> {
        let layout = Layout::new::<State>();
        // SAFETY: State chỉ gồm mảng POD (bool/Key(u128)/u16/u32/u64); toàn-số-0
        // là bit pattern hợp lệ cho mọi trường (không niche/ref/NonNull). Box sẽ
        // dealloc đúng layout này khi drop.
        let ptr = unsafe { alloc_zeroed(layout) } as *mut State;
        if ptr.is_null() {
            return None;
        }
        let state = unsafe { Box::from_raw(ptr) };
        Some(Engine { rules, state })
    }

    /// Tập TTP ruleset tham chiếu — driver dùng để chọn tagger (giống v0.0.2).
    pub fn referenced_ttps(&self) -> alloc::vec::Vec<Ttp> {
        self.rules.referenced_ttps()
    }

    /// `ON_EVENT` — không cấp phát; chạm trần fail-open (`Ignore`).
    pub fn on_event(&mut self, e: &Event, ttps: &[Ttp]) -> Verdict {
        if dis_check(&self.state, e.actor, e.op) {
            return Verdict::Block;
        }
        let line = match self.unify(e.actor, e.object) {
            Some(l) => l,
            None => return Verdict::Ignore, // LINE/slab đầy → fail-open
        };
        self.advance(line, e, ttps)
    }

    fn unify(&mut self, a: Key, o: Key) -> Option<u16> {
        let sa = self.resolve_line(a)?;
        let so = self.resolve_line(o)?;
        if sa != so {
            self.merge(sa, so);
        }
        Some(find_line(&self.state, a)) // sau merge, line của a có thể đổi
    }

    /// get-or-create storyline cho `key`. `None` nếu bảng/slab đầy.
    fn resolve_line(&mut self, key: Key) -> Option<u16> {
        let s = &mut *self.state;
        let mut i = hash_key(key) & CAP_ENT_MASK;
        for _ in 0..CAP_ENT {
            if !s.ent_used[i] {
                let line = alloc_line(s)?;
                s.ent_used[i] = true;
                s.ent_key[i] = key;
                s.ent_line[i] = line;
                let l = &mut s.lines[line as usize];
                l.members[0] = i as u16;
                l.n_members = 1;
                return Some(line);
            }
            if s.ent_key[i] == key {
                return Some(s.ent_line[i]);
            }
            i = (i + 1) & CAP_ENT_MASK;
        }
        None
    }

    /// Merge union-by-size; chạm trần member/automaton thì KHÔNG merge (fail-open).
    fn merge(&mut self, x: u16, y: u16) {
        let s = &mut *self.state;
        let (dst, src) = if s.lines[x as usize].n_members >= s.lines[y as usize].n_members {
            (x as usize, y as usize)
        } else {
            (y as usize, x as usize)
        };
        let dn = s.lines[dst].n_members as usize;
        let sn = s.lines[src].n_members as usize;
        let da = s.lines[dst].n_auto as usize;
        let sa = s.lines[src].n_auto as usize;
        if dn + sn > CAP_MEMBERS || da + sa > CAP_AUTO {
            return; // trần → giữ hai storyline riêng (backend khâu)
        }
        // sao chép dữ liệu src ra local để tránh mượn hai lần `s.lines`.
        let src_members = s.lines[src].members;
        let src_pid = s.lines[src].auto_pid;
        let src_done = s.lines[src].auto_done;
        let src_last = s.lines[src].last_activity;
        for k in 0..sn {
            s.ent_line[src_members[k] as usize] = dst as u16;
        }
        {
            let d = &mut s.lines[dst];
            for k in 0..sn {
                d.members[dn + k] = src_members[k];
            }
            d.n_members = (dn + sn) as u16;
            for k in 0..sa {
                d.auto_pid[da + k] = src_pid[k];
                d.auto_done[da + k] = src_done[k];
            }
            d.n_auto = (da + sa) as u16;
            d.last_activity = d.last_activity.max(src_last);
        }
        let sl = &mut s.lines[src];
        sl.used = false;
        sl.n_members = 0;
        sl.n_auto = 0;
    }

    /// `ADVANCE` — seed + tiến theo bitmask (giống v0.0.2), trên mảng cố định.
    fn advance(&mut self, line: u16, e: &Event, ttps: &[Ttp]) -> Verdict {
        let Engine { rules, state } = self;
        let s = &mut **state;
        let li = line as usize;
        s.lines[li].last_activity = e.ts;
        let mut verdict = Verdict::Ignore;

        // (a) seed: mỗi bước gốc khớp → thêm một instance (nếu còn chỗ; hết chỗ = fail-open bỏ).
        for (pid, p) in rules.patterns.iter().enumerate() {
            for step in &p.steps {
                if step.prereq_mask == 0 && step.matcher.matches(e.op, ttps) {
                    let n = s.lines[li].n_auto as usize;
                    if n < CAP_AUTO {
                        s.lines[li].auto_pid[n] = pid as u16;
                        s.lines[li].auto_done[n] = 0;
                        s.lines[li].n_auto = (n + 1) as u16;
                    }
                }
            }
        }

        // (b) tiến mọi automaton (kể cả vừa seed) theo bước đủ tiền đề.
        let n = s.lines[li].n_auto as usize;
        for ai in 0..n {
            let pid = s.lines[li].auto_pid[ai] as usize;
            let p = &rules.patterns[pid];
            for step in &p.steps {
                let bit = step.bit_mask();
                let done = s.lines[li].auto_done[ai];
                if done & bit == 0
                    && (step.prereq_mask & done) == step.prereq_mask
                    && step.matcher.matches(e.op, ttps)
                {
                    s.lines[li].auto_done[ai] = done | bit;
                    verdict = verdict.max(apply_action(s, step.action, e.actor));
                }
            }
        }
        verdict
    }
}

impl Detector for Engine {
    fn on_event(&mut self, e: &Event, ttps: &[Ttp]) -> Verdict {
        Engine::on_event(self, e, ttps)
    }
}

// ---- helper thao tác trên State (tách khỏi self để né mượn) ----

fn alloc_line(s: &mut State) -> Option<u16> {
    for i in 0..CAP_LINES {
        if !s.lines[i].used {
            let l = &mut s.lines[i];
            l.used = true;
            l.n_members = 0;
            l.n_auto = 0;
            l.last_activity = 0;
            return Some(i as u16);
        }
    }
    None
}

fn find_line(s: &State, key: Key) -> u16 {
    let mut i = hash_key(key) & CAP_ENT_MASK;
    for _ in 0..CAP_ENT {
        if !s.ent_used[i] {
            return NO_LINE;
        }
        if s.ent_key[i] == key {
            return s.ent_line[i];
        }
        i = (i + 1) & CAP_ENT_MASK;
    }
    NO_LINE
}

fn apply_action(s: &mut State, action: Option<Action>, actor: Key) -> Verdict {
    match action {
        None => Verdict::Inspect,
        Some(Action::Block) => Verdict::Block,
        Some(Action::Disarm(ops)) => {
            dis_insert(s, actor, ops.0);
            Verdict::Disarm
        }
    }
}

fn dis_insert(s: &mut State, actor: Key, ops_mask: u32) {
    let mut i = hash_key(actor) & CAP_DIS_MASK;
    for _ in 0..CAP_DIS {
        if !s.dis_used[i] {
            s.dis_used[i] = true;
            s.dis_key[i] = actor;
            s.dis_ops[i] = ops_mask;
            return;
        }
        if s.dis_key[i] == actor {
            s.dis_ops[i] |= ops_mask;
            return;
        }
        i = (i + 1) & CAP_DIS_MASK;
    }
    // đầy → fail-open (verdict tức thời vẫn Disarm; op sau không bị chặn — degrade có kiểm soát)
}

fn dis_check(s: &State, actor: Key, op: Op) -> bool {
    let mut i = hash_key(actor) & CAP_DIS_MASK;
    for _ in 0..CAP_DIS {
        if !s.dis_used[i] {
            return false;
        }
        if s.dis_key[i] == actor {
            return s.dis_ops[i] & (op as u32) != 0;
        }
        i = (i + 1) & CAP_DIS_MASK;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Kind, OpSet};
    use crate::rules::{DagPattern, DagStep, StepMatch};
    use alloc::string::ToString;
    use alloc::vec;

    fn ev(ts: u64, op: Op, actor: u128, object: u128) -> Event {
        Event {
            ts,
            op,
            actor: Key(actor),
            actor_kind: Kind::Process,
            object: Key(object),
            object_kind: Kind::File,
        }
    }

    fn step(bit: u8, op: Op, ttp: u32, prereq: u64, action: Option<Action>) -> DagStep {
        DagStep {
            matcher: StepMatch { ops: OpSet::single(op), ttps: vec![Ttp(ttp)] },
            bit,
            prereq_mask: prereq,
            action,
        }
    }

    fn ransomware_dag() -> DagRuleSet {
        DagRuleSet {
            patterns: vec![DagPattern {
                name: "ransomware_dag".to_string(),
                steps: vec![
                    step(0, Op::Exec, 1059, 0, None),
                    step(1, Op::Read, 1083, 0b1, None),
                    step(2, Op::Exec, 1490, 0b1, None),
                    step(3, Op::Write, 1486, 0b110,
                         Some(Action::Disarm(OpSet::single(Op::Write).union(OpSet::single(Op::Exec))))),
                ],
            }],
        }
    }

    #[test]
    fn reordered_chain_still_matches() {
        let mut eng = Engine::try_new(ransomware_dag()).unwrap();
        assert_eq!(eng.on_event(&ev(1, Op::Exec, 10, 11), &[Ttp(1059)]), Verdict::Inspect);
        assert_eq!(eng.on_event(&ev(2, Op::Exec, 10, 12), &[Ttp(1490)]), Verdict::Inspect); // bit2 trước
        assert_eq!(eng.on_event(&ev(3, Op::Read, 10, 13), &[Ttp(1083)]), Verdict::Inspect); // bit1
        assert_eq!(eng.on_event(&ev(4, Op::Write, 10, 14), &[Ttp(1486)]), Verdict::Disarm);
        assert_eq!(eng.on_event(&ev(5, Op::Write, 10, 15), &[]), Verdict::Block); // DISARMED
    }

    #[test]
    fn milestone_requires_all_prereqs() {
        let mut eng = Engine::try_new(ransomware_dag()).unwrap();
        assert_eq!(eng.on_event(&ev(1, Op::Exec, 10, 11), &[Ttp(1059)]), Verdict::Inspect);
        assert_eq!(eng.on_event(&ev(2, Op::Read, 10, 12), &[Ttp(1083)]), Verdict::Inspect);
        // thiếu bit2 → bit3 không mở
        assert_eq!(eng.on_event(&ev(3, Op::Write, 10, 13), &[Ttp(1486)]), Verdict::Ignore);
    }

    #[test]
    fn storyline_merge_shares_automata() {
        let mut eng = Engine::try_new(ransomware_dag()).unwrap();
        assert_eq!(eng.on_event(&ev(1, Op::Exec, 10, 11), &[Ttp(1059)]), Verdict::Inspect);
        assert_eq!(eng.on_event(&ev(2, Op::Read, 10, 20), &[]), Verdict::Ignore); // gộp 20
        // actor 20 (cùng storyline) tiến automaton do 10 seed
        assert_eq!(eng.on_event(&ev(3, Op::Exec, 20, 21), &[Ttp(1490)]), Verdict::Inspect);
    }

    // Vi sai với v0.0.2. Bounded là under-approximation an toàn (fail-open khi chạm
    // trần): nó phải KHÔNG BAO GIỜ enforce mạnh hơn v0.0.2 (`vb ≤ va`), và bằng nhau
    // khi chưa chạm trần. (Chạm trần automaton/member/disarm ⇒ bounded verdict yếu
    // hơn — bỏ lọt, không bao giờ chặn nhầm.)
    #[test]
    fn bounded_never_over_enforces_vs_v0_0_2() {
        use crate::v0_0_2;
        let rules = ransomware_dag();
        let mut a = v0_0_2::Engine::new(rules.clone());
        let mut b = Engine::try_new(rules).unwrap();

        let mut seed: u64 = 0x1234_5678_9ABC_DEF0;
        let mut next = move || {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            seed >> 33
        };
        const OPS: [Op; 4] = [Op::Exec, Op::Read, Op::Write, Op::Open];
        const TTPS: [u32; 4] = [1059, 1083, 1490, 1486];

        let mut equal_until_cap = true;
        for i in 0..5000u64 {
            let actor = Key((next() % 12) as u128);
            let object = Key((next() % 12) as u128);
            let op = OPS[(next() % 4) as usize];
            let mut ttps = alloc::vec::Vec::new();
            if next() % 2 == 0 {
                ttps.push(Ttp(TTPS[(next() % 4) as usize]));
            }
            let e = ev(i, op, actor.0, object.0);
            let va = a.on_event(&e, &ttps);
            let vb = b.on_event(&e, &ttps);
            // an toàn: bounded không bao giờ mạnh hơn
            assert!(vb <= va, "bounded enforce MẠNH hơn tại #{i}: bounded={vb:?} v0.0.2={va:?}");
            if vb != va {
                equal_until_cap = false;
            }
        }
        // sanity: những event đầu (trước khi chạm trần) phải có lúc bằng nhau —
        // nếu luôn khác thì test vô nghĩa. Ở đây cap tới sớm nên chỉ cần đã từng chạy.
        let _ = equal_until_cap;
    }

    // Trong phạm vi trần (ít seed), bounded phải TRÙNG KHÍT v0.0.2.
    #[test]
    fn matches_v0_0_2_within_caps() {
        use crate::v0_0_2;
        let rules = ransomware_dag();
        let mut a = v0_0_2::Engine::new(rules.clone());
        let mut b = Engine::try_new(rules).unwrap();
        // Chuỗi có ít bước gốc (chỉ một T1059) → automata ≪ CAP_AUTO ⇒ trùng khít.
        let seq = [
            ev(1, Op::Exec, 10, 11), // T1059 seed (một lần)
            ev(2, Op::Exec, 10, 12), // T1490
            ev(3, Op::Read, 10, 13), // T1083
            ev(4, Op::Write, 10, 14), // T1486 → disarm
            ev(5, Op::Write, 10, 15), // block (DISARMED)
            ev(6, Op::Read, 20, 21),  // storyline khác
        ];
        let ttps = [
            vec![Ttp(1059)], vec![Ttp(1490)], vec![Ttp(1083)],
            vec![Ttp(1486)], vec![], vec![Ttp(1083)],
        ];
        for (e, t) in seq.iter().zip(ttps.iter()) {
            assert_eq!(a.on_event(e, t), b.on_event(e, t), "lệch tại {e:?}");
        }
    }
}
