//! Bản v0.0.2 (`engine_v0.0.2.md`): pattern = **partial-order DAG**. Thay
//! `stage` tuyến tính của v0.0.1 bằng **bitmask tiến độ + `prereq_mask`** —
//! một bước khớp được khi mọi bit tiền đề đã bật, bất kể thứ tự đến.
//!
//! Đây là thay đổi **duy nhất** so với v0.0.1: `LINE`, `Storyline`, `DISARMED`,
//! `ON_EVENT`, cách seed đều giữ nguyên. Bản này không đụng tới mặt bộ nhớ
//! automaton (không thêm/bớt cấu trúc) — đặt trần là việc của bước sau
//! (`todo.md` bước 5).

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use crate::detector::{apply, Detector, Verdict};
use crate::event::{Event, Key, OpSet, Ttp};
use crate::rules::DagRuleSet;

/// Tiến độ khớp một pattern DAG: bitmask các bit đã commit (`engine_v0.0.2.md §3`).
#[derive(Clone, Copy, Debug)]
struct Automaton {
    /// `done_mask`: bit i bật ⟺ bước có `bit == i` đã commit.
    done_mask: u64,
}

/// Storyline — không đổi so với v0.0.1: thành phần liên thông theo `LINE`.
struct Storyline {
    members: BTreeSet<Key>,
    /// `pattern_id` → list instance (mô hình list của v0.0.1, chưa dedup/chưa GC).
    automata: BTreeMap<usize, Vec<Automaton>>,
    last_activity: u64,
}

/// Engine v0.0.2: khác v0.0.1 đúng ở ruột `ADVANCE` (bitmask thay cho stage).
pub struct Engine {
    rules: DagRuleSet,
    /// `LINE`: định danh → chỉ số storyline hiện hành.
    line: BTreeMap<Key, usize>,
    /// Slot đã merge thành `None`.
    storylines: Vec<Option<Storyline>>,
    /// `DISARMED`: actor → tập op đã bị tước quyền, hiệu lực vĩnh viễn.
    disarmed: BTreeMap<Key, OpSet>,
}

impl Engine {
    pub fn new(rules: DagRuleSet) -> Self {
        Engine {
            rules,
            line: BTreeMap::new(),
            storylines: Vec::new(),
            disarmed: BTreeMap::new(),
        }
    }

    /// `ON_EVENT` (`engine_v0.0.2.md §4`) — không đổi so với v0.0.1.
    pub fn on_event(&mut self, e: &Event, ttps: &[Ttp]) -> Verdict {
        if let Some(ops) = self.disarmed.get(&e.actor) {
            if ops.contains(e.op) {
                return Verdict::Block;
            }
        }

        let s = self.unify_storyline(e.actor, e.object);

        self.advance(s, e, ttps)
    }

    /// Tập member của storyline đang chứa `key`, nếu có.
    pub fn storyline_of(&self, key: Key) -> Option<impl Iterator<Item = Key> + '_> {
        let line = *self.line.get(&key)?;
        Some(self.storylines[line].as_ref().unwrap().members.iter().copied())
    }

    // ---- UNIFY_STORYLINE (không đổi so với v0.0.1) ----

    fn unify_storyline(&mut self, a: Key, o: Key) -> usize {
        let sa = self.resolve_line(a);
        let so = self.resolve_line(o);
        if sa != so {
            self.merge(sa, so);
        }
        self.line[&a]
    }

    fn resolve_line(&mut self, key: Key) -> usize {
        if let Some(&line) = self.line.get(&key) {
            return line;
        }
        let mut members = BTreeSet::new();
        members.insert(key);
        self.storylines.push(Some(Storyline {
            members,
            automata: BTreeMap::new(),
            last_activity: 0,
        }));
        let line = self.storylines.len() - 1;
        self.line.insert(key, line);
        line
    }

    fn merge(&mut self, x: usize, y: usize) {
        let (dst, src) = {
            let lx = self.storylines[x].as_ref().unwrap().members.len();
            let ly = self.storylines[y].as_ref().unwrap().members.len();
            if lx >= ly { (x, y) } else { (y, x) }
        };
        let moved = self.storylines[src].take().unwrap();
        for k in &moved.members {
            self.line.insert(*k, dst);
        }
        let d = self.storylines[dst].as_mut().unwrap();
        d.members.extend(moved.members);
        for (pid, mut autos) in moved.automata {
            d.automata.entry(pid).or_default().append(&mut autos);
        }
        d.last_activity = d.last_activity.max(moved.last_activity);
    }

    /// `ADVANCE` (`engine_v0.0.2.md §5`): seed như v0.0.1, tiến theo bitmask.
    fn advance(&mut self, s: usize, e: &Event, ttps: &[Ttp]) -> Verdict {
        let Engine { rules, storylines, disarmed, .. } = self;
        let line = storylines[s].as_mut().unwrap();
        line.last_activity = e.ts;

        let mut verdict = Verdict::Ignore;

        // (a) seed: mỗi bước GỐC (prereq_mask == 0) khớp e thì thêm một automaton
        //     mới vào list — giống cách v0.0.1 seed khi steps[0] khớp.
        for (pid, p) in rules.patterns.iter().enumerate() {
            for step in &p.steps {
                if step.prereq_mask == 0 && step.matcher.matches(e.op, ttps) {
                    line.automata
                        .entry(pid)
                        .or_default()
                        .push(Automaton { done_mask: 0 });
                }
            }
        }

        // (b) tiến mọi automaton trong S: bước chưa done + tiền đề đủ + match khớp → commit.
        //     Duyệt bước theo thứ tự khai báo; commit sớm cập nhật done_mask ngay nên
        //     một event có thể commit nhiều bước (kể cả bước vừa mở tiền đề trong event này).
        for (&pid, autos) in line.automata.iter_mut() {
            let p = &rules.patterns[pid];
            for a in autos.iter_mut() {
                for step in &p.steps {
                    let bit = step.bit_mask();
                    if a.done_mask & bit == 0
                        && (step.prereq_mask & a.done_mask) == step.prereq_mask
                        && step.matcher.matches(e.op, ttps)
                    {
                        a.done_mask |= bit;
                        verdict = verdict.max(apply(step.action, e.actor, disarmed));
                    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Kind, Op};
    use crate::rules::{Action, DagPattern, DagStep, StepMatch};
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

    fn step(bit: u8, op: Op, ttp: u32, prereq_mask: u64, action: Option<Action>) -> DagStep {
        DagStep {
            matcher: StepMatch { ops: OpSet::single(op), ttps: vec![Ttp(ttp)] },
            bit,
            prereq_mask,
            action,
        }
    }

    // ransomware_dag (engine_v0.0.2.md §6): bit0 gốc; bit1,2 cần {0}; bit3 cần {1,2}, disarm.
    fn ransomware_dag() -> DagRuleSet {
        DagRuleSet {
            patterns: vec![DagPattern {
                name: "ransomware_dag".to_string(),
                steps: vec![
                    step(0, Op::Exec, 1059, 0, None),
                    step(1, Op::Read, 1083, 0b1, None),
                    step(2, Op::Exec, 1490, 0b1, None),
                    step(
                        3,
                        Op::Write,
                        1486,
                        0b110,
                        Some(Action::Disarm(OpSet::single(Op::Write).union(OpSet::single(Op::Exec)))),
                    ),
                ],
            }],
        }
    }

    #[test]
    fn reordered_chain_still_matches() {
        // Chuỗi tới ĐẢO thứ tự: bit 2 (T1490) TRƯỚC bit 1 (T1083) — v0.0.1 tuyến tính kẹt ở đây.
        let mut eng = Engine::new(ransomware_dag());
        assert_eq!(eng.on_event(&ev(1, Op::Exec, 10, 11), &[Ttp(1059)]), Verdict::Inspect); // bit0
        assert_eq!(eng.on_event(&ev(2, Op::Exec, 10, 12), &[Ttp(1490)]), Verdict::Inspect); // bit2 trước
        assert_eq!(eng.on_event(&ev(3, Op::Read, 10, 13), &[Ttp(1083)]), Verdict::Inspect); // bit1 sau
        // mốc bit3 mở (prereq {1,2} đủ) → commit → disarm(write,exec)
        assert_eq!(eng.on_event(&ev(4, Op::Write, 10, 14), &[Ttp(1486)]), Verdict::Disarm);
        // write đã bị tước quyền → chặn thẳng
        assert_eq!(eng.on_event(&ev(5, Op::Write, 10, 15), &[]), Verdict::Block);
    }

    #[test]
    fn forward_order_also_matches() {
        // Thứ tự "xuôi" (bit1 trước bit2) cũng khớp — DAG chấp nhận cả hai chiều.
        let mut eng = Engine::new(ransomware_dag());
        assert_eq!(eng.on_event(&ev(1, Op::Exec, 10, 11), &[Ttp(1059)]), Verdict::Inspect);
        assert_eq!(eng.on_event(&ev(2, Op::Read, 10, 12), &[Ttp(1083)]), Verdict::Inspect);
        assert_eq!(eng.on_event(&ev(3, Op::Exec, 10, 13), &[Ttp(1490)]), Verdict::Inspect);
        assert_eq!(eng.on_event(&ev(4, Op::Write, 10, 14), &[Ttp(1486)]), Verdict::Disarm);
    }

    #[test]
    fn milestone_requires_all_prereqs() {
        // Chỉ có bit1, thiếu bit2 → mốc bit3 KHÔNG mở, không disarm.
        let mut eng = Engine::new(ransomware_dag());
        assert_eq!(eng.on_event(&ev(1, Op::Exec, 10, 11), &[Ttp(1059)]), Verdict::Inspect);
        assert_eq!(eng.on_event(&ev(2, Op::Read, 10, 12), &[Ttp(1083)]), Verdict::Inspect);
        // bit3 prereq {1,2} chưa đủ (thiếu bit2) → write T1486 không commit bit3
        assert_eq!(eng.on_event(&ev(3, Op::Write, 10, 13), &[Ttp(1486)]), Verdict::Ignore);
    }

    #[test]
    fn root_out_of_context_does_not_advance_middle() {
        // Bước giữa (bit1) tới khi chưa có bước gốc → không automaton nào, ignore.
        let mut eng = Engine::new(ransomware_dag());
        assert_eq!(eng.on_event(&ev(1, Op::Read, 10, 11), &[Ttp(1083)]), Verdict::Ignore);
        assert_eq!(eng.on_event(&ev(2, Op::Exec, 10, 12), &[Ttp(1059)]), Verdict::Inspect);
    }

    #[test]
    fn storylines_merge_and_share_automata() {
        let mut eng = Engine::new(ransomware_dag());
        // actor 10 seed automaton (bit 0)
        assert_eq!(eng.on_event(&ev(1, Op::Exec, 10, 11), &[Ttp(1059)]), Verdict::Inspect);
        // cạnh 10→20 gộp actor 20 vào cùng storyline (không TTP → ignore)
        assert_eq!(eng.on_event(&ev(2, Op::Read, 10, 20), &[]), Verdict::Ignore);
        // actor 20 (giờ cùng storyline) tiến automaton do 10 seed: bit 2, prereq {0} đủ
        assert_eq!(eng.on_event(&ev(3, Op::Exec, 20, 21), &[Ttp(1490)]), Verdict::Inspect);
        let members: Vec<Key> = eng.storyline_of(Key(10)).unwrap().collect();
        for k in [10u128, 11, 20, 21] {
            assert!(members.contains(&Key(k)), "thiếu {k}");
        }
    }
}
