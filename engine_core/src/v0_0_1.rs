//! Bản v0.0.1 (`engine_v0.0.1.md`): bỏ hẳn provenance graph (`Node`, `Edge`,
//! `GRAPH.edges`) — chỉ còn `LINE` (định danh → storyline hiện hành),
//! storyline, automaton và `DISARMED`.
//!
//! Đường phát hiện (`UNIFY_STORYLINE`, `ADVANCE`) chưa từng đọc cạnh nào ở
//! bản base, nên hai bản cho verdict **giống hệt nhau** trên cùng luồng event
//! (test vi sai ở `engine_replay`); cái mất chỉ là dữ liệu forensic
//! ("ai làm gì với ai theo thứ tự nào" — `engine_v0.0.1.md §8`).

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use crate::detector::{apply, Detector, Verdict};
use crate::event::{Event, Key, OpSet, Ttp};
use crate::rules::RuleSet;

/// Tiến độ khớp một pattern, tuyến tính — không đổi so với bản base (§3).
#[derive(Clone, Copy, Debug)]
struct Automaton {
    /// Số bước đã khớp: 0..=len(steps), tăng dần 1-1.
    stage: usize,
    #[allow(dead_code)] // §3: mốc thời gian khớp gần nhất; GC dùng ở engine_v* sau
    stage_ts: u64,
}

/// Storyline — không đổi so với bản base (§3): thành phần liên thông theo
/// `LINE`, không cần đồ thị để biết ai-nối-ai.
struct Storyline {
    members: BTreeSet<Key>,
    /// `pattern_id` (chỉ số trong ruleset) → các instance đang sống.
    automata: BTreeMap<usize, Vec<Automaton>>,
    last_activity: u64,
}

/// Engine v0.0.1: bộ nhớ tăng theo số định danh distinct đã chạm tới,
/// không theo tổng số event (§7).
pub struct Engine {
    rules: RuleSet,
    /// `LINE`: định danh → chỉ số storyline hiện hành (thay cho `Node.line`).
    /// Không mang `kind`, không mang lịch sử (§3).
    line: BTreeMap<Key, usize>,
    /// Slot đã merge thành `None`.
    storylines: Vec<Option<Storyline>>,
    /// `DISARMED`: actor → tập op đã bị tước quyền, hiệu lực vĩnh viễn (§3).
    disarmed: BTreeMap<Key, OpSet>,
}

impl Engine {
    pub fn new(rules: RuleSet) -> Self {
        Engine {
            rules,
            line: BTreeMap::new(),
            storylines: Vec::new(),
            disarmed: BTreeMap::new(),
        }
    }

    /// `ON_EVENT` (§4): không còn `RESOLVE_NODE`, không còn `edges.append`.
    pub fn on_event(&mut self, e: &Event, ttps: &[Ttp]) -> Verdict {
        // DISARMED đứng trước mọi bước khác — chặn thẳng, không chạm LINE/automaton.
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

    /// `UNIFY_STORYLINE` (§5): mọi cạnh — bất kể op — vẫn gộp storyline,
    /// giống hệt bản base; chỉ khác là không giữ lại cạnh nào để giải thích.
    fn unify_storyline(&mut self, a: Key, o: Key) -> usize {
        let sa = self.resolve_line(a);
        let so = self.resolve_line(o);
        if sa != so {
            self.merge(sa, so);
        }
        self.line[&a]
    }

    /// `RESOLVE_LINE` (§5): lần đầu chạm tới thì gán vào storyline mới.
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

    /// `MERGE` (§5): dời members/automata sang tập lớn hơn; với mỗi key vừa
    /// dời, cập nhật `LINE[k]` = storyline đích.
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

    /// `ADVANCE` (§6) — giữ NGUYÊN VẸN logic bản base: nó chưa từng phụ thuộc
    /// `GRAPH`, nên bỏ graph không phải sửa một dòng nào ở đây.
    fn advance(&mut self, s: usize, e: &Event, ttps: &[Ttp]) -> Verdict {
        let Engine { rules, storylines, disarmed, .. } = self;
        let line = storylines[s].as_mut().unwrap();
        line.last_activity = e.ts;

        let mut verdict = Verdict::Ignore;

        // (a) seed: mẫu nào có bước đầu khớp e thì tạo automaton mới trong S.
        for (pid, p) in rules.patterns.iter().enumerate() {
            if p.steps[0].matcher.matches(e.op, ttps) {
                line.automata
                    .entry(pid)
                    .or_default()
                    .push(Automaton { stage: 1, stage_ts: e.ts });
                verdict = verdict.max(apply(p.steps[0].action, e.actor, disarmed));
            }
        }

        // (b) tiến mọi automaton đang có trong S theo ĐÚNG bước kế tiếp.
        for (&pid, autos) in line.automata.iter_mut() {
            let p = &rules.patterns[pid];
            for a in autos.iter_mut() {
                if a.stage < p.steps.len() && p.steps[a.stage].matcher.matches(e.op, ttps) {
                    verdict = verdict.max(apply(p.steps[a.stage].action, e.actor, disarmed));
                    a.stage += 1;
                    a.stage_ts = e.ts;
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
    use crate::rules::{Action, Pattern, Step, StepMatch};
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

    fn one_pattern() -> RuleSet {
        RuleSet {
            patterns: vec![Pattern {
                name: "p".to_string(),
                steps: vec![
                    Step {
                        matcher: StepMatch { ops: OpSet::single(Op::Exec), ttps: vec![Ttp(1)] },
                        action: None, // chỉ báo hiệu → inspect
                    },
                    Step {
                        matcher: StepMatch { ops: OpSet::single(Op::Write), ttps: vec![Ttp(2)] },
                        action: Some(Action::Disarm(OpSet::single(Op::Write))),
                    },
                ],
            }],
        }
    }

    #[test]
    fn linear_advance_then_disarm_blocks_forever() {
        let mut eng = Engine::new(one_pattern());
        assert_eq!(eng.on_event(&ev(1, Op::Exec, 10, 11), &[Ttp(1)]), Verdict::Inspect);
        assert_eq!(eng.on_event(&ev(2, Op::Read, 10, 12), &[]), Verdict::Ignore);
        assert_eq!(eng.on_event(&ev(3, Op::Write, 10, 13), &[Ttp(2)]), Verdict::Disarm);
        assert_eq!(eng.on_event(&ev(4, Op::Write, 10, 14), &[]), Verdict::Block);
        assert_eq!(eng.on_event(&ev(5, Op::Read, 10, 14), &[]), Verdict::Ignore);
    }

    #[test]
    fn storylines_merge_and_share_automata() {
        let mut eng = Engine::new(one_pattern());
        assert_eq!(eng.on_event(&ev(1, Op::Exec, 10, 11), &[Ttp(1)]), Verdict::Inspect);
        assert_eq!(eng.on_event(&ev(2, Op::Read, 20, 21), &[]), Verdict::Ignore);
        // cạnh 10→21 gộp hai storyline; actor 20 tiến automaton do 10 seed
        assert_eq!(eng.on_event(&ev(3, Op::Read, 10, 21), &[]), Verdict::Ignore);
        assert_eq!(eng.on_event(&ev(4, Op::Write, 20, 22), &[Ttp(2)]), Verdict::Disarm);
        let members: Vec<Key> = eng.storyline_of(Key(10)).unwrap().collect();
        for k in [10u128, 11, 20, 21, 22] {
            assert!(members.contains(&Key(k)), "thiếu {k}");
        }
    }

    #[test]
    fn memory_tracks_distinct_keys_not_events() {
        let mut eng = Engine::new(one_pattern());
        // cùng một cặp (actor, object) lặp nhiều event → LINE chỉ có 2 mục (§7)
        for ts in 0..100 {
            eng.on_event(&ev(ts, Op::Read, 10, 11), &[]);
        }
        assert_eq!(eng.line.len(), 2);
        assert_eq!(eng.storyline_of(Key(10)).unwrap().count(), 2);
    }
}
