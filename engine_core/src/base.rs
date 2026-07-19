//! Bản base (`engine_base.md §3–§5`): full provenance graph — node/cạnh
//! sống mãi — cộng storyline + automaton tuyến tính.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use crate::detector::{apply, Detector, Verdict};
use crate::event::{Event, Key, Kind, Op, OpSet, Ttp};
use crate::rules::RuleSet;

/// Node của provenance graph — sống mãi, không bao giờ bị gỡ (§2).
struct Node {
    #[allow(dead_code)] // giữ theo §2; bản base chưa có đường đọc lại kind
    kind: Kind,
    /// Chỉ số storyline hiện hành trong `Engine::storylines`.
    line: Option<usize>,
}

/// Cạnh — mỗi event sinh đúng một cạnh, lưu vĩnh viễn (§2, phục vụ forensic).
#[derive(Clone, Copy, Debug)]
pub struct Edge {
    pub from: Key,
    pub to: Key,
    pub op: Op,
    pub ts: u64,
}

/// Tiến độ khớp một pattern, tuyến tính (§2).
#[derive(Clone, Copy, Debug)]
struct Automaton {
    /// Số bước đã khớp: 0..=len(steps), tăng dần 1-1.
    stage: usize,
    #[allow(dead_code)] // §2: mốc thời gian khớp gần nhất; GC dùng ở engine_v* sau
    stage_ts: u64,
}

/// Storyline = thành phần liên thông của graph (§2, §4).
struct Storyline {
    members: BTreeSet<Key>,
    /// `pattern_id` (chỉ số trong ruleset) → các instance đang sống.
    automata: BTreeMap<usize, Vec<Automaton>>,
    last_activity: u64,
}

/// Engine bản base: giữ mọi node, cạnh, automaton từ lúc khởi động (§1).
pub struct Engine {
    rules: RuleSet,
    nodes: BTreeMap<Key, Node>,
    edges: Vec<Edge>,
    /// Slot đã merge thành `None`; storyline không bao giờ bị xoá vì lý do khác.
    storylines: Vec<Option<Storyline>>,
    /// `DISARMED`: actor → tập op đã bị tước quyền, hiệu lực vĩnh viễn (§2).
    disarmed: BTreeMap<Key, OpSet>,
}

impl Engine {
    pub fn new(rules: RuleSet) -> Self {
        Engine {
            rules,
            nodes: BTreeMap::new(),
            edges: Vec::new(),
            storylines: Vec::new(),
            disarmed: BTreeMap::new(),
        }
    }

    /// `ON_EVENT` (§3). `ttps` do tagger platform-specific bên ngoài gán.
    pub fn on_event(&mut self, e: &Event, ttps: &[Ttp]) -> Verdict {
        // DISARMED đứng trước mọi bước khác: op đã bị tước quyền thì event
        // không bao giờ tới được graph/storyline/automaton (§3).
        if let Some(ops) = self.disarmed.get(&e.actor) {
            if ops.contains(e.op) {
                return Verdict::Block;
            }
        }

        self.resolve_node(e.actor, e.actor_kind);
        self.resolve_node(e.object, e.object_kind);

        self.edges.push(Edge { from: e.actor, to: e.object, op: e.op, ts: e.ts });

        let s = self.unify_storyline(e.actor, e.object);

        self.advance(s, e, ttps)
    }

    /// Cạnh forensic tích lũy từ lúc khởi động ("ai làm gì với ai", §2).
    pub fn edges(&self) -> &[Edge] {
        &self.edges
    }

    /// Tập member của storyline đang chứa `key`, nếu có.
    pub fn storyline_of(&self, key: Key) -> Option<impl Iterator<Item = Key> + '_> {
        let line = self.nodes.get(&key)?.line?;
        Some(self.storylines[line].as_ref().unwrap().members.iter().copied())
    }

    /// get-or-create trong `GRAPH.nodes` (§3).
    fn resolve_node(&mut self, key: Key, kind: Kind) {
        self.nodes.entry(key).or_insert(Node { kind, line: None });
    }

    /// `UNIFY_STORYLINE` (§4): mọi cạnh — bất kể op — đều gộp storyline.
    fn unify_storyline(&mut self, a: Key, o: Key) -> usize {
        let sa = self.line_or_new(a);
        let so = self.line_or_new(o);
        if sa != so {
            self.merge(sa, so);
        }
        self.nodes[&a].line.unwrap()
    }

    fn line_or_new(&mut self, key: Key) -> usize {
        if let Some(line) = self.nodes[&key].line {
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
        self.nodes.get_mut(&key).unwrap().line = Some(line);
        line
    }

    /// `MERGE` (§4): dời members/automata của tập nhỏ vào tập lớn (union-by-size).
    fn merge(&mut self, x: usize, y: usize) {
        let (dst, src) = {
            let lx = self.storylines[x].as_ref().unwrap().members.len();
            let ly = self.storylines[y].as_ref().unwrap().members.len();
            if lx >= ly { (x, y) } else { (y, x) }
        };
        let moved = self.storylines[src].take().unwrap();
        for k in &moved.members {
            self.nodes.get_mut(k).unwrap().line = Some(dst);
        }
        let d = self.storylines[dst].as_mut().unwrap();
        d.members.extend(moved.members);
        for (pid, mut autos) in moved.automata {
            d.automata.entry(pid).or_default().append(&mut autos);
        }
        d.last_activity = d.last_activity.max(moved.last_activity);
    }

    /// `ADVANCE` (§5): seed + tiến automaton tuyến tính, trả verdict của event.
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
                verdict = verdict.max(apply(&p.steps[0], e.actor, disarmed));
            }
        }

        // (b) tiến mọi automaton đang có trong S theo ĐÚNG bước kế tiếp.
        for (&pid, autos) in line.automata.iter_mut() {
            let p = &rules.patterns[pid];
            for a in autos.iter_mut() {
                if a.stage < p.steps.len() && p.steps[a.stage].matcher.matches(e.op, ttps) {
                    verdict = verdict.max(apply(&p.steps[a.stage], e.actor, disarmed));
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
        // bước 0 seed
        assert_eq!(eng.on_event(&ev(1, Op::Exec, 10, 11), &[Ttp(1)]), Verdict::Inspect);
        // event không khớp bước kế → ignore
        assert_eq!(eng.on_event(&ev(2, Op::Read, 10, 12), &[]), Verdict::Ignore);
        // bước 1 khớp → disarm(write)
        assert_eq!(eng.on_event(&ev(3, Op::Write, 10, 13), &[Ttp(2)]), Verdict::Disarm);
        // từ nay mọi write của actor 10 bị chặn thẳng, không chạm automaton
        assert_eq!(eng.on_event(&ev(4, Op::Write, 10, 14), &[]), Verdict::Block);
        // op khác không bị tước quyền thì vẫn qua
        assert_eq!(eng.on_event(&ev(5, Op::Read, 10, 14), &[]), Verdict::Ignore);
    }

    #[test]
    fn steps_must_match_in_order() {
        let mut eng = Engine::new(one_pattern());
        // bước 1 tới trước khi automaton tồn tại → không có gì khớp
        assert_eq!(eng.on_event(&ev(1, Op::Write, 10, 11), &[Ttp(2)]), Verdict::Ignore);
        assert_eq!(eng.on_event(&ev(2, Op::Exec, 10, 12), &[Ttp(1)]), Verdict::Inspect);
    }

    #[test]
    fn storylines_merge_and_share_automata() {
        let mut eng = Engine::new(one_pattern());
        // storyline A: actor 10 seed automaton
        assert_eq!(eng.on_event(&ev(1, Op::Exec, 10, 11), &[Ttp(1)]), Verdict::Inspect);
        // storyline B: actor 20 chưa liên quan
        assert_eq!(eng.on_event(&ev(2, Op::Read, 20, 21), &[]), Verdict::Ignore);
        // cạnh 10→21 gộp A và B; actor 20 giờ cùng storyline với automaton
        assert_eq!(eng.on_event(&ev(3, Op::Read, 10, 21), &[]), Verdict::Ignore);
        // actor 20 tiến bước 1 của automaton do 10 seed
        assert_eq!(eng.on_event(&ev(4, Op::Write, 20, 22), &[Ttp(2)]), Verdict::Disarm);
        let members: Vec<Key> = eng.storyline_of(Key(10)).unwrap().collect();
        for k in [10u128, 11, 20, 21, 22] {
            assert!(members.contains(&Key(k)), "thiếu {k}");
        }
    }

    #[test]
    fn edges_accumulate_one_per_event() {
        let mut eng = Engine::new(one_pattern());
        eng.on_event(&ev(1, Op::Exec, 10, 11), &[]);
        eng.on_event(&ev(2, Op::Read, 10, 12), &[]);
        assert_eq!(eng.edges().len(), 2);
    }
}
