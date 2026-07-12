//! Inline behavioral prevention engine — **userland detection core**.
//!
//! Implements the algorithm in engine.md: node resolution (§2), storyline
//! union-find (§3), TTP tagging (§4), partial-order automaton matching (§5),
//! kill-chain scoring (§6) and the inline verdict/arm mechanism (§5.5, §8).
//!
//! Rules (TTP taggers + attack patterns) are **not** compiled in — they load from
//! an external rule file at runtime (see `rules.rs`, `rules/builtin.rules`). The
//! kernel sensor is out of scope for offline replay.

pub mod dataset;
pub mod event;
pub mod pattern;
pub mod rules;

use event::{Event, NodeKey, Op};
use pattern::{Mask, Pattern, RoleSource, Scope, Step};
use rules::{RateState, RuleSet, TtpId};
use std::collections::{HashMap, HashSet, VecDeque};

/// Default rule set, embedded so `Engine::new()` works out of the box.
pub const DEFAULT_RULES: &str = include_str!("../rules/builtin.rules");

// ---- scoring weights (engine.md §6) ----------------------------------------
const W_STAGES: f64 = 2.0;
const W_SEV: f64 = 0.3;
const W_ORDER: f64 = 1.0;
const W_RARITY: f64 = 2.0;

// ---- verdict ----------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum VerdictKind {
    None = 0,
    Suspect = 1,
    Alert = 2,
    Block = 3,
}

#[derive(Clone, Debug)]
pub struct Verdict {
    pub kind: VerdictKind,
    pub pattern: String,
    pub score: f64,
    pub reason: String,
}

impl Verdict {
    fn none() -> Verdict {
        Verdict { kind: VerdictKind::None, pattern: String::new(), score: 0.0, reason: String::new() }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Decision {
    Allow,
    Deny,
}

// ---- graph & storyline ------------------------------------------------------

struct Node {
    #[allow(dead_code)] // kept for investigation/graph export
    key: NodeKey,
    sid: usize,
}

struct Automaton {
    #[allow(dead_code)] // pattern index is re-derived by id; kept for clarity/debug
    pattern_idx: usize,
    completed_mask: Mask,
    step_ts: HashMap<u8, u64>,
    bound_nodes: HashMap<String, usize>,
    armed: bool,
}

impl Automaton {
    fn new(pattern_idx: usize) -> Automaton {
        Automaton {
            pattern_idx,
            completed_mask: 0,
            step_ts: HashMap::new(),
            bound_nodes: HashMap::new(),
            armed: false,
        }
    }
    fn has(&self, bit: u8) -> bool {
        self.completed_mask & (1 << bit) != 0
    }
}

#[derive(Default)]
struct Storyline {
    automata: HashMap<String, Automaton>,
    ttp_history: VecDeque<(TtpId, u64)>,
    score: f64,
    last_activity: u64,
}

// ---- engine -----------------------------------------------------------------

pub struct Engine {
    nodes: Vec<Node>,
    node_index: HashMap<NodeKey, usize>,
    storylines: HashMap<usize, Storyline>,
    dsu_parent: HashMap<usize, usize>,
    next_sid: usize,
    rules: RuleSet,
    rate: HashMap<usize, RateState>,
    kernel_arm: HashMap<usize, Op>,
    pub log: Vec<String>,
}

impl Engine {
    /// Build with the embedded default rules.
    pub fn new() -> Engine {
        Engine::from_rules_str(DEFAULT_RULES).expect("builtin rules parse")
    }

    pub fn from_rules_str(s: &str) -> Result<Engine, String> {
        Ok(Engine::with_rules(RuleSet::parse_str(s)?))
    }

    pub fn from_rules_file(path: &str) -> Result<Engine, String> {
        let s = std::fs::read_to_string(path).map_err(|e| format!("read {}: {}", path, e))?;
        Engine::from_rules_str(&s)
    }

    pub fn with_rules(rules: RuleSet) -> Engine {
        Engine {
            nodes: Vec::new(),
            node_index: HashMap::new(),
            storylines: HashMap::new(),
            dsu_parent: HashMap::new(),
            next_sid: 0,
            rules,
            rate: HashMap::new(),
            kernel_arm: HashMap::new(),
            log: Vec::new(),
        }
    }

    // -- DSU over storyline ids ----------------------------------------------
    fn find(&mut self, sid: usize) -> usize {
        let mut root = sid;
        while let Some(&p) = self.dsu_parent.get(&root) {
            if p == root {
                break;
            }
            root = p;
        }
        let mut cur = sid;
        while let Some(&p) = self.dsu_parent.get(&cur) {
            if p == root {
                break;
            }
            self.dsu_parent.insert(cur, root);
            cur = p;
        }
        root
    }

    fn new_storyline(&mut self) -> usize {
        let sid = self.next_sid;
        self.next_sid += 1;
        self.dsu_parent.insert(sid, sid);
        self.storylines.insert(sid, Storyline::default());
        sid
    }

    // -- node resolution (§2) ------------------------------------------------
    fn resolve(&mut self, key: &NodeKey) -> usize {
        if let Some(&uid) = self.node_index.get(key) {
            return uid;
        }
        let sid = self.new_storyline();
        let uid = self.nodes.len();
        self.nodes.push(Node { key: key.clone(), sid });
        self.node_index.insert(key.clone(), uid);
        uid
    }

    fn storyline_of(&mut self, uid: usize) -> usize {
        let sid = self.nodes[uid].sid;
        self.find(sid)
    }

    // -- storyline unification (§3) ------------------------------------------
    fn unify(&mut self, a_uid: usize, o_uid: usize, op: Op) -> usize {
        let sa = self.storyline_of(a_uid);
        if !op.is_causal() {
            return sa;
        }
        let so = self.storyline_of(o_uid);
        if sa == so {
            return sa;
        }
        self.merge(sa, so)
    }

    fn merge(&mut self, a: usize, b: usize) -> usize {
        let (root, child) = {
            let na = self.storylines.get(&a).map(|s| s.automata.len()).unwrap_or(0);
            let nb = self.storylines.get(&b).map(|s| s.automata.len()).unwrap_or(0);
            if na >= nb {
                (a, b)
            } else {
                (b, a)
            }
        };
        self.dsu_parent.insert(child, root);
        if let Some(child_s) = self.storylines.remove(&child) {
            let root_s = self.storylines.get_mut(&root).unwrap();
            for (pid, autom) in child_s.automata {
                match root_s.automata.get_mut(&pid) {
                    None => {
                        root_s.automata.insert(pid, autom);
                    }
                    Some(existing) => {
                        existing.completed_mask |= autom.completed_mask;
                        for (bit, ts) in autom.step_ts {
                            existing.step_ts.entry(bit).and_modify(|t| *t = (*t).min(ts)).or_insert(ts);
                        }
                        for (role, uid) in autom.bound_nodes {
                            existing.bound_nodes.entry(role).or_insert(uid);
                        }
                    }
                }
            }
            for h in child_s.ttp_history {
                root_s.ttp_history.push_back(h);
            }
            root_s.score = root_s.score.max(child_s.score);
            root_s.last_activity = root_s.last_activity.max(child_s.last_activity);
        }
        root
    }

    // -- main per-event pipeline (§1) ----------------------------------------
    pub fn on_event(&mut self, e: &Event) -> (Decision, Verdict) {
        let a_uid = self.resolve(&e.actor);
        let o_uid = self.resolve(&e.object);
        let img_uid = e.image_key().map(|k| self.resolve(&k));

        let sid = self.unify(a_uid, o_uid, e.op);

        let rate = self.rate.entry(a_uid).or_default();
        let ttps = self.rules.tag(e, rate);
        {
            let s = self.storylines.get_mut(&sid).unwrap();
            s.last_activity = e.ts;
            for t in &ttps {
                s.ttp_history.push_back((t.clone(), e.ts));
            }
        }

        // Kernel fast-path: armed storyline + armed enforceable action -> deny
        // without a userland round-trip (§5.5).
        let mut kernel_denied = false;
        if let Some(&armed_op) = self.kernel_arm.get(&sid) {
            if armed_op == e.op
                && step_is_enforceable_chokepoint(&self.rules.patterns, &self.storylines[&sid], e.op)
            {
                kernel_denied = true;
            }
        }

        let verdict = self.advance(sid, &ttps, e, a_uid, o_uid, img_uid);

        let decision = if verdict.kind == VerdictKind::Block || kernel_denied {
            Decision::Deny
        } else {
            Decision::Allow
        };
        (decision, verdict)
    }

    // -- ADVANCE: partial-order matching (§5.3) ------------------------------
    fn advance(
        &mut self,
        sid: usize,
        ttps: &[TtpId],
        e: &Event,
        a_uid: usize,
        o_uid: usize,
        img_uid: Option<usize>,
    ) -> Verdict {
        // (a) seed root automata whose root step matches this event
        let mut to_start: Vec<(usize, String)> = Vec::new();
        for (idx, p) in self.rules.patterns.iter().enumerate() {
            if self.storylines[&sid].automata.contains_key(&p.id) {
                continue;
            }
            if p.root_steps().any(|rs| rs.slot_matches(e, ttps) && p.root_gate.ok(e)) {
                to_start.push((idx, p.id.clone()));
            }
        }
        for (idx, pid) in to_start {
            self.storylines
                .get_mut(&sid)
                .unwrap()
                .automata
                .insert(pid, Automaton::new(idx));
        }

        // (b) advance every automaton on this storyline
        let pattern_ids: Vec<String> = self.storylines[&sid].automata.keys().cloned().collect();
        let mut best = Verdict::none();

        for pid in pattern_ids {
            let idx = self.rules.patterns.iter().position(|p| p.id == pid).unwrap();
            let matching_bits: Vec<u8> = self.rules.patterns[idx]
                .steps
                .iter()
                .filter(|s| s.slot_matches(e, ttps))
                .map(|s| s.bit)
                .collect();

            for bit in matching_bits {
                if self.try_commit(sid, idx, &pid, bit, e, a_uid, o_uid, img_uid) {
                    let v = self.rescore_and_emit(sid, idx, &pid, bit, e);
                    if v.kind > best.kind {
                        best = v;
                    }
                }
            }
        }
        best
    }

    #[allow(clippy::too_many_arguments)]
    fn try_commit(
        &mut self,
        sid: usize,
        idx: usize,
        pid: &str,
        bit: u8,
        e: &Event,
        a_uid: usize,
        o_uid: usize,
        img_uid: Option<usize>,
    ) -> bool {
        let step: &Step = self.rules.patterns[idx].step(bit);
        let prereq = step.prereq_mask;
        let seg_window = step.seg_window;
        let bindings = step.bindings.clone();
        let scope = self.rules.patterns[idx].scope;

        let autom = self.storylines.get(&sid).unwrap().automata.get(pid).unwrap();
        if autom.has(bit) {
            return false;
        }
        if (prereq & autom.completed_mask) != prereq {
            return false; // PREREQ_OK — partial order
        }
        if prereq != 0 {
            // SEG_WINDOW_OK — per-segment deadline (§5.6)
            let mut t_enabled = 0u64;
            for b in bits(prereq) {
                if let Some(&t) = autom.step_ts.get(&b) {
                    t_enabled = t_enabled.max(t);
                }
            }
            if e.ts.saturating_sub(t_enabled) > seg_window {
                return false;
            }
        }
        let scope_ok = match scope {
            Scope::SameStoryline => true,
            Scope::SameActor => autom.bound_nodes.values().any(|&u| u == a_uid),
            Scope::Free => true,
        };
        if !scope_ok {
            return false;
        }
        // BINDING_OK — variable binding by identity (§5.8)
        let mut resolved: Vec<(String, usize)> = Vec::new();
        for b in &bindings {
            let uid = match b.source {
                RoleSource::Object => Some(o_uid),
                RoleSource::Actor => Some(a_uid),
                RoleSource::Image => img_uid,
            };
            let uid = match uid {
                Some(u) => u,
                None => return false,
            };
            if let Some(&existing) = autom.bound_nodes.get(&b.role) {
                if existing != uid {
                    return false; // binding conflict — rejects "write X, exec Y"
                }
            }
            resolved.push((b.role.clone(), uid));
        }

        // COMMIT_STEP
        let autom = self.storylines.get_mut(&sid).unwrap().automata.get_mut(pid).unwrap();
        autom.completed_mask |= 1 << bit;
        autom.step_ts.insert(bit, e.ts);
        for (role, uid) in resolved {
            autom.bound_nodes.insert(role, uid);
        }
        true
    }

    fn rescore_and_emit(&mut self, sid: usize, idx: usize, pid: &str, bit: u8, e: &Event) -> Verdict {
        let (completed, step_ts) = {
            let a = &self.storylines[&sid].automata[pid];
            (a.completed_mask, a.step_ts.clone())
        };
        let score = kill_chain_score(&self.rules.patterns[idx], completed, &step_ts, &self.rules);
        self.storylines.get_mut(&sid).unwrap().score = score;

        let p = &self.rules.patterns[idx];
        let accepting = (completed & p.required_mask) == p.required_mask;
        let step = p.step(bit);
        let at_block = p.block_at == Some(bit) && step.enforceable;

        if accepting {
            if score >= p.theta_block && at_block {
                self.log.push(format!(
                    "ts={} BLOCK pattern={} score={:.1} at chokepoint step={}",
                    e.ts, p.id, score, step.name
                ));
                return Verdict {
                    kind: VerdictKind::Block,
                    pattern: p.id.clone(),
                    score,
                    reason: format!("chokepoint {}", step.name),
                };
            }
            if score >= p.theta_alert {
                return Verdict { kind: VerdictKind::Alert, pattern: p.id.clone(), score, reason: "accepting".into() };
            }
            return Verdict { kind: VerdictKind::Suspect, pattern: p.id.clone(), score, reason: "accepting-low-score".into() };
        }

        // Not yet accepting: arm kernel if confident and an enforceable step pends.
        if score >= p.theta_block {
            let pending: Vec<&Step> = p
                .steps
                .iter()
                .filter(|s| s.enforceable && (completed & s.bit_mask()) == 0)
                .collect();
            if let Some(choke) = pending.first() {
                let armed_op = enforceable_op(choke);
                let already = self.storylines[&sid].automata[pid].armed;
                if !already {
                    self.storylines.get_mut(&sid).unwrap().automata.get_mut(pid).unwrap().armed = true;
                    self.kernel_arm.insert(sid, armed_op);
                    self.log.push(format!(
                        "ts={} ARM   pattern={} score={:.1} push kernel arm (deny next {:?} on storyline)",
                        e.ts, p.id, score, armed_op
                    ));
                }
            }
        }

        if score >= p.theta_alert {
            Verdict { kind: VerdictKind::Alert, pattern: p.id.clone(), score, reason: "partial-high-score".into() }
        } else {
            Verdict::none()
        }
    }
}

impl Default for Engine {
    fn default() -> Self {
        Engine::new()
    }
}

// ---- scoring helpers (§6) ---------------------------------------------------

fn kill_chain_score(p: &Pattern, completed: Mask, step_ts: &HashMap<u8, u64>, rules: &RuleSet) -> f64 {
    use rules::Tactic;
    let mut tactics: HashSet<u8> = HashSet::new();
    let mut sev = 0.0;
    let mut rarity = 0.0;
    for bit in bits(completed) {
        let step = p.step(bit);
        match &step.matcher {
            pattern::StepMatch::ByTtp(set) => {
                let m = rules.meta(&set[0]);
                tactics.insert(m.tactic.id());
                sev += m.severity;
                rarity += m.rarity;
            }
            pattern::StepMatch::ByOp(_) => {
                tactics.insert(Tactic::Staging.id());
                sev += 1.0;
                rarity += 0.15;
            }
        }
    }
    let stages = tactics.len() as f64;
    let order = order_observed(completed, step_ts);
    W_STAGES * stages + W_SEV * sev + W_ORDER * order + W_RARITY * rarity
}

fn order_observed(completed: Mask, step_ts: &HashMap<u8, u64>) -> f64 {
    let mut arr: Vec<(u64, u8)> = bits(completed)
        .into_iter()
        .filter_map(|b| step_ts.get(&b).map(|&t| (t, b)))
        .collect();
    if arr.len() <= 1 {
        return 1.0;
    }
    arr.sort();
    let mut good = 0;
    let mut total = 0;
    for w in arr.windows(2) {
        total += 1;
        if w[0].1 < w[1].1 {
            good += 1;
        }
    }
    good as f64 / total as f64
}

fn bits(mask: Mask) -> Vec<u8> {
    let mut v = Vec::new();
    let mut m = mask;
    while m != 0 {
        let b = m.trailing_zeros() as u8;
        v.push(b);
        m &= m - 1;
    }
    v
}

fn enforceable_op(step: &Step) -> Op {
    match &step.matcher {
        pattern::StepMatch::ByOp(op) => *op,
        pattern::StepMatch::ByTtp(set) => match set.first().map(|s| s.as_str()) {
            Some("T1486") => Op::Write,
            Some("T1490") => Op::Exec,
            Some("T1003") => Op::Read,
            _ => Op::Write,
        },
    }
}

fn step_is_enforceable_chokepoint(patterns: &[Pattern], s: &Storyline, op: Op) -> bool {
    for (pid, a) in &s.automata {
        if let Some(p) = patterns.iter().find(|p| &p.id == pid) {
            if let Some(bit) = p.block_at {
                let st = p.step(bit);
                if st.enforceable && enforceable_op(st) == op && !a.has(bit) {
                    return true;
                }
            }
        }
    }
    false
}
