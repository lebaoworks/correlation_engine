//! **Endpoint** — the fast/light/accurate half (engine.md §1–§7).
//!
//! Differences from the original monolithic core (bak/engine.md), all deliberate:
//!  * **No local graph.** Edges are never stored; every event is shipped to the
//!    backend and forgotten (§4). The endpoint keeps only *detection* state.
//!  * **Working-set invariant** (§3): an entity is retained iff it is bound by a
//!    live automaton (`refcount>0`) OR touched within window `W`. Memory is bounded
//!    by that invariant, not by an eviction policy.
//!  * **Storyline = explicit small set** (§5), not a global union-find; deletable.
//!  * **Binding by identity** (`bound_ids: NodeKey`), so dropping a node never
//!    breaks an automaton (§2).
//!  * **seg_window GC** releases refcounts; cold unbound entities are swept (§6c).
//!  * Kernel-arm is keyed by **identity** (§9).

use crate::event::{Event, NodeKey, Op};
use crate::pattern::{Mask, Pattern, RoleSource, Scope, Step, StepMatch};
use crate::rules::{RateState, RuleSet, Tactic};
use crate::{Decision, Verdict, VerdictKind, DEFAULT_RULES};
use std::collections::{HashMap, HashSet, VecDeque};

use crate::wire::{BlockReport, Wire, WireEvent};

/// Working-set window: an unbound entity idle longer than this is swept (§3).
pub const DEFAULT_W_MS: u64 = 300_000;
const TTP_RING_CAP: usize = 32;

// ---- scoring weights (mirror crate::lib §6) ---------------------------
const W_STAGES: f64 = 2.0;
const W_SEV: f64 = 0.3;
const W_ORDER: f64 = 1.0;
const W_RARITY: f64 = 2.0;

fn verdict_none() -> Verdict {
    Verdict {
        kind: VerdictKind::None,
        pattern: String::new(),
        score: 0.0,
        reason: String::new(),
        advanced: false,
        completed: false,
    }
}

/// A control-plane command the endpoint pushes to the kernel sensor so that
/// *only* the exact `(actor identity, op)` about to hit a chokepoint travels the
/// synchronous enforcement path; everything else stays async telemetry (§9).
///
/// The sensor keeps a small arm table: on `Arm` it starts sending that
/// `(actor, op)` synchronously (with a reply) and enforcing the verdict inline;
/// on `Disarm` it drops back to fire-and-forget for that identity. Arms are
/// keyed by identity `(pid, start_ts)` — reused pids never inherit a stale arm.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ArmCmd {
    Arm { actor: NodeKey, op: Op },
    Disarm { actor: NodeKey },
}

// ---- lean state -------------------------------------------------------------

struct Entity {
    #[allow(dead_code)] // identity is the map key; copy kept for clarity/debug
    key: NodeKey,
    line: Option<usize>, // which storyline (explicit set) this entity belongs to
    refcount: u32,       // # live automata binding this identity → pins it warm (§3a)
    last_touch: u64,
}

struct Automaton {
    pattern_idx: usize,
    completed_mask: Mask,
    step_ts: HashMap<u8, u64>,
    bound_ids: HashMap<String, NodeKey>, // role -> identity (§2), NOT a node pointer
    pins: Vec<NodeKey>,                  // identities whose refcount we raised (released on GC)
    armed: bool,
    last_progress: u64,
}

impl Automaton {
    fn new(pattern_idx: usize, now: u64) -> Automaton {
        Automaton {
            pattern_idx,
            completed_mask: 0,
            step_ts: HashMap::new(),
            bound_ids: HashMap::new(),
            pins: Vec::new(),
            armed: false,
            last_progress: now,
        }
    }
    fn has(&self, bit: u8) -> bool {
        self.completed_mask & (1 << bit) != 0
    }
}

#[derive(Default)]
struct Storyline {
    members: HashSet<NodeKey>,
    automata: HashMap<String, Automaton>,
    ttp_ring: VecDeque<(String, u64)>,
    score: f64,
    last_activity: u64,
}

pub struct Endpoint {
    active: HashMap<NodeKey, Entity>,
    storylines: HashMap<usize, Storyline>,
    next_sid: usize,
    rules: RuleSet,
    rate: HashMap<NodeKey, RateState>,
    kernel_arm: HashMap<NodeKey, Op>, // armed identity -> denied op (§9)
    pushed_arms: HashMap<NodeKey, Op>, // arm state last emitted to the sensor
    arm_outbox: Vec<ArmCmd>,           // ARM/DISARM deltas awaiting push to the sensor
    outbox: Vec<Wire>,
    seq: u64,
    w_ms: u64,
    max_nodes_per_sid: usize,
    max_automata_per_sid: usize,
    // observability
    pub shipped_events: u64,
    pub shipped_blocks: u64,
    pub swept: u64,
    pub log: Vec<String>,
}

impl Endpoint {
    pub fn new() -> Endpoint {
        Endpoint::from_rules_str(DEFAULT_RULES).expect("builtin rules parse")
    }

    pub fn from_rules_str(s: &str) -> Result<Endpoint, String> {
        Ok(Endpoint::with_rules(RuleSet::parse_str(s)?))
    }

    pub fn from_rules_file(path: &str) -> Result<Endpoint, String> {
        let s = std::fs::read_to_string(path).map_err(|e| format!("read {}: {}", path, e))?;
        Endpoint::from_rules_str(&s)
    }

    pub fn with_rules(rules: RuleSet) -> Endpoint {
        Endpoint {
            active: HashMap::new(),
            storylines: HashMap::new(),
            next_sid: 0,
            rules,
            rate: HashMap::new(),
            kernel_arm: HashMap::new(),
            pushed_arms: HashMap::new(),
            arm_outbox: Vec::new(),
            outbox: Vec::new(),
            seq: 0,
            w_ms: DEFAULT_W_MS,
            max_nodes_per_sid: 4096,
            max_automata_per_sid: 32,
            shipped_events: 0,
            shipped_blocks: 0,
            swept: 0,
            log: Vec::new(),
        }
    }

    pub fn set_window_ms(&mut self, w: u64) {
        self.w_ms = w;
    }
    pub fn active_len(&self) -> usize {
        self.active.len()
    }
    pub fn storyline_count(&self) -> usize {
        self.storylines.len()
    }
    /// Take everything queued for the backend (ship-and-forget drain).
    pub fn drain_outbox(&mut self) -> Vec<Wire> {
        std::mem::take(&mut self.outbox)
    }

    /// Take the pending control-plane arm deltas to push down to the sensor (§9).
    /// The caller forwards these to the kernel so only armed `(actor, op)` pairs
    /// take the synchronous enforcement path.
    pub fn drain_arm_cmds(&mut self) -> Vec<ArmCmd> {
        std::mem::take(&mut self.arm_outbox)
    }

    // -- working set ---------------------------------------------------------
    fn touch(&mut self, key: &NodeKey, now: u64) {
        let e = self
            .active
            .entry(key.clone())
            .or_insert_with(|| Entity { key: key.clone(), line: None, refcount: 0, last_touch: now });
        e.last_touch = now;
    }

    fn line_of(&mut self, key: &NodeKey, now: u64) -> usize {
        self.touch(key, now);
        if let Some(sid) = self.active[key].line {
            return sid;
        }
        let sid = self.next_sid;
        self.next_sid += 1;
        let mut s = Storyline::default();
        s.members.insert(key.clone());
        s.last_activity = now;
        self.storylines.insert(sid, s);
        self.active.get_mut(key).unwrap().line = Some(sid);
        sid
    }

    // -- LINK: causal merge over explicit small sets (§5) --------------------
    fn link(&mut self, actor: &NodeKey, object: &NodeKey, op: Op, now: u64) -> usize {
        let sa = self.line_of(actor, now);
        if !op.is_causal() {
            return sa; // touch edge: no merge (edge is shipped for forensics)
        }
        let so = self.line_of(object, now);
        if sa == so {
            return sa;
        }
        self.merge(sa, so)
    }

    fn merge(&mut self, a: usize, b: usize) -> usize {
        // union by size (members + automata)
        let (root, child) = {
            let sa = &self.storylines[&a];
            let sb = &self.storylines[&b];
            if sa.members.len() + sa.automata.len() >= sb.members.len() + sb.automata.len() {
                (a, b)
            } else {
                (b, a)
            }
        };
        // Hub cap: if the merge would exceed the size cap, DON'T merge on the endpoint —
        // leave two storylines; the backend stitches them from the shipped causal edge (§5).
        let mm = self.storylines[&root].members.len() + self.storylines[&child].members.len();
        let ma = self.storylines[&root].automata.len() + self.storylines[&child].automata.len();
        if mm > self.max_nodes_per_sid || ma > self.max_automata_per_sid {
            return root;
        }

        let child_s = self.storylines.remove(&child).unwrap();
        for m in &child_s.members {
            if let Some(ent) = self.active.get_mut(m) {
                ent.line = Some(root);
            }
        }
        let root_s = self.storylines.get_mut(&root).unwrap();
        for m in child_s.members {
            root_s.members.insert(m);
        }
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
                    for (role, key) in autom.bound_ids {
                        existing.bound_ids.entry(role).or_insert(key);
                    }
                    // keep child's pins so refcounts stay balanced at GC time
                    existing.pins.extend(autom.pins);
                    existing.armed |= autom.armed;
                    existing.last_progress = existing.last_progress.max(autom.last_progress);
                }
            }
        }
        for h in child_s.ttp_ring {
            root_s.ttp_ring.push_back(h);
        }
        root_s.score = root_s.score.max(child_s.score);
        root_s.last_activity = root_s.last_activity.max(child_s.last_activity);
        root
    }

    // -- per-event pipeline (§4) ---------------------------------------------
    pub fn on_event(&mut self, e: &Event) -> (Decision, Verdict) {
        let now = e.ts;
        let sid = self.link(&e.actor, &e.object, e.op, now);
        if let Some(img) = e.image_key() {
            self.touch(&img, now); // image entity warm (may be bound by a dropper step)
        }

        let rate = self.rate.entry(e.actor.clone()).or_default();
        let ttps = self.rules.tag(e, rate);
        {
            let s = self.storylines.get_mut(&sid).unwrap();
            s.last_activity = now;
            for t in &ttps {
                s.ttp_ring.push_back((t.clone(), now));
                while s.ttp_ring.len() > TTP_RING_CAP {
                    s.ttp_ring.pop_front();
                }
            }
        }

        // SHIP every event (ship-and-forget). Edge lives only long enough to update
        // LINK + rate, then it is the backend's to keep.
        self.seq += 1;
        self.shipped_events += 1;
        self.outbox.push(Wire::Event(WireEvent {
            seq: self.seq,
            endpoint_sid: sid,
            ttps: ttps.clone(),
            event: e.clone(),
        }));

        // Kernel-arm fast path (arm by identity, §9): the actor is armed for this op
        // and its storyline still has a pending enforceable chokepoint of this op.
        let mut kernel_denied = false;
        if let Some(&armed_op) = self.kernel_arm.get(&e.actor) {
            if armed_op == e.op && self.storyline_has_pending_chokepoint(sid, e.op) {
                kernel_denied = true;
            }
        }

        let verdict = self.advance(sid, &ttps, e, now);
        let decision = if verdict.kind == VerdictKind::Block || kernel_denied {
            Decision::Deny
        } else {
            Decision::Allow
        };

        if decision == Decision::Deny {
            // Control-plane: ask the backend to trace & display the whole chain.
            let (pattern, score, reason) = if verdict.kind == VerdictKind::Block {
                (verdict.pattern.clone(), verdict.score, verdict.reason.clone())
            } else {
                (
                    "armed-chokepoint".to_string(),
                    self.storylines.get(&sid).map(|s| s.score).unwrap_or(0.0),
                    "kernel-armed deny".to_string(),
                )
            };
            self.seq += 1;
            self.shipped_blocks += 1;
            self.outbox.push(Wire::Block(BlockReport { seq: self.seq, pattern, score, reason, event: e.clone() }));
            self.log.push(format!(
                "ts={} DENY  ship BlockReport → backend (actor={} op={:?})",
                now,
                short_key(&e.actor),
                e.op
            ));
        }

        // lifecycle: GC dead automata (release pins), then sweep cold unbound entities (§3, §6c)
        self.gc_and_sweep(now);

        // Reconcile the sensor's arm table against the live chokepoints (§9): emit
        // ARM/DISARM so the kernel enforces synchronously *only* the identities
        // that are one step from a block.
        self.reconcile_arms();
        (decision, verdict)
    }

    /// Prune arms that no longer back a pending chokepoint (the block fired, or the
    /// storyline GC'd), then diff the justified set against what the sensor was last
    /// told and queue the deltas. Keeps `kernel_arm` honest so the pushed-down table
    /// never denies a stale (e.g. pid-reused) identity.
    fn reconcile_arms(&mut self) {
        // Recompute which existing arms are still justified by a live storyline.
        let candidates: Vec<(NodeKey, Op)> =
            self.kernel_arm.iter().map(|(k, op)| (k.clone(), *op)).collect();
        let mut justified: HashMap<NodeKey, Op> = HashMap::new();
        for (actor, op) in candidates {
            if let Some(sid) = self.active.get(&actor).and_then(|e| e.line) {
                if self.storyline_has_pending_chokepoint(sid, op) {
                    justified.insert(actor, op);
                }
            }
        }
        self.kernel_arm = justified.clone();

        // Diff against the last pushed state → ARM new / re-keyed, DISARM dropped.
        for (actor, op) in &justified {
            if self.pushed_arms.get(actor) != Some(op) {
                self.arm_outbox.push(ArmCmd::Arm { actor: actor.clone(), op: *op });
            }
        }
        for actor in self.pushed_arms.keys() {
            if !justified.contains_key(actor) {
                self.arm_outbox.push(ArmCmd::Disarm { actor: actor.clone() });
            }
        }
        self.pushed_arms = justified;
    }

    fn storyline_has_pending_chokepoint(&self, sid: usize, op: Op) -> bool {
        let s = match self.storylines.get(&sid) {
            Some(s) => s,
            None => return false,
        };
        for a in s.automata.values() {
            let p = &self.rules.patterns[a.pattern_idx];
            if let Some(bit) = p.block_at {
                let st = p.step(bit);
                if st.enforceable && enforceable_op(st) == op && !a.has(bit) {
                    return true;
                }
            }
        }
        false
    }

    // -- ADVANCE: partial-order matching (§6) --------------------------------
    fn advance(&mut self, sid: usize, ttps: &[String], e: &Event, now: u64) -> Verdict {
        // (a) seed root automata whose root step matches this event (no admission gate)
        let mut to_start: Vec<(usize, String)> = Vec::new();
        for (idx, p) in self.rules.patterns.iter().enumerate() {
            if self.storylines[&sid].automata.contains_key(&p.id) {
                continue;
            }
            if p.root_steps().any(|rs| rs.slot_matches(e, ttps) && p.root_gate.ok(e)) {
                // safety-net cap: don't seed beyond MAX_AUTOMATA_PER_SID (event already shipped)
                if self.storylines[&sid].automata.len() + to_start.len() >= self.max_automata_per_sid {
                    break;
                }
                to_start.push((idx, p.id.clone()));
            }
        }
        for (idx, pid) in to_start {
            self.storylines.get_mut(&sid).unwrap().automata.insert(pid, Automaton::new(idx, now));
        }

        // (b) advance every automaton on this storyline
        let pattern_ids: Vec<String> = self.storylines[&sid].automata.keys().cloned().collect();
        let mut best = verdict_none();
        let mut advanced = false; // this event committed ≥1 step (matched an automaton)
        let mut completed = false; // this event drove some pattern to accept
        for pid in pattern_ids {
            let idx = self.storylines[&sid].automata[&pid].pattern_idx;
            let matching: Vec<u8> = self.rules.patterns[idx]
                .steps
                .iter()
                .filter(|s| s.slot_matches(e, ttps))
                .map(|s| s.bit)
                .collect();
            for bit in matching {
                if self.try_commit(sid, idx, &pid, bit, e, now) {
                    advanced = true;
                    let v = self.rescore_and_emit(sid, idx, &pid, bit, e, now);
                    completed |= v.completed;
                    if v.kind > best.kind {
                        best = v;
                    }
                }
            }
        }
        best.advanced = advanced;
        best.completed = completed;
        best
    }

    fn try_commit(&mut self, sid: usize, idx: usize, pid: &str, bit: u8, e: &Event, now: u64) -> bool {
        let (prereq, seg_window, bindings) = {
            let step = self.rules.patterns[idx].step(bit);
            (step.prereq_mask, step.seg_window, step.bindings.clone())
        };
        let scope = self.rules.patterns[idx].scope;

        let a = self.storylines[&sid].automata.get(pid).unwrap();
        if a.has(bit) {
            return false;
        }
        if (prereq & a.completed_mask) != prereq {
            return false; // PREREQ_OK — partial order
        }
        if prereq != 0 {
            let mut t_enabled = 0u64;
            for b in bits(prereq) {
                if let Some(&t) = a.step_ts.get(&b) {
                    t_enabled = t_enabled.max(t);
                }
            }
            if now.saturating_sub(t_enabled) > seg_window {
                return false; // SEG_WINDOW_OK — per-segment deadline (§5.6)
            }
        }
        let scope_ok = match scope {
            Scope::SameStoryline => true,
            Scope::SameActor => a.bound_ids.values().any(|k| k == &e.actor),
            Scope::Free => true,
        };
        if !scope_ok {
            return false;
        }
        // BINDING_OK — by identity (§2/§5.8): "write X, exec Y" is rejected here.
        let mut resolved: Vec<(String, NodeKey)> = Vec::new();
        for b in &bindings {
            let key = match b.source {
                RoleSource::Object => Some(e.object.clone()),
                RoleSource::Actor => Some(e.actor.clone()),
                RoleSource::Image => e.image_key(),
            };
            let key = match key {
                Some(k) => k,
                None => return false,
            };
            if let Some(existing) = a.bound_ids.get(&b.role) {
                if existing != &key {
                    return false;
                }
            }
            resolved.push((b.role.clone(), key));
        }

        // COMMIT_STEP + pin newly bound identities (raise refcount)
        let mut newly_pinned: Vec<NodeKey> = Vec::new();
        {
            let a = self.storylines.get_mut(&sid).unwrap().automata.get_mut(pid).unwrap();
            a.completed_mask |= 1 << bit;
            a.step_ts.insert(bit, now);
            a.last_progress = now;
            for (role, key) in resolved {
                if !a.bound_ids.contains_key(&role) {
                    a.bound_ids.insert(role.clone(), key.clone());
                    a.pins.push(key.clone());
                    newly_pinned.push(key);
                }
            }
        }
        for key in newly_pinned {
            if let Some(ent) = self.active.get_mut(&key) {
                ent.refcount += 1;
            }
        }
        true
    }

    fn rescore_and_emit(&mut self, sid: usize, idx: usize, pid: &str, bit: u8, e: &Event, now: u64) -> Verdict {
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
                    now, p.id, score, step.name
                ));
                return Verdict {
                    kind: VerdictKind::Block,
                    pattern: p.id.clone(),
                    score,
                    reason: format!("chokepoint {}", step.name),
                    advanced: true,
                    completed: true,
                };
            }
            if score >= p.theta_alert {
                return Verdict { kind: VerdictKind::Alert, pattern: p.id.clone(), score, reason: "accepting".into(), advanced: true, completed: true };
            }
            return Verdict { kind: VerdictKind::Suspect, pattern: p.id.clone(), score, reason: "accepting-low-score".into(), advanced: true, completed: true };
        }

        // Not yet accepting: arm the kernel (by actor identity) if confident and an
        // enforceable step still pends (§5.5).
        if score >= p.theta_block {
            let pending: Vec<&Step> =
                p.steps.iter().filter(|s| s.enforceable && (completed & s.bit_mask()) == 0).collect();
            if let Some(choke) = pending.first() {
                let armed_op = enforceable_op(choke);
                let already = self.storylines[&sid].automata[pid].armed;
                if !already {
                    self.storylines.get_mut(&sid).unwrap().automata.get_mut(pid).unwrap().armed = true;
                    self.kernel_arm.insert(e.actor.clone(), armed_op);
                    self.log.push(format!(
                        "ts={} ARM   pattern={} score={:.1} arm identity={} deny next {:?}",
                        now,
                        p.id,
                        score,
                        short_key(&e.actor),
                        armed_op
                    ));
                }
            }
        }

        if score >= p.theta_alert {
            // Advanced (a step committed) but the pattern hasn't accepted yet.
            Verdict {
                kind: VerdictKind::Alert,
                pattern: p.id.clone(),
                score,
                reason: "partial-high-score".into(),
                advanced: true,
                completed: false,
            }
        } else {
            // Committed a step but below any threshold → no verdict, still "advanced"
            // is set by advance(); here just report None.
            verdict_none()
        }
    }

    // -- lifecycle: seg_window GC + working-set sweep (§3, §6c) ---------------
    fn gc_and_sweep(&mut self, now: u64) {
        // (1) GC automata that can no longer make progress; release their pins.
        let sids: Vec<usize> = self.storylines.keys().cloned().collect();
        for sid in sids {
            let dead: Vec<String> = {
                let s = match self.storylines.get(&sid) {
                    Some(s) => s,
                    None => continue,
                };
                s.automata
                    .iter()
                    .filter_map(|(pid, a)| {
                        if automaton_dead(&self.rules.patterns[a.pattern_idx], a, now) {
                            Some(pid.clone())
                        } else {
                            None
                        }
                    })
                    .collect()
            };
            for pid in dead {
                if let Some(a) = self.storylines.get_mut(&sid).unwrap().automata.remove(&pid) {
                    for key in a.pins {
                        if let Some(ent) = self.active.get_mut(&key) {
                            ent.refcount = ent.refcount.saturating_sub(1);
                        }
                    }
                    self.log.push(format!("ts={} GC    automaton pattern={} (seg_window expired)", now, pid));
                }
            }
        }

        // (2) sweep cold, unbound entities — the working-set invariant (§3).
        let cold: Vec<NodeKey> = self
            .active
            .iter()
            .filter(|(_, e)| e.refcount == 0 && now.saturating_sub(e.last_touch) > self.w_ms)
            .map(|(k, _)| k.clone())
            .collect();
        for k in cold {
            if let Some(ent) = self.active.remove(&k) {
                if let Some(sid) = ent.line {
                    if let Some(s) = self.storylines.get_mut(&sid) {
                        s.members.remove(&k);
                    }
                }
                self.rate.remove(&k);
                self.swept += 1;
            }
        }

        // (3) drop storylines that are now empty of members and automata.
        let empty: Vec<usize> = self
            .storylines
            .iter()
            .filter(|(_, s)| s.members.is_empty() && s.automata.is_empty())
            .map(|(id, _)| *id)
            .collect();
        for id in empty {
            self.storylines.remove(&id);
        }
    }
}

impl Default for Endpoint {
    fn default() -> Self {
        Endpoint::new()
    }
}

// ---- helpers (ported from crate::lib, using only public API) ----------

fn automaton_dead(p: &Pattern, a: &Automaton, now: u64) -> bool {
    // No progress for longer than the pattern's largest segment window ⟹ no enabled
    // step could still be committed in time (§6c). Coarse but safe: the worst case a
    // single segment can wait is its own seg_window.
    let max_seg = p.steps.iter().map(|s| s.seg_window).max().unwrap_or(0);
    now.saturating_sub(a.last_progress) > max_seg
}

fn kill_chain_score(
    p: &Pattern,
    completed: Mask,
    step_ts: &HashMap<u8, u64>,
    rules: &RuleSet,
) -> f64 {
    let mut tactics: HashSet<u8> = HashSet::new();
    let mut sev = 0.0;
    let mut rarity = 0.0;
    for bit in bits(completed) {
        let step = p.step(bit);
        match &step.matcher {
            StepMatch::ByTtp(set) => {
                let m = rules.meta(&set[0]);
                tactics.insert(m.tactic.id());
                sev += m.severity;
                rarity += m.rarity;
            }
            StepMatch::ByOp(_) => {
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
    let mut arr: Vec<(u64, u8)> =
        bits(completed).into_iter().filter_map(|b| step_ts.get(&b).map(|&t| (t, b))).collect();
    if arr.len() <= 1 {
        return 1.0;
    }
    arr.sort();
    let (mut good, mut total) = (0, 0);
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
        v.push(m.trailing_zeros() as u8);
        m &= m - 1;
    }
    v
}

fn enforceable_op(step: &Step) -> Op {
    match &step.matcher {
        StepMatch::ByOp(op) => *op,
        StepMatch::ByTtp(set) => match set.first().map(|s| s.as_str()) {
            Some("T1486") => Op::Write,
            Some("T1490") => Op::Exec,
            Some("T1003") => Op::Read,
            _ => Op::Write,
        },
    }
}

fn short_key(k: &NodeKey) -> String {
    match k {
        NodeKey::Process { pid, start_ts } => format!("proc {}.{}", pid, start_ts),
        NodeKey::File { file_id } => format!("file:{}", file_id),
        NodeKey::Socket { key } => format!("sock:{}", key),
        NodeKey::Other { kind, key } => format!("{}:{}", kind, key),
    }
}
