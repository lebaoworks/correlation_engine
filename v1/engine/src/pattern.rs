//! Attack patterns as **partial-order precedence DAGs** (engine.md §5.1).
//!
//! These are pure data structures. Concrete patterns are no longer hardcoded here —
//! they are declared in an external rule file and built by `rules::parse_str`.
//! Progress is a bitmask (`completed_mask`), not a linear stage; order is encoded
//! purely by `prereq_mask`, so free-order groups, milestones and OR-slots all fall
//! out of the same O(1) bitwise test.

use crate::event::{Event, Op};

pub type Mask = u64; // up to 64 steps/pattern

/// Where a step reads the node it binds/compares against.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RoleSource {
    Object, // the event's object node
    Image,  // attrs["image"] resolved to a File node (exec image)
    Actor,  // the event's actor node
}

/// A variable-binding constraint: this role must resolve to the same node across
/// steps (engine.md §5.8). Binding by *identity* (FileId), not path.
#[derive(Clone, Debug)]
pub struct RoleBinding {
    pub role: String,
    pub source: RoleSource,
}

/// How a step is satisfied.
#[derive(Clone, Debug)]
pub enum StepMatch {
    /// OR-slot: any TTP in this set satisfies the step (tool variants).
    ByTtp(Vec<String>),
    /// Structural: a raw op (e.g. dropper write/exec, TTP-less).
    ByOp(Op),
}

#[derive(Clone, Debug)]
pub struct Step {
    pub bit: u8,
    pub name: String,
    pub matcher: StepMatch,
    pub prereq_mask: Mask, // bits that MUST be completed first (partial order)
    pub seg_window: u64,   // ms deadline measured from when prereq became satisfied
    pub enforceable: bool, // is this a chokepoint we can synchronously deny?
    pub optional: bool,    // excluded from required_mask
    pub bindings: Vec<RoleBinding>,
}

impl Step {
    pub fn bit_mask(&self) -> Mask {
        1 << self.bit
    }
    /// Does event `e` (with its confirmed `ttps`) match this step's slot?
    pub fn slot_matches(&self, e: &Event, ttps: &[String]) -> bool {
        match &self.matcher {
            StepMatch::ByTtp(set) => ttps.iter().any(|t| set.contains(t)),
            StepMatch::ByOp(op) => e.op == *op,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Scope {
    SameStoryline,
    SameActor,
    Free,
}

/// Root-seeding gate: a small closed set of named guards that keep the number of
/// live automata bounded (engine.md §7). Data-selectable, not arbitrary code.
#[derive(Clone, Copy, Debug)]
pub enum RootGate {
    Always,
    PeWrite, // only executable-file writes may seed (e.g. the dropper pattern)
}

impl RootGate {
    pub fn ok(self, e: &Event) -> bool {
        match self {
            RootGate::Always => true,
            RootGate::PeWrite => e.op == Op::Write && e.attr_bool("pe"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Pattern {
    pub id: String,
    pub steps: Vec<Step>,
    pub required_mask: Mask, // bits needed to accept
    pub scope: Scope,
    pub block_at: Option<u8>, // bit of the enforceable chokepoint
    pub theta_alert: f64,
    pub theta_block: f64,
    pub root_gate: RootGate,
}

impl Pattern {
    pub fn step(&self, bit: u8) -> &Step {
        self.steps.iter().find(|s| s.bit == bit).expect("bit exists")
    }
    pub fn root_steps(&self) -> impl Iterator<Item = &Step> {
        self.steps.iter().filter(|s| s.prereq_mask == 0)
    }
}
