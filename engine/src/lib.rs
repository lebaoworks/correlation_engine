//! Endpoint–backend split detection core (engine.md).
//!
//! Two halves with a crisp contract:
//!  * [`endpoint::Endpoint`] — fast/light/accurate inline blocker. Bounded memory
//!    via the working-set invariant (§3); ships every event, blocks locally, keeps
//!    no forensic graph.
//!  * [`backend::Backend`] — unbounded forensic correlator. Holds the full graph;
//!    on a block it rebuilds and displays the whole storyline.
//!
//! [`Pipeline`] wires them: feed one event, the endpoint decides + ships, the
//! backend ingests, and on a block you get the reconstructed [`Chain`] back.
//!
//! The pure telemetry/rule model (`event`, `pattern`, `rules`, `dataset`) is shared
//! infrastructure carried over from the original engine.md prototype.

pub mod backend;
pub mod dataset;
pub mod endpoint;
pub mod event;
pub mod pattern;
pub mod rules;
pub mod wire;

use wire::Wire;

/// Default rule set, embedded so `Endpoint::new()` works out of the box.
pub const DEFAULT_RULES: &str = include_str!("../rules/builtin.rules");

// ---- verdict / decision (inline enforcement, bak/engine.md §5.5, §8) --------

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
    /// This event committed ≥1 automaton step — i.e. it matched/advanced a live
    /// detection (even if the score stayed below any alert threshold).
    pub advanced: bool,
    /// This event drove a pattern to its accepting set — a detection chain completed.
    pub completed: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Decision {
    Allow,
    Deny,
}

pub use backend::{render_chain, Backend, Chain, ChainStep};
pub use endpoint::{ArmCmd, Endpoint};
pub use event::{Attrs, Event, NodeKey, Op};

/// Convenience harness: an endpoint feeding a backend over the ship channel.
pub struct Pipeline {
    pub endpoint: Endpoint,
    pub backend: Backend,
}

impl Pipeline {
    pub fn new() -> Pipeline {
        Pipeline { endpoint: Endpoint::new(), backend: Backend::new() }
    }

    pub fn from_rules_str(s: &str) -> Result<Pipeline, String> {
        Ok(Pipeline { endpoint: Endpoint::from_rules_str(s)?, backend: Backend::new() })
    }

    pub fn from_rules_file(path: &str) -> Result<Pipeline, String> {
        Ok(Pipeline { endpoint: Endpoint::from_rules_file(path)?, backend: Backend::new() })
    }

    /// Process one event end-to-end. Returns the endpoint decision + verdict, and
    /// any chain the backend rebuilt (present exactly when a block was shipped).
    pub fn feed(&mut self, e: &Event) -> (Decision, Verdict, Option<Chain>) {
        // `feed` is the in-process replay/test path; it keeps the borrowing API and
        // pays one clone. The production hot path (endpoint service) calls
        // `on_event` directly and moves the event in — no copy.
        let (d, v) = self.endpoint.on_event(e.clone());
        let mut chain = None;
        for msg in self.endpoint.drain_outbox() {
            if let Wire::Block(_) = msg {
                if let Some(c) = self.backend.ingest(msg) {
                    chain = Some(c);
                }
            } else {
                self.backend.ingest(msg);
            }
        }
        (d, v, chain)
    }
}

impl Default for Pipeline {
    fn default() -> Self {
        Pipeline::new()
    }
}
