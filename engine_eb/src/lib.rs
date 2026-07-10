//! Endpoint–backend split detection core (engine_endpoint_backend.md).
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

pub mod backend;
pub mod endpoint;
pub mod wire;

pub use backend::{render_chain, Backend, Chain, ChainStep};
pub use endpoint::Endpoint;
pub use edr_engine::{Decision, Verdict, VerdictKind};
pub use edr_engine::event::{Event, NodeKey, Op};

use wire::Wire;

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
        let (d, v) = self.endpoint.on_event(e);
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
