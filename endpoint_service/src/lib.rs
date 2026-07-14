//! EDR userland service — bridges the kernel **sensor** to the detection **engine**.
//!
//! Pipeline per batch: decode sensor frames (`sensor`) → normalize to engine events
//! (`translate`) → feed the engine (`edr_engine::Pipeline`) → collect a per-event
//! ALLOW/DENY and, on a block, the backend-reconstructed chain. The batch-level
//! decision is handed back to the sensor by the source's `reply`.

pub mod control;
pub mod sensor;
pub mod source;
pub mod translate;
#[cfg(windows)]
pub mod winport;

use edr_engine::wire::Wire;
use edr_engine::{ArmCmd, Chain, Decision, Pipeline};

/// The default rule set for the service: the engine's built-in patterns (which
/// already declare the T1003 ttp + tagger) plus the LSASS-dump *pattern* only, so
/// no ttp/tagger is duplicated. Embedded so it works regardless of the cwd.
pub const SERVICE_RULES: &str = concat!(
    include_str!("../../engine/rules/builtin.rules"),
    "\n",
    include_str!("../rules/lsass_pattern.rules"),
);

/// One decoded event's outcome, ready to print. The `advanced`/`completed` flags
/// come straight from the engine verdict so the caller can pick a log level:
/// no match → debug, matched an automaton → info, completed a chain → warn.
pub struct EventOutcome {
    pub line: String,
    pub deny: bool,
    /// The event committed ≥1 automaton step (matched a live detection).
    pub advanced: bool,
    /// The event drove a pattern to accept (a detection chain completed).
    pub completed: bool,
}

/// Result of processing one batch.
pub struct BatchOutcome {
    pub outcomes: Vec<EventOutcome>,
    pub chains: Vec<Chain>,
    /// True if any event in the batch was denied → the batch's block decision.
    pub deny: bool,
    /// Sensor records the engine has no op for (process enumeration / exit).
    pub state_only: usize,
    /// Control-plane arm/disarm deltas to push down to the sensor (§9): the driver
    /// enforces synchronously *only* the `(actor, op)` pairs armed here.
    pub arms: Vec<ArmCmd>,
    /// Wire records to ship to the remote backend service (only filled when
    /// `Service.remote` — otherwise the in-process backend consumed them and
    /// `chains` carries the reconstruction).
    pub wire: Vec<Wire>,
}

pub struct Service {
    pub pipe: Pipeline,
    /// True when a backend service is attached: the endpoint's outbox is handed
    /// to the caller (`BatchOutcome.wire`) instead of the in-process backend, and
    /// storyline reconstruction happens on the backend's console.
    pub remote: bool,
    pub events_seen: u64,
    pub denies: u64,
}

impl Service {
    pub fn new() -> Result<Service, String> {
        Service::with_rules(SERVICE_RULES)
    }

    pub fn with_rules(rules: &str) -> Result<Service, String> {
        Ok(Service { pipe: Pipeline::from_rules_str(rules)?, remote: false, events_seen: 0, denies: 0 })
    }

    /// Decode a raw batch payload, run every event through the engine, and return
    /// the per-event decisions + any reconstructed chains.
    pub fn process_batch(&mut self, payload: &[u8]) -> Result<BatchOutcome, String> {
        let events = sensor::parse_batch(payload)?;
        let mut outcomes = Vec::new();
        let mut chains = Vec::new();
        let mut wire = Vec::new();
        let mut deny = false;
        let mut state_only = 0;

        for se in events {
            // Read the cheap log hint (Copy fields only) before the record is moved
            // into the translator, which consumes it to avoid re-copying its strings.
            let ttp = ttp_hint(&se);
            let ev = match translate::to_engine_event(se) {
                Some(e) => e,
                None => {
                    state_only += 1;
                    continue;
                }
            };
            self.events_seen += 1;
            // Snapshot the display fields before the event is moved into the engine
            // (which now consumes it, so its strings are never copied on this path).
            let (ev_ts, ev_op, actor_s, object_s) =
                (ev.ts, ev.op, key_short(&ev.actor), key_short(&ev.object));
            let (d, v) = self.pipe.endpoint.on_event(ev);
            // Ship the outbox: to the remote backend service when attached,
            // otherwise into the in-process backend (which reconstructs chains).
            let mut chain = None;
            for msg in self.pipe.endpoint.drain_outbox() {
                if self.remote {
                    wire.push(msg);
                } else if let Some(c) = self.pipe.backend.ingest(msg) {
                    chain = Some(c);
                }
            }
            let is_deny = d == Decision::Deny;
            if is_deny {
                self.denies += 1;
                deny = true;
                if let Some(c) = chain {
                    chains.push(c);
                }
            }
            let vtxt = if v.kind == edr_engine::VerdictKind::None {
                String::new()
            } else {
                format!("  [{:?} {} {:.1}]", v.kind, v.pattern, v.score)
            };
            outcomes.push(EventOutcome {
                line: format!(
                    "  ts={:<10} {:<7} {:<20} -> {:<20} {}{}{}",
                    ev_ts,
                    op_name(ev_op),
                    actor_s,
                    object_s,
                    ttp,
                    if is_deny { "DENY" } else { "ALLOW" },
                    vtxt
                ),
                deny: is_deny,
                advanced: v.advanced,
                completed: v.completed,
            });
        }
        // Collect the control-plane arm deltas this batch produced; the caller
        // pushes them down to the sensor so only these identities enforce inline.
        let arms = self.pipe.endpoint.drain_arm_cmds();
        Ok(BatchOutcome { outcomes, chains, deny, state_only, arms, wire })
    }
}

fn op_name(op: edr_engine::Op) -> &'static str {
    use edr_engine::Op::*;
    match op {
        Exec => "exec",
        Open => "open",
        Read => "read",
        Write => "write",
        Connect => "connect",
        Inject => "inject",
        Create => "create",
        Delete => "delete",
        Load => "load",
        Dup => "dup",
    }
}

fn key_short(k: &edr_engine::NodeKey) -> String {
    use edr_engine::NodeKey::*;
    match k {
        Process { pid, start_ts } => format!("{}.{}", pid, start_ts),
        File { file_id } => {
            let b = file_id.rsplit(['\\', '/']).next().unwrap_or(file_id);
            format!("file:{}", b)
        }
        Socket { key } => format!("sock:{}", key),
        Other { kind, key } => format!("{}:{}", kind, key),
    }
}

fn ttp_hint(se: &sensor::SensorEvent) -> &'static str {
    use sensor::SensorEvent::*;
    match se {
        ProcessOpen { desired_access, .. } if desired_access & 0x0010 != 0 => "[→lsass? T1003] ",
        ProcessCreate { .. } => "[exec] ",
        RemoteThreadCreate { .. } => "[inject] ",
        _ => "",
    }
}
