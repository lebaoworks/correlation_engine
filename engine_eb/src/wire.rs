//! Messages crossing the endpoint → backend boundary (the "ship" channel, §2/§4).
//!
//! The endpoint **ships every event** (ship-and-forget) so the backend can hold the
//! full forensic graph; when the endpoint issues a block it additionally ships a
//! control-plane [`BlockReport`] asking the backend to trace and render the whole
//! chain. In this offline prototype the "wire" is just a `Vec<Wire>` the driver
//! drains — there is no serialization (the base crate is dependency-free).

use edr_engine::event::Event;

/// A normal telemetry record: one event, plus the TTPs the endpoint already
/// confirmed (so the backend annotates the chain without re-running taggers).
#[derive(Clone, Debug)]
pub struct WireEvent {
    pub seq: u64,
    pub endpoint_sid: usize, // endpoint's local storyline id (a hint; backend re-derives its own)
    pub ttps: Vec<String>,
    pub event: Event,
}

/// Control-plane record: the endpoint denied `event`; ask the backend to rebuild
/// the full storyline that led here and display it (forensic view).
#[derive(Clone, Debug)]
pub struct BlockReport {
    pub seq: u64,
    pub pattern: String,
    pub score: f64,
    pub reason: String,
    pub event: Event,
}

#[derive(Clone, Debug)]
pub enum Wire {
    Event(WireEvent),
    Block(BlockReport),
}
