//! EDR backend service — the forensic half of engine.md §8, as a real service.
//!
//! Consumes the endpoint service's wire stream (contract: `proto/wire.proto`,
//! codec: `edr_proto`):
//! every [`Wire::Event`] grows the full provenance graph, and a [`Wire::Block`]
//! is the endpoint's alert — the backend walks the graph and renders the whole
//! storyline that led to the denied action.
//!
//! [`Ingestor`] is transport-agnostic: push raw bytes in (from TCP, a file, or
//! stdin), printable [`Output`] records come out. `main.rs` only does I/O.

use edr_engine::wire::Wire;
use edr_engine::{render_chain, Backend, NodeKey};
use edr_proto::decode_frame;

/// One printable result of ingesting bytes.
pub enum Output {
    /// A telemetry event was added to the graph (one formatted line).
    Event(String),
    /// The endpoint blocked something: the alert header + the reconstructed chain.
    Alert { header: String, chain: String },
}

/// Reassembles frames from a byte stream and feeds the forensic backend.
pub struct Ingestor {
    pub backend: Backend,
    buf: Vec<u8>,
    pub events: u64,
    pub alerts: u64,
    pub bad_frames: u64,
}

impl Ingestor {
    pub fn new() -> Ingestor {
        Ingestor { backend: Backend::new(), buf: Vec::new(), events: 0, alerts: 0, bad_frames: 0 }
    }

    /// Append raw bytes from the transport; decode and ingest every complete
    /// frame now available. Returns the printable outputs, in arrival order.
    pub fn push_bytes(&mut self, data: &[u8]) -> Result<Vec<Output>, String> {
        self.buf.extend_from_slice(data);
        let mut outs = Vec::new();
        let mut consumed = 0;
        loop {
            match decode_frame(&self.buf[consumed..]) {
                Ok(Some((wire, used))) => {
                    consumed += used;
                    outs.push(self.ingest(wire));
                }
                Ok(None) => break, // need more bytes for the next frame
                Err(e) => {
                    // The length prefix is intact (decode_frame only errors once the
                    // whole frame is buffered), so we know this frame's exact size:
                    // skip just it and resync, rather than tearing down the whole
                    // connection over one bad record.
                    let rest = &self.buf[consumed..];
                    let frame_len = 4 + u32::from_le_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
                    self.bad_frames += 1;
                    eprintln!("backend: bỏ 1 frame lỗi ({} byte): {} — giữ kết nối", frame_len, e);
                    consumed += frame_len;
                }
            }
        }
        self.buf.drain(..consumed);
        Ok(outs)
    }

    fn ingest(&mut self, wire: Wire) -> Output {
        match wire {
            Wire::Event(ref we) => {
                let line = format!(
                    "  seq={:<5} sid={:<3} ts={:<10} {:<7} {:<22} -> {:<22}{}",
                    we.seq,
                    we.endpoint_sid,
                    we.event.ts,
                    format!("{:?}", we.event.op).to_lowercase(),
                    key_short(&we.event.actor),
                    key_short(&we.event.object),
                    if we.ttps.is_empty() { String::new() } else { format!("  [{}]", we.ttps.join(",")) },
                );
                self.events += 1;
                self.backend.ingest(wire);
                Output::Event(line)
            }
            Wire::Block(ref br) => {
                self.alerts += 1;
                let header = format!(
                    "⚠ ALERT seq={} — endpoint DENY  pattern={}  score={:.1}  reason={}  → rà soát graph...",
                    br.seq, br.pattern, br.score, br.reason
                );
                let chain = match self.backend.ingest(wire) {
                    Some(c) => render_chain(&c),
                    None => "  (không truy vết được: actor chưa từng xuất hiện trong graph)\n".to_string(),
                };
                Output::Alert { header, chain }
            }
        }
    }

    /// Leftover bytes that never formed a complete frame (should be 0 at EOF).
    pub fn pending_bytes(&self) -> usize {
        self.buf.len()
    }
}

impl Default for Ingestor {
    fn default() -> Self {
        Ingestor::new()
    }
}

fn key_short(k: &NodeKey) -> String {
    match k {
        NodeKey::Process { pid, start_ts } => format!("proc {}.{}", pid, start_ts),
        NodeKey::File { file_id } => {
            let b = file_id.rsplit(['\\', '/']).next().unwrap_or(file_id);
            format!("file:{}", b)
        }
        NodeKey::Socket { key } => format!("sock:{}", key),
        NodeKey::Other { kind, key } => format!("{}:{}", kind, key),
    }
}
