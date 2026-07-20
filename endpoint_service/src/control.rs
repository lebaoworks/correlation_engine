//! Control-plane wire: ARM/DISARM commands the service pushes **down** to the
//! sensor (opposite direction from the event telemetry).
//!
//! This is the mechanism that keeps enforcement latency off the hot path (§9):
//! the engine arms only the exact `(process identity, op)` that is one step from
//! a chokepoint, and the service serializes that here and sends it to the driver's
//! control port. The driver keeps a small arm table; a callback whose
//! `(pid, op)` is armed goes the synchronous `FltSendMessage`-with-reply path and
//! is enforced inline, while every other event stays fire-and-forget telemetry.
//!
//! ```text
//! cmd = Kind:u8 (1=Arm, 2=Disarm) ++ Op:u8 ++ pad[2]
//!       ++ Pid:u32le ++ PidStartMs:u64le
//! ```
//! Fixed 16 bytes, naturally aligned — the driver reads fields at fixed offsets.
//!
//! Two more records ride the same channel now that telemetry moved to the shared
//! ring (`ringbuf`). Both are the same fixed 16 bytes, so the driver's
//! `InputBufferLength % 16 == 0` check and its flat parse loop are unchanged:
//!
//! ```text
//! register = Kind:u8 (4) ++ pad[3] ++ RingBytes:u32le ++ DoorbellHandle:u64le
//! verdict  = Kind:u8 (5) ++ Deny:u8 ++ pad[2] ++ ReqId:u32le ++ pad[8]
//! ```
//!
//! `register` is a *request*: the driver allocates the ring from non-paged pool,
//! maps it into this process, and returns the mapped address in the
//! `FilterSendMessage` **output buffer**. The service never sends an address down —
//! which is why these records still fit in 16 bytes and no variable-length record
//! kind was needed.
//!
//! `verdict` answers a ring record flagged `FRAME_REPLY_EXPECTED`, matched by
//! `ReqId` (see `sensor::req_id`). It is the one part of the enforcement path that
//! is still a syscall, and deliberately so: it is rare, and it lands directly in the
//! driver's message callback which can wake the blocked thread with no extra hop.
//!
//! Identity note: `PidStartMs` is the process creation time in the **same engine
//! milliseconds** the telemetry uses (FILETIME / 10_000). The driver matches an
//! arm by `pid` plus its own creation FILETIME truncated to ms — strong enough
//! that a reused pid never inherits a stale arm (collision only if the same pid
//! is recreated within the same millisecond).

use edr_engine::{ArmCmd, NodeKey, Op};

pub const C_ARM: u8 = 1;
pub const C_DISARM: u8 = 2;
/// The service registers its own pid so the driver can exempt it from
/// enforcement (a self-triggered sync-enforce would deadlock — see spec).
pub const C_SET_SELF: u8 = 3;
/// Ask the driver to allocate + map the telemetry ring. Replies with the mapped
/// user address in the output buffer. See the module docs.
pub const C_REGISTER_RING: u8 = 4;
/// Answer one `FRAME_REPLY_EXPECTED` ring record, matched by `ReqId`.
pub const C_VERDICT: u8 = 5;
/// Push a compiled DAG ruleset down to the in-kernel engine (variable length,
/// not a 16-byte record — see [`encode_set_rules`]).
pub const C_SET_RULES: u8 = 6;
pub const CONTROL_RECORD: usize = 16;

/// Stable op codes for the enforceable subset (must match the driver).
pub fn op_code(op: Op) -> u8 {
    match op {
        Op::Exec => 1,
        Op::Read => 2,
        Op::Write => 3,
        Op::Inject => 4,
        Op::Open => 5,
        Op::Connect => 6,
        Op::Create => 7,
        Op::Delete => 8,
        Op::Load => 9,
        Op::Dup => 10,
    }
}

pub fn op_from_code(c: u8) -> Option<Op> {
    Some(match c {
        1 => Op::Exec,
        2 => Op::Read,
        3 => Op::Write,
        4 => Op::Inject,
        5 => Op::Open,
        6 => Op::Connect,
        7 => Op::Create,
        8 => Op::Delete,
        9 => Op::Load,
        10 => Op::Dup,
        _ => return None,
    })
}

/// Serialize one arm command. Returns `None` for a non-process identity (only
/// process `(pid, start)` is enforceable in the kernel).
pub fn encode(cmd: &ArmCmd) -> Option<Vec<u8>> {
    let (kind, op_c, actor) = match cmd {
        ArmCmd::Arm { actor, op } => (C_ARM, op_code(*op), actor),
        ArmCmd::Disarm { actor } => (C_DISARM, 0u8, actor),
    };
    let (pid, start_ms) = match actor {
        NodeKey::Process { pid, start_ts } => (*pid, *start_ts),
        _ => return None,
    };
    let mut v = Vec::with_capacity(CONTROL_RECORD);
    v.push(kind);
    v.push(op_c);
    v.extend_from_slice(&[0u8, 0u8]);
    v.extend_from_slice(&pid.to_le_bytes());
    v.extend_from_slice(&start_ms.to_le_bytes());
    Some(v)
}

/// Decode a control record (used by tests and to document the exact layout).
pub fn decode(rec: &[u8]) -> Result<ArmCmd, String> {
    if rec.len() < CONTROL_RECORD {
        return Err(format!("control record too short: {} bytes", rec.len()));
    }
    let kind = rec[0];
    let pid = u32::from_le_bytes(rec[4..8].try_into().unwrap());
    let start_ms = u64::from_le_bytes(rec[8..16].try_into().unwrap());
    let actor = NodeKey::Process { pid, start_ts: start_ms };
    match kind {
        C_ARM => {
            let op = op_from_code(rec[1]).ok_or_else(|| format!("bad op code {}", rec[1]))?;
            Ok(ArmCmd::Arm { actor, op })
        }
        C_DISARM => Ok(ArmCmd::Disarm { actor }),
        other => Err(format!("unknown control kind {}", other)),
    }
}

/// Concatenate encoded commands into one control frame to send to the driver.
/// Non-process arms are skipped (they can't be enforced in the kernel).
pub fn encode_frame(cmds: &[ArmCmd]) -> Vec<u8> {
    let mut out = Vec::new();
    for c in cmds {
        if let Some(bytes) = encode(c) {
            out.extend_from_slice(&bytes);
        }
    }
    out
}

/// Encode a `SetSelf` record so the driver learns (and exempts) the service pid.
pub fn encode_set_self(pid: u32) -> Vec<u8> {
    let mut v = Vec::with_capacity(CONTROL_RECORD);
    v.push(C_SET_SELF);
    v.push(0);
    v.extend_from_slice(&[0u8, 0u8]);
    v.extend_from_slice(&pid.to_le_bytes());
    v.extend_from_slice(&0u64.to_le_bytes());
    v
}

/// Ask the driver for a ring of `ring_bytes` and give it `doorbell` to signal when
/// it publishes to a sleeping consumer. `ring_bytes` is the data region and must be
/// a power of two; the driver rejects anything outside its accepted range.
pub fn encode_register_ring(ring_bytes: u32, doorbell: u64) -> Vec<u8> {
    let mut v = Vec::with_capacity(CONTROL_RECORD);
    v.push(C_REGISTER_RING);
    v.extend_from_slice(&[0u8; 3]);
    v.extend_from_slice(&ring_bytes.to_le_bytes());
    v.extend_from_slice(&doorbell.to_le_bytes());
    v
}

/// Push a compiled DAG ruleset (engine_core wire format `ERD1`) to the in-kernel
/// engine. Variable-length frame, distinct from the 16-byte record frames:
/// `{ C_SET_RULES:u8@0, pad[3], WireLen:u32@4, wire bytes @8.. }`. Matches the
/// driver's `MiniFilter::Port::ControlMessageNotify` `C_SET_RULES` branch.
pub fn encode_set_rules(wire: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(8 + wire.len());
    v.push(C_SET_RULES);
    v.extend_from_slice(&[0u8; 3]);
    v.extend_from_slice(&(wire.len() as u32).to_le_bytes());
    v.extend_from_slice(wire);
    v
}

/// Answer the enforce request `req_id`. `deny` = block the operation.
pub fn encode_verdict(req_id: u32, deny: bool) -> Vec<u8> {
    let mut v = Vec::with_capacity(CONTROL_RECORD);
    v.push(C_VERDICT);
    v.push(if deny { 1 } else { 0 });
    v.extend_from_slice(&[0u8; 2]);
    v.extend_from_slice(&req_id.to_le_bytes());
    v.extend_from_slice(&0u64.to_le_bytes());
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The driver parses this channel with a flat `len % 16 == 0` loop and reads
    /// every field at a fixed offset, so a record that is not exactly 16 bytes is a
    /// silent stream desync, not a decode error.
    #[test]
    fn every_record_kind_is_exactly_one_16_byte_record() {
        assert_eq!(encode_register_ring(1 << 20, 0x1234).len(), CONTROL_RECORD);
        assert_eq!(encode_verdict(7, true).len(), CONTROL_RECORD);
        assert_eq!(encode_set_self(1).len(), CONTROL_RECORD);
        assert_eq!(
            encode(&ArmCmd::Disarm { actor: NodeKey::Process { pid: 1, start_ts: 2 } })
                .unwrap()
                .len(),
            CONTROL_RECORD
        );
    }

    #[test]
    fn register_ring_record_is_well_formed() {
        let rec = encode_register_ring(4 * 1024 * 1024, 0xdead_beef_0000_1234);
        assert_eq!(rec[0], C_REGISTER_RING);
        assert_eq!(u32::from_le_bytes(rec[4..8].try_into().unwrap()), 4 * 1024 * 1024);
        assert_eq!(u64::from_le_bytes(rec[8..16].try_into().unwrap()), 0xdead_beef_0000_1234);
    }

    #[test]
    fn verdict_record_carries_req_id_and_decision() {
        let deny = encode_verdict(0x0102_0304, true);
        assert_eq!(deny[0], C_VERDICT);
        assert_eq!(deny[1], 1);
        assert_eq!(u32::from_le_bytes(deny[4..8].try_into().unwrap()), 0x0102_0304);

        let allow = encode_verdict(9, false);
        assert_eq!(allow[1], 0, "allow must be a distinct byte value, not just 'not 1'");
    }

    /// Kinds are a wire contract with `MiniFilter.cpp`'s switch; renumbering one
    /// silently reroutes commands to the wrong handler.
    #[test]
    fn record_kinds_are_stable_and_distinct() {
        let kinds = [C_ARM, C_DISARM, C_SET_SELF, C_REGISTER_RING, C_VERDICT];
        assert_eq!(kinds, [1, 2, 3, 4, 5]);
        let mut sorted = kinds.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), kinds.len());
    }

    #[test]
    fn arm_roundtrips() {
        let cmd = ArmCmd::Arm { actor: NodeKey::Process { pid: 800, start_ts: 2000 }, op: Op::Read };
        let bytes = encode(&cmd).expect("process arm encodes");
        assert_eq!(bytes.len(), CONTROL_RECORD);
        assert_eq!(decode(&bytes).unwrap(), cmd);
    }

    #[test]
    fn disarm_roundtrips() {
        let cmd = ArmCmd::Disarm { actor: NodeKey::Process { pid: 800, start_ts: 2000 } };
        let bytes = encode(&cmd).expect("process disarm encodes");
        assert_eq!(decode(&bytes).unwrap(), cmd);
    }

    #[test]
    fn non_process_identity_is_not_enforceable() {
        let cmd = ArmCmd::Arm { actor: NodeKey::File { file_id: "X".into() }, op: Op::Write };
        assert!(encode(&cmd).is_none(), "only process identities are enforceable in kernel");
        assert!(encode_frame(&[cmd]).is_empty());
    }

    #[test]
    fn set_self_record_is_well_formed() {
        let rec = encode_set_self(4242);
        assert_eq!(rec.len(), CONTROL_RECORD);
        assert_eq!(rec[0], C_SET_SELF);
        assert_eq!(u32::from_le_bytes(rec[4..8].try_into().unwrap()), 4242);
    }

    #[test]
    fn frame_packs_multiple_records() {
        let cmds = vec![
            ArmCmd::Arm { actor: NodeKey::Process { pid: 1, start_ts: 10 }, op: Op::Exec },
            ArmCmd::Disarm { actor: NodeKey::Process { pid: 1, start_ts: 10 } },
        ];
        let frame = encode_frame(&cmds);
        assert_eq!(frame.len(), 2 * CONTROL_RECORD);
        assert_eq!(decode(&frame[0..CONTROL_RECORD]).unwrap(), cmds[0]);
        assert_eq!(decode(&frame[CONTROL_RECORD..]).unwrap(), cmds[1]);
    }
}
