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

#[cfg(test)]
mod tests {
    use super::*;

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
