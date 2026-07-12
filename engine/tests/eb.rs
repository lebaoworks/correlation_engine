//! Behavioral tests for the endpoint–backend split core.
//!
//! Reuses the base crate's shipped datasets (datasets). Checks that the
//! endpoint preserves the proven detection behavior AND that the backend rebuilds
//! the full chain on a block, plus the endpoint's working-set boundedness.

use edr_engine::dataset;
use edr_engine::{Chain, Decision, Pipeline, VerdictKind};

const DS: &str = "datasets";

fn run(path: &str) -> (Vec<(Decision, VerdictKind, String)>, Vec<Chain>, Pipeline) {
    let text = std::fs::read_to_string(path).expect("dataset readable");
    let events = dataset::parse_str(&text).expect("dataset parses");
    let mut pipe = Pipeline::new();
    let mut rows = Vec::new();
    let mut chains = Vec::new();
    for e in &events {
        let (d, v, c) = pipe.feed(e);
        rows.push((d, v.kind, v.pattern));
        if let Some(c) = c {
            chains.push(c);
        }
    }
    (rows, chains, pipe)
}

fn any_deny(rows: &[(Decision, VerdictKind, String)]) -> bool {
    rows.iter().any(|(d, _, _)| *d == Decision::Deny)
}
fn max_kind(rows: &[(Decision, VerdictKind, String)]) -> VerdictKind {
    rows.iter().map(|(_, k, _)| *k).max().unwrap_or(VerdictKind::None)
}

#[test]
fn ransomware_blocked_at_first_encrypting_write() {
    let (rows, chains, pipe) = run(&format!("{DS}/ransomware.evt"));
    assert!(any_deny(&rows), "ransomware chain must DENY");
    let first_deny = rows.iter().position(|(d, _, _)| *d == Decision::Deny).unwrap();
    assert_eq!(first_deny, 4, "deny must land on the first encrypting write (index 4)");
    assert!(pipe.endpoint.log.iter().any(|l| l.contains("ARM")), "kernel armed before encryption");
    // Backend reconstructed the chain and marked the blocked step.
    assert!(!chains.is_empty(), "backend must produce a chain on block");
    let first = &chains[0];
    assert!(first.steps.iter().any(|s| s.blocked), "the chain must mark a blocked step");
    // The full storyline is present: powershell, vssadmin and a document all appear.
    let labels = first.nodes.join(" ");
    assert!(labels.contains("powershell"), "chain shows the interpreter node");
    assert!(labels.contains("vssadmin"), "chain shows the recovery-inhibit node");
    assert!(labels.contains("file:DOC1"), "chain shows the encrypted document");
}

#[test]
fn ransomware_detected_when_middle_group_reordered() {
    let (rows, _, _) = run(&format!("{DS}/ransomware_reordered.evt"));
    assert!(any_deny(&rows), "reordered free-order middle group must still DENY");
}

#[test]
fn installer_write_then_exec_same_file_not_blocked() {
    let (rows, chains, _) = run(&format!("{DS}/benign_installer_write_exec_same.evt"));
    assert!(!any_deny(&rows), "a benign installer must never be DENIED");
    assert!(max_kind(&rows) <= VerdictKind::Suspect, "installer must stay <= SUSPECT, got {:?}", max_kind(&rows));
    assert!(chains.is_empty(), "no block → backend rebuilds no chain");
}

#[test]
fn write_x_exec_y_does_not_false_positive() {
    let (rows, _, _) = run(&format!("{DS}/benign_write_exec_different.evt"));
    assert!(!any_deny(&rows), "write X / exec Y must not DENY");
    assert!(
        rows.iter().all(|(_, _, p)| p != "dropper_write_then_exec"),
        "dropper pattern must not emit when the exec'd file differs (binding by identity)"
    );
}

#[test]
fn lsass_dump_blocked_at_read_with_chain() {
    // Single-event chokepoint pattern loaded purely from data.
    let text = std::fs::read_to_string(format!("{DS}/lsass_dump.evt")).unwrap();
    let events = dataset::parse_str(&text).unwrap();
    let mut pipe = Pipeline::from_rules_file("rules/lsass_dump.rules").expect("rules load");
    let mut denied = false;
    let mut chain = None;
    for e in &events {
        let (d, _, c) = pipe.feed(e);
        if d == Decision::Deny {
            denied = true;
        }
        if c.is_some() {
            chain = c;
        }
    }
    assert!(denied, "LSASS memory read must be DENIED");
    let c = chain.expect("backend rebuilds the LSASS chain");
    assert!(c.steps.iter().any(|s| s.blocked), "the LSASS read step is marked blocked");
}

#[test]
fn backend_receives_every_event_shipped() {
    // Ship-and-forget completeness: the backend's full graph sees all events, even
    // though the endpoint keeps no edges.
    let text = std::fs::read_to_string(format!("{DS}/ransomware.evt")).unwrap();
    let n = dataset::parse_str(&text).unwrap().len() as u64;
    let (_, _, pipe) = run(&format!("{DS}/ransomware.evt"));
    assert_eq!(pipe.endpoint.shipped_events, n, "endpoint ships every event");
    assert_eq!(pipe.backend.events_ingested, n, "backend ingests every shipped event");
    assert!(pipe.endpoint.shipped_blocks >= 1, "at least one block report shipped");
}

#[test]
fn working_set_sweeps_cold_unbound_entities() {
    // A touched-but-unbound file goes cold after window W and is swept from the
    // endpoint (backend still has it). Bound/active chain nodes are NOT swept.
    let ev = "\
ts=1000 op=exec  actor=100.1 object=proc:200.5 image=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe cmd=x\n\
ts=1100 op=open  actor=200.5 object=file:SCRATCH enum=0\n\
ts=999000 op=exec actor=200.5 object=proc:400.9 image=C:\\Windows\\System32\\notepad.exe cmd=y\n";
    let events = dataset::parse_str(ev).unwrap();
    let mut pipe = Pipeline::new();
    pipe.endpoint.set_window_ms(5_000); // small window so the late event triggers a sweep
    for e in &events {
        pipe.feed(e);
    }
    assert!(pipe.endpoint.swept >= 1, "the cold unbound scratch file must be swept, swept={}", pipe.endpoint.swept);
    // Working set stays small/bounded — it never accumulates the whole history.
    assert!(pipe.endpoint.active_len() <= 4, "ACTIVE must stay bounded, got {}", pipe.endpoint.active_len());
    // The backend, by contrast, keeps everything.
    assert_eq!(pipe.backend.events_ingested, 3);
}

/// Run a dataset, draining the control-plane arm stream after each event.
fn run_arms(path: &str) -> Vec<edr_engine::ArmCmd> {
    let text = std::fs::read_to_string(path).expect("dataset readable");
    let events = dataset::parse_str(&text).expect("dataset parses");
    let mut pipe = Pipeline::new();
    let mut cmds = Vec::new();
    for e in &events {
        pipe.feed(e);
        cmds.extend(pipe.endpoint.drain_arm_cmds());
    }
    cmds
}

/// §9 pushdown: the endpoint arms the *exact* `(actor, op)` about to hit the
/// chokepoint — so only that identity+op ever travels the synchronous path — and
/// disarms once the block fires. Only armed events pay enforcement latency.
#[test]
fn arm_stream_arms_the_chokepoint_then_disarms_on_block() {
    use edr_engine::{ArmCmd, NodeKey, Op};
    let cmds = run_arms(&format!("{DS}/ransomware.evt"));

    // Exactly one identity is armed, for the enforceable op, before it acts...
    let arm = cmds
        .iter()
        .find_map(|c| match c {
            ArmCmd::Arm { actor, op } => Some((actor.clone(), *op)),
            _ => None,
        })
        .expect("ransomware must arm a chokepoint");
    assert!(matches!(arm.0, NodeKey::Process { .. }), "arm is keyed by process identity");
    assert_eq!(arm.1, Op::Write, "the armed op is the encrypting-write chokepoint");

    // ...and the same identity is disarmed after the block fires (no stale arm
    // left in the pushed-down table).
    assert!(
        cmds.iter().any(|c| matches!(c, ArmCmd::Disarm { actor } if *actor == arm.0)),
        "the armed identity must be disarmed once the chokepoint is consumed"
    );

    // Net arm state is empty: every Arm is balanced by a later Disarm.
    let net: i32 = cmds
        .iter()
        .map(|c| match c {
            ArmCmd::Arm { .. } => 1,
            ArmCmd::Disarm { .. } => -1,
        })
        .sum();
    assert_eq!(net, 0, "arms must not leak: each Arm is balanced by a Disarm");
}

/// A benign installer never crosses theta_block, so nothing is ever armed — the
/// synchronous enforcement path stays completely idle.
#[test]
fn benign_run_emits_no_arms() {
    use edr_engine::ArmCmd;
    let cmds = run_arms(&format!("{DS}/benign_installer_write_exec_same.evt"));
    assert!(
        !cmds.iter().any(|c| matches!(c, ArmCmd::Arm { .. })),
        "benign activity must never arm the kernel, got {:?}",
        cmds
    );
}
