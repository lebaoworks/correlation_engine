//! Behavioral tests for the detection core, driven by the shipped datasets.

use edr_engine::{dataset, Decision, Engine, VerdictKind};

type Row = (Decision, VerdictKind, String);

fn run(path: &str) -> (Vec<Row>, Vec<String>) {
    let text = std::fs::read_to_string(path).expect("dataset readable");
    let events = dataset::parse_str(&text).expect("dataset parses");
    let mut eng = Engine::new();
    let mut out = Vec::new();
    for e in &events {
        let (d, v) = eng.on_event(e);
        out.push((d, v.kind, v.pattern));
    }
    (out, eng.log)
}

fn any_deny(rows: &[Row]) -> bool {
    rows.iter().any(|(d, _, _)| *d == Decision::Deny)
}
fn max_kind(rows: &[Row]) -> VerdictKind {
    rows.iter().map(|(_, k, _)| *k).max().unwrap_or(VerdictKind::None)
}

#[test]
fn ransomware_is_blocked_at_first_encrypting_write() {
    let (rows, log) = run("datasets/ransomware.evt");
    assert!(any_deny(&rows), "ransomware chain must produce a DENY");
    // The DENY must land on a write op (the encrypting chokepoint), not earlier.
    let first_deny = rows.iter().position(|(d, _, _)| *d == Decision::Deny).unwrap();
    // events 0..3 are exec/open/exec (no deny); first deny is the first write (index 4).
    assert_eq!(first_deny, 4, "deny should fire on the first encrypting write");
    assert!(log.iter().any(|l| l.contains("ARM")), "kernel should be armed before encryption");
}

#[test]
fn ransomware_detected_even_when_middle_group_reordered() {
    let (rows, _) = run("datasets/ransomware_reordered.evt");
    assert!(any_deny(&rows), "reordered free-order middle group must still DENY");
}

#[test]
fn installer_write_then_exec_same_file_is_not_blocked() {
    let (rows, _) = run("datasets/benign_installer_write_exec_same.evt");
    assert!(!any_deny(&rows), "a benign installer must never be DENIED");
    // The dropper pattern legitimately matches, but only to SUSPECT level.
    assert!(max_kind(&rows) <= VerdictKind::Suspect,
        "installer should not reach ALERT/BLOCK, got {:?}", max_kind(&rows));
}

#[test]
fn write_x_exec_y_does_not_false_positive() {
    // Directly answers the user's question: dropping X then running a DIFFERENT
    // file Y must NOT match the write->exec dropper pattern.
    let (rows, _) = run("datasets/benign_write_exec_different.evt");
    assert!(!any_deny(&rows), "write X / exec Y must not DENY");
    assert!(
        rows.iter().all(|(_, _, p)| p != "dropper_write_then_exec"),
        "dropper pattern must not emit a verdict when the exec'd file differs"
    );
}
