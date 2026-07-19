//! Regression: verdict của từng event trong docs/replay.md phải khớp kỳ vọng.

#[test]
fn ransomware_fast_encrypt_linear_scenario() {
    for o in engine_replay::run() {
        assert_eq!(
            o.actual, o.case.expect,
            "ts={} — {}",
            o.case.event.ts, o.case.desc,
        );
    }
}
