//! Ingestor tests: a chunked wire stream must rebuild the same graph + chain the
//! in-process backend would.

use edr_backend_service::{Ingestor, Output};
use edr_engine::wire::{BlockReport, Wire, WireEvent};
use edr_engine::{Event, NodeKey, Op};
use edr_proto::encode_frame;
use std::collections::HashMap;

fn proc(pid: u32, start_ts: u64) -> NodeKey {
    NodeKey::Process { pid, start_ts }
}

fn ev(ts: u64, op: Op, actor: NodeKey, object: NodeKey, attrs: &[(&str, &str)]) -> Event {
    Event {
        ts,
        op,
        actor,
        object,
        attrs: attrs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
    }
}

/// The demo scenario as raw wire bytes: exec mimikatz (causal) → mimikatz reads
/// lsass (tagged T1003) → BlockReport on that read.
fn lsass_stream() -> Vec<u8> {
    let exec = ev(
        2000,
        Op::Exec,
        proc(100, 5),
        proc(800, 2000),
        &[("image", r"C:\Tools\mimikatz.exe")],
    );
    let read = ev(2100, Op::Read, proc(800, 2000), proc(50, 900), &[("vm_read", "1")]);
    let mut out = Vec::new();
    out.extend(encode_frame(&Wire::Event(WireEvent {
        seq: 1,
        endpoint_sid: 0,
        ttps: vec![],
        event: exec,
    })));
    out.extend(encode_frame(&Wire::Event(WireEvent {
        seq: 2,
        endpoint_sid: 0,
        ttps: vec!["T1003".to_string()],
        event: read.clone(),
    })));
    out.extend(encode_frame(&Wire::Block(BlockReport {
        seq: 3,
        pattern: "lsass_credential_dump".to_string(),
        score: 7.4,
        reason: "chokepoint lsass_read".to_string(),
        event: read,
    })));
    out
}

#[test]
fn whole_stream_rebuilds_chain() {
    let mut ing = Ingestor::new();
    let outs = ing.push_bytes(&lsass_stream()).unwrap();
    assert_eq!(ing.events, 2);
    assert_eq!(ing.alerts, 1);
    assert_eq!(ing.pending_bytes(), 0);

    let alert = outs
        .iter()
        .find_map(|o| match o {
            Output::Alert { header, chain } => Some((header, chain)),
            _ => None,
        })
        .expect("an alert output");
    assert!(alert.0.contains("lsass_credential_dump"));
    assert!(alert.1.contains("*** BLOCKED ***"));
    assert!(alert.1.contains("mimikatz.exe"));

    let chain = &ing.backend.chains[0];
    assert_eq!(chain.pattern, "lsass_credential_dump");
    // exec + read(+blocked read edge from the report) all belong to the storyline
    assert!(chain.steps.iter().any(|s| s.op == Op::Exec));
    assert!(chain.steps.iter().any(|s| s.op == Op::Read && s.blocked));
}

#[test]
fn byte_by_byte_chunking_is_equivalent() {
    let stream = lsass_stream();
    let mut ing = Ingestor::new();
    let mut alerts = 0;
    for b in &stream {
        for o in ing.push_bytes(std::slice::from_ref(b)).unwrap() {
            if matches!(o, Output::Alert { .. }) {
                alerts += 1;
            }
        }
    }
    assert_eq!(ing.events, 2);
    assert_eq!(alerts, 1);
    assert_eq!(ing.pending_bytes(), 0);
    assert_eq!(ing.backend.chains.len(), 1);
}

#[test]
fn alert_without_history_still_reports() {
    // A BlockReport whose actor was never shipped: no chain, but no crash either.
    let read = ev(10, Op::Read, proc(1, 1), proc(2, 2), &[]);
    let bytes = encode_frame(&Wire::Block(BlockReport {
        seq: 1,
        pattern: "p".to_string(),
        score: 1.0,
        reason: "r".to_string(),
        event: read,
    }));
    let mut ing = Ingestor::new();
    let outs = ing.push_bytes(&bytes).unwrap();
    assert_eq!(ing.alerts, 1);
    match &outs[0] {
        Output::Alert { chain, .. } => assert!(chain.contains("không truy vết được")),
        _ => panic!("expected alert"),
    }
}
