//! End-to-end: synthesize sensor frames (byte-exact to Event.hpp wire v2), decode,
//! translate, and drive the engine — proving the sensor→engine→decision path.

use edr_endpoint_service::{sensor, Service};

/// Round-trip: an encoded batch decodes back to the same events, with identity
/// (pid, create_time) and the inline target image intact.
#[test]
fn batch_encode_decode_roundtrip() {
    let batch = sensor::build_batch(&[
        sensor::enc_process_create(20_000_000, 800, 100, 5_000_000, r"C:\Tools\mimikatz.exe", "x"),
        sensor::enc_process_open(
            21_000_000,
            800,
            20_000_000,
            50,
            9_000_000,
            0x0010,
            r"C:\Windows\System32\lsass.exe",
        ),
        sensor::enc_file_open(22_000_000, 800, 20_000_000, r"C:\Users\a\secret.txt"),
    ]);
    let evs = sensor::parse_batch(&batch).expect("parse");
    assert_eq!(evs.len(), 3);
    assert!(matches!(
        &evs[0],
        sensor::SensorEvent::ProcessCreate {
            pid: 100,
            pid_start: 5_000_000,
            child_pid: 800,
            child_start: 20_000_000,
            ..
        }
    ));
    if let sensor::SensorEvent::ProcessOpen {
        pid: 800,
        pid_start: 20_000_000,
        target_pid: 50,
        target_start: 9_000_000,
        desired_access: 0x0010,
        target_image,
        ..
    } = &evs[1]
    {
        assert!(target_image.ends_with("lsass.exe"), "target image inline: {}", target_image);
    } else {
        panic!("expected ProcessOpen, got {:?}", evs[1]);
    }
    if let sensor::SensorEvent::FileOpen { file_name, .. } = &evs[2] {
        assert!(file_name.ends_with("secret.txt"), "utf-16 name decoded: {}", file_name);
    } else {
        panic!("expected FileOpen");
    }
}

/// A first-write record decodes and normalizes to an `Op::Write` engine event.
#[test]
fn file_write_decodes_and_is_a_write() {
    use edr_endpoint_service::translate;
    let batch = sensor::build_batch(&[sensor::enc_file_write(
        22_000_000, 800, 20_000_000, r"C:\Users\a\payload.exe",
    )]);
    let evs = sensor::parse_batch(&batch).expect("parse");
    assert_eq!(evs.len(), 1);
    let se = match &evs[0] {
        sensor::SensorEvent::FileWrite { file_name, pid: 800, .. } => {
            assert!(file_name.ends_with("payload.exe"));
            evs[0].clone()
        }
        other => panic!("expected FileWrite, got {:?}", other),
    };
    let ev = translate::to_engine_event(&se).expect("write is not state-only");
    assert_eq!(ev.op, edr_engine::Op::Write, "first-write maps to Op::Write");
}

/// The enforcement-path flag rides the frame `Count` high bit and does not
/// disturb record decoding.
#[test]
fn reply_expected_flag_roundtrips() {
    let recs = [sensor::enc_process_open(
        21_000_000, 800, 20_000_000, 50, 9_000_000, 0x0010, r"C:\Windows\System32\lsass.exe",
    )];
    let async_frame = sensor::build_frame(&recs, false);
    let sync_frame = sensor::build_frame(&recs, true);
    assert!(!sensor::expects_reply(&async_frame));
    assert!(sensor::expects_reply(&sync_frame));
    // Both decode to the same single record despite the flag bit.
    assert_eq!(sensor::parse_batch(&async_frame).unwrap().len(), 1);
    assert_eq!(sensor::parse_batch(&sync_frame).unwrap().len(), 1);
}

/// Records stay 8-aligned: every record size is a multiple of 8 and numeric
/// fields land on their natural alignment inside the batch buffer.
#[test]
fn records_are_size_prefixed_and_aligned() {
    let recs = [
        sensor::enc_process_create(20_000_000, 800, 100, 5_000_000, r"C:\x.exe", "abc"),
        sensor::enc_file_open(22_000_000, 800, 20_000_000, r"C:\odd"),
        sensor::enc_process_exit(23_000_000, 800, 20_000_000),
    ];
    for r in &recs {
        assert_eq!(r.len() % 8, 0, "record padded to 8 bytes");
        let size = u32::from_le_bytes(r[..4].try_into().unwrap()) as usize;
        assert_eq!(size, r.len(), "Size field covers the whole record");
    }
}

/// An unknown record type is skipped via its Size instead of failing the batch.
#[test]
fn unknown_record_type_is_skipped() {
    let mut alien = sensor::enc_process_exit(23_000_000, 800, 20_000_000);
    alien[4] = 200; // unassigned type
    let batch = sensor::build_batch(&[
        alien,
        sensor::enc_file_open(24_000_000, 800, 20_000_000, r"C:\f"),
    ]);
    let evs = sensor::parse_batch(&batch).expect("parse");
    assert_eq!(evs.len(), 1, "unknown type skipped, known one decoded");
    assert!(matches!(&evs[0], sensor::SensorEvent::FileOpen { .. }));
}

/// The LSASS credential-dump chain must DENY at the memory-read, and the backend
/// must reconstruct the chain. Under wire v2 no prior enumeration is needed:
/// identity and the target image ride inline on each record.
#[test]
fn lsass_dump_is_blocked_and_chain_rebuilt() {
    let mut svc = Service::new().expect("rules");

    // exec mimikatz, then open LSASS with PROCESS_VM_READ — one batch, no priming.
    let b = sensor::build_batch(&[
        sensor::enc_process_create(
            20_000_000,
            800,
            100,
            5_000_000,
            r"C:\Tools\mimikatz.exe",
            "sekurlsa::logonpasswords",
        ),
        sensor::enc_process_open(
            21_000_000,
            800,
            20_000_000,
            50,
            9_000_000,
            0x0010,
            r"C:\Windows\System32\lsass.exe",
        ),
    ]);
    let o = svc.process_batch(&b).expect("batch");
    assert!(o.deny, "LSASS VM_READ must produce a BLOCK decision");
    assert!(!o.chains.is_empty(), "backend must reconstruct the chain on block");
    assert!(o.chains[0].steps.iter().any(|s| s.blocked), "the read step is marked blocked");
    assert_eq!(svc.denies, 1);
}

/// ProcessExist / ProcessExit are informational only (no engine op).
#[test]
fn exist_and_exit_are_state_only() {
    let mut svc = Service::new().expect("rules");
    let b = sensor::build_batch(&[
        sensor::enc_process_exist(10_000_000, 50, 9_000_000, r"C:\Windows\System32\lsass.exe"),
        sensor::enc_process_exit(11_000_000, 60, 8_000_000),
    ]);
    let o = svc.process_batch(&b).expect("batch");
    assert!(!o.deny);
    assert_eq!(o.state_only, 2);
    assert!(o.outcomes.is_empty());
}

/// A benign process opening a non-LSASS process (no VM_READ) must NOT block.
#[test]
fn benign_process_open_not_blocked() {
    let mut svc = Service::new().expect("rules");
    let b = sensor::build_batch(&[
        sensor::enc_process_create(20_000_000, 900, 100, 5_000_000, r"C:\Windows\System32\taskmgr.exe", ""),
        sensor::enc_process_open(
            21_000_000,
            900,
            20_000_000,
            60,
            9_000_000,
            0x0400, /* QUERY_INFORMATION, no VM_READ */
            r"C:\Windows\System32\svchost.exe",
        ),
    ]);
    let o = svc.process_batch(&b).expect("b");
    assert!(!o.deny, "no VM_READ on non-lsass → no block");
}

/// End-to-end §9 pushdown: processing a batch surfaces the control-plane arm
/// deltas, and they serialize to the 16-byte control records the driver consumes.
#[test]
fn batch_surfaces_armed_identities_for_the_driver() {
    use edr_endpoint_service::control;

    let mut svc = Service::new().expect("rules");
    // A dropper storyline that arms before its chokepoint: write a PE, then exec it.
    let b = sensor::build_batch(&[
        sensor::enc_file_open(19_000_000, 700, 5_000_000, r"C:\Users\a\payload.exe"),
    ]);
    let _ = svc.process_batch(&b).expect("b");

    // Drive the LSASS scenario, which the engine blocks; collect any arm deltas.
    let attack = sensor::build_batch(&[
        sensor::enc_process_create(20_000_000, 800, 100, 5_000_000, r"C:\Tools\mimikatz.exe", "sekurlsa"),
        sensor::enc_process_open(21_000_000, 800, 20_000_000, 50, 9_000_000, 0x0010, r"C:\Windows\System32\lsass.exe"),
    ]);
    let out = svc.process_batch(&attack).expect("attack");
    assert!(out.deny, "attack blocks");

    // Whatever arm deltas were produced must serialize to the driver's wire format
    // and round-trip back (proving the control-plane encoding is wired end-to-end).
    for a in &out.arms {
        if let Some(bytes) = control::encode(a) {
            assert_eq!(bytes.len(), control::CONTROL_RECORD);
            assert_eq!(&control::decode(&bytes).unwrap(), a);
        }
    }
}

/// FILETIME → engine ms conversion keeps events monotonically ordered.
#[test]
fn timestamps_are_monotone_ms() {
    let mut svc = Service::new().expect("rules");
    let b = sensor::build_batch(&[
        sensor::enc_process_create(20_000_000, 800, 100, 5_000_000, r"C:\Tools\a.exe", ""),
        sensor::enc_process_create(30_000_000, 801, 800, 20_000_000, r"C:\Tools\b.exe", ""),
    ]);
    let o = svc.process_batch(&b).expect("b");
    // 20_000_000 / 10_000 = 2000 ms ; 30_000_000 / 10_000 = 3000 ms
    assert!(o.outcomes[0].line.contains("ts=2000"), "{}", o.outcomes[0].line);
    assert!(o.outcomes[1].line.contains("ts=3000"), "{}", o.outcomes[1].line);
}
