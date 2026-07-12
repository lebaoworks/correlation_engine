//! Contract tests for the hand-written protobuf codec (wire.proto).

use edr_engine::wire::{BlockReport, Wire, WireEvent};
use edr_engine::{Event, NodeKey, Op};
use edr_proto::{decode_frame, encode_frame};
use std::collections::HashMap;

/// The bare protobuf payload of a record (frame with its 4-byte length prefix stripped).
fn payload_of(w: &Wire) -> Vec<u8> {
    encode_frame(w)[4..].to_vec()
}

/// Wrap a raw payload in the TCP frame (`Len:u32le ++ payload`) so it can go
/// through the public `decode_frame`. Used to feed hand-forged payloads.
fn frame(payload: &[u8]) -> Vec<u8> {
    let mut v = (payload.len() as u32).to_le_bytes().to_vec();
    v.extend_from_slice(payload);
    v
}

/// Decode a raw payload through the public frame API.
fn decode_payload(payload: &[u8]) -> Result<Wire, String> {
    Ok(decode_frame(&frame(payload))?.expect("a complete frame").0)
}

fn sample_event() -> Event {
    let mut attrs = HashMap::new();
    attrs.insert("image".to_string(), r"C:\Tools\mimikatz.exe".to_string());
    attrs.insert("cmd".to_string(), "sekurlsa::logonpasswords".to_string());
    Event {
        ts: 21_000_000,
        op: Op::Read,
        actor: NodeKey::Process { pid: 800, start_ts: 20_000_000 },
        object: NodeKey::Process { pid: 50, start_ts: 9_000_000 },
        attrs,
    }
}

fn assert_event_eq(a: &Event, b: &Event) {
    assert_eq!(a.ts, b.ts);
    assert_eq!(a.op, b.op);
    assert_eq!(a.actor, b.actor);
    assert_eq!(a.object, b.object);
    assert_eq!(a.attrs, b.attrs);
}

/// Byte-exact check against the protobuf wire format, computed by hand from
/// wire.proto: Wire{event: WireEvent{seq:7, ttps:["T1003"], event: Event{ts:1,
/// op:OP_EXEC, actor:Process{pid:2,start_ts:3}, object:File{file_id:"f"}}}}.
#[test]
fn golden_bytes_match_protobuf_wire_format() {
    let w = Wire::Event(WireEvent {
        seq: 7,
        endpoint_sid: 0,
        ttps: vec!["T1003".to_string()],
        event: Event {
            ts: 1,
            op: Op::Exec,
            actor: NodeKey::Process { pid: 2, start_ts: 3 },
            object: NodeKey::File { file_id: "f".to_string() },
            attrs: HashMap::new(),
        },
    });
    #[rustfmt::skip]
    let expected: Vec<u8> = vec![
        0x0a, 0x1e,                                     // Wire.event (field 1, len 30)
          0x08, 0x07,                                   //   WireEvent.seq = 7
          0x1a, 0x05, b'T', b'1', b'0', b'0', b'3',     //   WireEvent.ttps[0] = "T1003"
          0x22, 0x13,                                   //   WireEvent.event (field 4, len 19)
            0x08, 0x01,                                 //     Event.ts = 1
            0x10, 0x01,                                 //     Event.op = OP_EXEC
            0x1a, 0x06,                                 //     Event.actor (field 3, len 6)
              0x0a, 0x04,                               //       NodeKey.process (field 1, len 4)
                0x08, 0x02,                             //         ProcessKey.pid = 2
                0x10, 0x03,                             //         ProcessKey.start_ts = 3
            0x22, 0x05,                                 //     Event.object (field 4, len 5)
              0x12, 0x03,                               //       NodeKey.file (field 2, len 3)
                0x0a, 0x01, b'f',                       //         FileKey.file_id = "f"
    ];
    // The frame is the 4-byte little-endian payload length followed by exactly
    // these bytes — so checking the frame also pins the bare protobuf payload.
    let mut framed = vec![0x20, 0x00, 0x00, 0x00];
    framed.extend_from_slice(&expected);
    assert_eq!(encode_frame(&w), framed);
    assert_eq!(payload_of(&w), expected);
}

#[test]
fn roundtrip_event() {
    let w = Wire::Event(WireEvent {
        seq: 7,
        endpoint_sid: 3,
        ttps: vec!["T1003".to_string(), "T1055".to_string()],
        event: sample_event(),
    });
    let bytes = encode_frame(&w);
    let (got, used) = decode_frame(&bytes).unwrap().unwrap();
    assert_eq!(used, bytes.len());
    match got {
        Wire::Event(we) => {
            assert_eq!(we.seq, 7);
            assert_eq!(we.endpoint_sid, 3);
            assert_eq!(we.ttps, vec!["T1003", "T1055"]);
            assert_event_eq(&we.event, &sample_event());
        }
        _ => panic!("expected Event"),
    }
}

#[test]
fn roundtrip_block() {
    let w = Wire::Block(BlockReport {
        seq: 8,
        pattern: "lsass_credential_dump".to_string(),
        score: 7.4,
        reason: "chokepoint lsass_read".to_string(),
        event: sample_event(),
    });
    let (got, _) = decode_frame(&encode_frame(&w)).unwrap().unwrap();
    match got {
        Wire::Block(br) => {
            assert_eq!(br.seq, 8);
            assert_eq!(br.pattern, "lsass_credential_dump");
            assert_eq!(br.score, 7.4);
            assert_eq!(br.reason, "chokepoint lsass_read");
            assert_event_eq(&br.event, &sample_event());
        }
        _ => panic!("expected Block"),
    }
}

#[test]
fn roundtrip_all_key_kinds_and_defaults() {
    // Other/Socket keys + default-heavy values (ts=0, empty attrs, sid=0).
    let ev = Event {
        ts: 0,
        op: Op::Connect,
        actor: NodeKey::Other { kind: "user".to_string(), key: "S-1-5-21".to_string() },
        object: NodeKey::Socket { key: "10.0.0.5:443".to_string() },
        attrs: HashMap::new(),
    };
    let w = Wire::Event(WireEvent { seq: 0, endpoint_sid: 0, ttps: vec![], event: ev.clone() });
    let (got, _) = decode_frame(&encode_frame(&w)).unwrap().unwrap();
    match got {
        Wire::Event(we) => {
            assert_eq!(we.seq, 0);
            assert_eq!(we.endpoint_sid, 0);
            assert!(we.ttps.is_empty());
            assert_event_eq(&we.event, &ev);
        }
        _ => panic!("expected Event"),
    }
}

#[test]
fn partial_frame_needs_more_bytes() {
    let bytes = encode_frame(&Wire::Event(WireEvent {
        seq: 1,
        endpoint_sid: 0,
        ttps: vec![],
        event: sample_event(),
    }));
    for cut in 0..bytes.len() {
        assert!(decode_frame(&bytes[..cut]).unwrap().is_none(), "cut at {}", cut);
    }
}

#[test]
fn two_frames_in_one_buffer() {
    let a = encode_frame(&Wire::Event(WireEvent {
        seq: 1,
        endpoint_sid: 0,
        ttps: vec![],
        event: sample_event(),
    }));
    let b = encode_frame(&Wire::Block(BlockReport {
        seq: 2,
        pattern: "p".to_string(),
        score: 1.0,
        reason: "r".to_string(),
        event: sample_event(),
    }));
    let mut buf = a.clone();
    buf.extend_from_slice(&b);
    let (w1, used1) = decode_frame(&buf).unwrap().unwrap();
    assert!(matches!(w1, Wire::Event(_)));
    assert_eq!(used1, a.len());
    let (w2, used2) = decode_frame(&buf[used1..]).unwrap().unwrap();
    assert!(matches!(w2, Wire::Block(_)));
    assert_eq!(used1 + used2, buf.len());
}

#[test]
fn unknown_fields_are_skipped() {
    // Forward compatibility: a newer producer adds Wire field 3 (varint) — an old
    // decoder must ignore it and still find the oneof.
    let mut payload = payload_of(&Wire::Event(WireEvent {
        seq: 1,
        endpoint_sid: 0,
        ttps: vec![],
        event: sample_event(),
    }));
    payload.extend_from_slice(&[0x18, 0x05]); // field 3, wire type varint, value 5
    let got = decode_payload(&payload).unwrap();
    assert!(matches!(got, Wire::Event(_)));
}

#[test]
fn malformed_payloads_are_errors() {
    // Empty Wire: no oneof member.
    assert!(decode_payload(&[]).is_err());
    // OP_UNSPECIFIED (0 is never encoded, so a forged explicit 11 must be refused):
    // Wire.event { WireEvent.event { op = 11, actor, object } } is easiest to forge
    // by mutating the golden encoding's op byte.
    let mut payload = payload_of(&Wire::Event(WireEvent {
        seq: 7,
        endpoint_sid: 0,
        ttps: vec!["T1003".to_string()],
        event: Event {
            ts: 1,
            op: Op::Exec,
            actor: NodeKey::Process { pid: 2, start_ts: 3 },
            object: NodeKey::File { file_id: "f".to_string() },
            attrs: HashMap::new(),
        },
    }));
    // In the golden layout the op value byte follows the 0x10 key inside Event.
    let pos = payload.windows(2).position(|w| w == [0x10, 0x01]).unwrap() + 1;
    payload[pos] = 11;
    assert!(decode_payload(&payload).is_err());
    // Truncated frame length that lies about its size decodes as incomplete.
    assert!(decode_frame(&[0xff, 0x00, 0x00, 0x00, 0x01]).unwrap().is_none());
}
