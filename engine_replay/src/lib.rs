//! `engine_replay` — regression test cho engine: replay dataset event
//! (docs/replay.md) qua `engine_core` với rule do `engine_rules` compile,
//! so verdict thực tế với verdict kỳ vọng.
//!
//! TTP của mỗi event nằm sẵn trong dataset: tagger là lớp platform-specific
//! (engine.md §6.0), ngoài phạm vi core — replay giả lập đầu ra của nó.

use engine_core::{Engine, Event, Key, Kind, Op, Ttp, Verdict};

pub const RULES: &str = include_str!("../rules/ransomware.rules");

/// Một event trong dataset kèm TTP đã tag và verdict kỳ vọng.
pub struct Case {
    pub desc: &'static str,
    pub event: Event,
    pub ttps: Vec<Ttp>,
    pub expect: Verdict,
}

/// Kết quả replay một case.
pub struct Outcome {
    pub case: Case,
    pub actual: Verdict,
}

// Định danh giả lập: 128 bit = (loại << 96) | id — thay cho (pid,start_ts)/FileId thật.
fn proc_key(pid: u128) -> (Key, Kind) {
    (Key((1u128 << 96) | pid), Kind::Process)
}

fn file_key(id: u128) -> (Key, Kind) {
    (Key((2u128 << 96) | id), Kind::File)
}

fn case(
    desc: &'static str,
    ts: u64,
    op: Op,
    actor: (Key, Kind),
    object: (Key, Kind),
    ttps: &[u32],
    expect: Verdict,
) -> Case {
    Case {
        desc,
        event: Event {
            ts,
            op,
            actor: actor.0,
            actor_kind: actor.1,
            object: object.0,
            object_kind: object.1,
        },
        ttps: ttps.iter().copied().map(Ttp).collect(),
        expect,
    }
}

/// Lịch sử 8 event của docs/replay.md, đúng thứ tự timestamp.
pub fn dataset() -> Vec<Case> {
    let explorer = proc_key(1);
    let powershell = proc_key(200);
    let svchost = proc_key(50);
    let conhost = proc_key(80);
    let vssadmin = proc_key(300);
    let notepad = proc_key(90);
    let documents_dir = file_key(1);
    let readme = file_key(2);
    let doc1 = file_key(3);
    let doc2 = file_key(4);

    vec![
        case(
            "explorer.exe chạy powershell.exe (ẩn cửa sổ, lệnh base64) — seed bước 0",
            1000, Op::Exec, explorer, powershell, &[1059], Verdict::Inspect,
        ),
        case(
            "powershell.exe liệt kê thư mục Documents — tiến bước 1",
            1500, Op::Read, powershell, documents_dir, &[1083], Verdict::Inspect,
        ),
        case(
            "svchost.exe chạy conhost.exe — lành tính, storyline khác",
            1650, Op::Exec, svchost, conhost, &[], Verdict::Ignore,
        ),
        case(
            "powershell.exe chạy vssadmin.exe xoá Shadow Copy — tiến bước 2",
            2000, Op::Exec, powershell, vssadmin, &[1490], Verdict::Inspect,
        ),
        case(
            "conhost.exe đọc readme.txt — lành tính",
            2200, Op::Read, conhost, readme, &[], Verdict::Ignore,
        ),
        case(
            "powershell.exe ghi DOC1 entropy 0.96 — bước 3: disarm",
            2500, Op::Write, powershell, doc1, &[1486], Verdict::Disarm,
        ),
        case(
            "powershell.exe ghi DOC2 — write đã bị tước quyền → chặn thẳng",
            2600, Op::Write, powershell, doc2, &[1486], Verdict::Block,
        ),
        case(
            "svchost.exe chạy notepad.exe — lành tính",
            2750, Op::Exec, svchost, notepad, &[], Verdict::Ignore,
        ),
    ]
}

/// Compile rule (đi vòng qua wire format để phủ luôn đường giao rule cho
/// kernel), replay toàn bộ dataset, trả kết quả từng event.
pub fn run() -> Vec<Outcome> {
    let bytes = engine_rules::compile_to_bytes(RULES).expect("rule nguồn phải hợp lệ");
    let rules = engine_core::wire::decode(&bytes).expect("wire roundtrip phải hợp lệ");
    let mut engine = Engine::new(rules);
    dataset()
        .into_iter()
        .map(|case| {
            let actual = engine.on_event(&case.event, &case.ttps);
            Outcome { case, actual }
        })
        .collect()
}
