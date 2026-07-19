//! `engine_replay` — regression test cho engine: replay dataset event
//! (docs/replay.md) qua `engine_core`, so verdict thực tế với verdict kỳ vọng.
//!
//! Có hai dataset:
//! - [`linear_dataset`] — kịch bản 8 event ĐÚNG thứ tự, cho `base`/`v0_0_1`
//!   (rule tuyến tính).
//! - [`dag_dataset`] — kịch bản 8 event ĐẢO thứ tự (xoá Shadow Copy trước do
//!   thám), cho `v0_0_2` (rule DAG). Đây là chỗ automaton tuyến tính bỏ lọt.
//!
//! TTP của mỗi event nằm sẵn trong dataset: tagger là lớp platform-specific
//! (engine.md §6.0), ngoài phạm vi core — replay giả lập đầu ra của nó.

use engine_core::{DagRuleSet, Detector, Engine, Event, Key, Kind, Op, RuleSet, Ttp, Verdict};

/// Rule tuyến tính (base/v0.0.1).
pub const LINEAR_RULES: &str = include_str!("../rules/ransomware.rules");
/// Rule DAG (v0.0.2).
pub const DAG_RULES: &str = include_str!("../rules/ransomware_dag.rules");

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

/// Kịch bản 8 event ĐÚNG thứ tự (docs/replay.md — khối gốc), cho base/v0.0.1.
pub fn linear_dataset() -> Vec<Case> {
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
        case("explorer chạy powershell (T1059) — seed bước 0",
            1000, Op::Exec, explorer, powershell, &[1059], Verdict::Inspect),
        case("powershell liệt kê Documents (T1083) — bước 1",
            1500, Op::Read, powershell, documents_dir, &[1083], Verdict::Inspect),
        case("svchost chạy conhost — lành tính, storyline khác",
            1650, Op::Exec, svchost, conhost, &[], Verdict::Ignore),
        case("powershell chạy vssadmin xoá Shadow Copy (T1490) — bước 2",
            2000, Op::Exec, powershell, vssadmin, &[1490], Verdict::Inspect),
        case("conhost đọc readme.txt — lành tính",
            2200, Op::Read, conhost, readme, &[], Verdict::Ignore),
        case("powershell ghi DOC1 entropy 0.96 (T1486) — bước 3: disarm",
            2500, Op::Write, powershell, doc1, &[1486], Verdict::Disarm),
        case("powershell ghi DOC2 — write đã bị tước quyền → chặn thẳng",
            2600, Op::Write, powershell, doc2, &[1486], Verdict::Block),
        case("svchost chạy notepad — lành tính",
            2750, Op::Exec, svchost, notepad, &[], Verdict::Ignore),
    ]
}

/// Kịch bản 8 event ĐẢO thứ tự (docs/replay.md — khối v0.0.2), cho v0.0.2.
/// vssadmin (bit 2) chạy TRƯỚC bước do thám (bit 1) — mẫu tuyến tính kẹt ở đây.
pub fn dag_dataset() -> Vec<Case> {
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
        case("explorer chạy powershell (T1059) — seed bit 0",
            1000, Op::Exec, explorer, powershell, &[1059], Verdict::Inspect),
        case("svchost chạy conhost — lành tính, storyline khác",
            1500, Op::Exec, svchost, conhost, &[], Verdict::Ignore),
        case("powershell chạy vssadmin xoá Shadow Copy (T1490) — bit 2 TRƯỚC bit 1",
            2000, Op::Exec, powershell, vssadmin, &[1490], Verdict::Inspect),
        case("conhost đọc readme.txt — lành tính",
            2200, Op::Read, conhost, readme, &[], Verdict::Ignore),
        case("powershell liệt kê Documents (T1083) — bit 1; mốc bit 3 mở",
            2500, Op::Read, powershell, documents_dir, &[1083], Verdict::Inspect),
        case("powershell ghi DOC1 entropy 0.96 (T1486) — bit 3: disarm",
            2800, Op::Write, powershell, doc1, &[1486], Verdict::Disarm),
        case("powershell ghi DOC2 — write đã bị tước quyền → chặn thẳng",
            2900, Op::Write, powershell, doc2, &[1486], Verdict::Block),
        case("svchost chạy notepad — lành tính",
            3000, Op::Exec, svchost, notepad, &[], Verdict::Ignore),
    ]
}

/// Rule tuyến tính, đi vòng qua wire format (`ERL1`) để phủ đường giao kernel.
pub fn linear_rules() -> RuleSet {
    let bytes = engine_rules::compile_to_bytes(LINEAR_RULES).expect("rule tuyến tính hợp lệ");
    engine_core::wire::decode(&bytes).expect("wire roundtrip tuyến tính")
}

/// Rule DAG, đi vòng qua wire format (`ERD1`).
pub fn dag_rules() -> DagRuleSet {
    let bytes = engine_rules::compile_dag_to_bytes(DAG_RULES).expect("rule DAG hợp lệ");
    engine_core::wire::decode_dag(&bytes).expect("wire roundtrip DAG")
}

/// Replay một dataset qua một bản engine bất kỳ, trả kết quả từng event.
pub fn replay(engine: &mut dyn Detector, dataset: Vec<Case>) -> Vec<Outcome> {
    dataset
        .into_iter()
        .map(|case| {
            let actual = engine.on_event(&case.event, &case.ttps);
            Outcome { case, actual }
        })
        .collect()
}

/// Replay qua bản engine hiện hành (`engine_core::Engine` = v0.0.2) trên dataset DAG.
pub fn run() -> Vec<Outcome> {
    replay(&mut Engine::new(dag_rules()), dag_dataset())
}
