//! Regression cho các bản engine:
//! - base + v0.0.1 khớp verdict kỳ vọng trên dataset ĐÚNG thứ tự, và cho
//!   verdict giống hệt nhau trên luồng event bất kỳ (bỏ graph không đổi detection).
//! - v0.0.2 khớp verdict kỳ vọng trên dataset ĐẢO thứ tự.
//! - Điểm mấu chốt: trên luồng đảo thứ tự, v0.0.1 (tuyến tính) BỎ LỌT chuỗi
//!   mà v0.0.2 (DAG) bắt được.

use engine_core::{base, v0_0_1, Detector, Event, Key, Kind, Op, Ttp, Verdict};
use engine_replay::Case;

fn assert_scenario(engine: &mut dyn Detector, dataset: Vec<Case>, label: &str) {
    for o in engine_replay::replay(engine, dataset) {
        assert_eq!(
            o.actual, o.case.expect,
            "[{label}] ts={} — {}",
            o.case.event.ts, o.case.desc,
        );
    }
}

#[test]
fn linear_scenario_on_base() {
    assert_scenario(
        &mut base::Engine::new(engine_replay::linear_rules()),
        engine_replay::linear_dataset(),
        "base",
    );
}

#[test]
fn linear_scenario_on_v0_0_1() {
    assert_scenario(
        &mut v0_0_1::Engine::new(engine_replay::linear_rules()),
        engine_replay::linear_dataset(),
        "v0.0.1",
    );
}

#[test]
fn reordered_scenario_on_v0_0_2() {
    // engine_core::Engine = v0.0.2
    assert_scenario(
        &mut engine_core::Engine::new(engine_replay::dag_rules()),
        engine_replay::dag_dataset(),
        "v0.0.2",
    );
}

/// Kịch bản chính của bước này: cùng luồng event ĐẢO thứ tự, v0.0.1 tuyến tính
/// bỏ lọt (không disarm/block), v0.0.2 DAG bắt trọn (disarm rồi block).
#[test]
fn v0_0_1_misses_reordered_chain_that_v0_0_2_catches() {
    let events = engine_replay::dag_dataset();

    let mut v1 = v0_0_1::Engine::new(engine_replay::linear_rules());
    let v1_verdicts: Vec<Verdict> =
        events.iter().map(|c| v1.on_event(&c.event, &c.ttps)).collect();
    assert!(
        !v1_verdicts.iter().any(|v| matches!(v, Verdict::Disarm | Verdict::Block)),
        "v0.0.1 tuyến tính lẽ ra bỏ lọt chuỗi đảo thứ tự, nhưng phản ứng: {v1_verdicts:?}",
    );

    let mut v2 = engine_core::Engine::new(engine_replay::dag_rules());
    let v2_verdicts: Vec<Verdict> =
        events.iter().map(|c| v2.on_event(&c.event, &c.ttps)).collect();
    assert!(v2_verdicts.contains(&Verdict::Disarm), "v0.0.2 phải disarm: {v2_verdicts:?}");
    assert!(v2_verdicts.contains(&Verdict::Block), "v0.0.2 phải block: {v2_verdicts:?}");
}

/// Test vi sai base ↔ v0.0.1: cùng luồng event giả ngẫu nhiên (deterministic),
/// verdict và storyline phải trùng nhau từng event (bỏ graph không đổi detection).
#[test]
fn base_and_v0_0_1_verdicts_are_identical() {
    let src = "\
pattern fuzz_a
    step ops=exec ttps=T1059
    step ops=read ttps=T1083
    step ops=write ttps=T1486 action=disarm(write,exec)
end
pattern fuzz_b
    step ops=connect ttps=T1071
    step ttps=T1105 action=block
end
";
    let rules = engine_rules::compile(src).expect("rule fuzz hợp lệ");
    let mut base = base::Engine::new(rules.clone());
    let mut v001 = v0_0_1::Engine::new(rules);

    let mut seed: u64 = 0x243F_6A88_85A3_08D3;
    let mut next = move || {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        seed >> 33
    };

    const OPS: [Op; 8] = [
        Op::Exec, Op::Create, Op::Write, Op::Read,
        Op::Open, Op::Connect, Op::Inject, Op::Dup,
    ];
    const TTPS: [u32; 6] = [1059, 1083, 1486, 1071, 1105, 1490];

    for i in 0..5000u64 {
        let actor = Key((next() % 24) as u128);
        let object = Key((next() % 24) as u128);
        let op = OPS[(next() % OPS.len() as u64) as usize];
        let mut ttps = Vec::new();
        for _ in 0..(next() % 3) {
            let t = Ttp(TTPS[(next() % TTPS.len() as u64) as usize]);
            if !ttps.contains(&t) {
                ttps.push(t);
            }
        }
        let e = Event {
            ts: i,
            op,
            actor,
            actor_kind: Kind::Process,
            object,
            object_kind: Kind::File,
        };
        let vb = base.on_event(&e, &ttps);
        let vv = v001.on_event(&e, &ttps);
        assert_eq!(vb, vv, "lệch verdict tại event #{i}: {e:?} ttps={ttps:?}");
        let mb: Vec<Key> = base.storyline_of(actor).map(|it| it.collect()).unwrap_or_default();
        let mv: Vec<Key> = v001.storyline_of(actor).map(|it| it.collect()).unwrap_or_default();
        assert_eq!(mb, mv, "lệch storyline tại event #{i}");
    }
}

/// `run()` mặc định (v0.0.2 trên dataset DAG) — khớp verdict kỳ vọng từng event.
#[test]
fn default_run_matches_expected() {
    for o in engine_replay::run() {
        assert_eq!(
            o.actual, o.case.expect,
            "ts={} — {}",
            o.case.event.ts, o.case.desc,
        );
    }
}
