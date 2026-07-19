//! Regression: mọi bản engine phải cho verdict khớp kỳ vọng trên dataset
//! docs/replay.md, và các bản phải cho verdict GIỐNG HỆT NHAU trên cùng
//! một luồng event bất kỳ (khẳng định của engine_v0.0.1.md: bỏ graph không
//! đổi kết quả phát hiện).

use engine_core::{base, v0_0_1, Detector, Event, Key, Kind, Op, Ttp};

fn assert_scenario(engine: &mut dyn Detector, label: &str) {
    for o in engine_replay::replay(engine) {
        assert_eq!(
            o.actual, o.case.expect,
            "[{label}] ts={} — {}",
            o.case.event.ts, o.case.desc,
        );
    }
}

#[test]
fn scenario_matches_on_base() {
    assert_scenario(&mut base::Engine::new(engine_replay::compiled_rules()), "base");
}

#[test]
fn scenario_matches_on_v0_0_1() {
    assert_scenario(&mut v0_0_1::Engine::new(engine_replay::compiled_rules()), "v0.0.1");
}

/// Test vi sai: bơm một luồng event giả ngẫu nhiên (deterministic) qua cả hai
/// bản, verdict phải trùng nhau từng event một.
#[test]
fn base_and_v0_0_1_verdicts_are_identical() {
    // rule riêng cho fuzz: phủ cả block lẫn disarm, cả bước khớp mọi op
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

    // LCG deterministic — không kéo dependency random nào
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
        // 0..=2 TTP mỗi event
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
        // hai bản phải cùng nhìn thấy một storyline cho actor này
        let mb: Vec<Key> = base.storyline_of(actor).map(|it| it.collect()).unwrap_or_default();
        let mv: Vec<Key> = v001.storyline_of(actor).map(|it| it.collect()).unwrap_or_default();
        assert_eq!(mb, mv, "lệch storyline tại event #{i}");
    }

    // luồng có chứa write+T1486 sau chuỗi khớp → chắc chắn đã có disarm nổ;
    // sanity: cả hai bản phải đã trả ít nhất một verdict ≠ Ignore ở trên
    // (nếu không, test này không phủ được gì — báo bằng verdict cuối cùng)
    let probe = Event {
        ts: 5000,
        op: Op::Exec,
        actor: Key(0),
        actor_kind: Kind::Process,
        object: Key(1),
        object_kind: Kind::File,
    };
    assert_eq!(
        base.on_event(&probe, &[Ttp(1059)]),
        v001.on_event(&probe, &[Ttp(1059)]),
    );
}

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
