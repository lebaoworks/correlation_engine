//! In bảng replay: từng event, verdict kỳ vọng vs thực tế.

fn main() {
    let outcomes = engine_replay::run();
    let mut failed = 0usize;

    println!("{:>4}  {:<10} {:<8} {:<8}  mô tả", "ts", "kỳ vọng", "thực tế", "");
    for o in &outcomes {
        let ok = o.actual == o.case.expect;
        if !ok {
            failed += 1;
        }
        println!(
            "{:>4}  {:<10} {:<8} {:<8}  {}",
            o.case.event.ts,
            format!("{:?}", o.case.expect),
            format!("{:?}", o.actual),
            if ok { "ok" } else { "SAI" },
            o.case.desc,
        );
    }

    if failed > 0 {
        eprintln!("\n{failed}/{} event sai verdict", outcomes.len());
        std::process::exit(1);
    }
    println!("\n{} event khớp verdict kỳ vọng", outcomes.len());
}
