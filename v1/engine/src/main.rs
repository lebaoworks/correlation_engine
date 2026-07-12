//! Replay tool: feed a `.evt` dataset through the detection core in audit mode and
//! print, per event, the verdict and kernel decision (Allow/Deny).
//!
//!   cargo run --bin edr-replay -- datasets/ransomware.evt [rules/custom.rules]

use edr_engine::{Decision, Engine, VerdictKind};
use std::env;
use std::fs;
use std::process::ExitCode;

fn main() -> ExitCode {
    let path = match env::args().nth(1) {
        Some(p) => p,
        None => {
            eprintln!("usage: edr-replay <dataset.evt> [rules.rules]");
            return ExitCode::from(2);
        }
    };
    let text = match fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("cannot read {}: {}", path, e);
            return ExitCode::from(2);
        }
    };
    let events = match edr_engine::dataset::parse_str(&text) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("parse error: {}", e);
            return ExitCode::from(2);
        }
    };

    // Optional second arg: a rule file to load instead of the embedded default.
    let mut engine = match env::args().nth(2) {
        Some(rp) => match Engine::from_rules_file(&rp) {
            Ok(e) => {
                println!("(rules loaded from {})", rp);
                e
            }
            Err(e) => {
                eprintln!("rule error: {}", e);
                return ExitCode::from(2);
            }
        },
        None => Engine::new(),
    };
    let mut blocks = 0usize;

    println!("Replaying {} events from {}\n", events.len(), path);
    println!("{:>6}  {:<8} {:<7} {:<26} verdict", "ts", "op", "decn", "pattern/score");
    println!("{}", "-".repeat(70));

    for e in &events {
        let (decision, v) = engine.on_event(e);
        let decn = match decision {
            Decision::Allow => "ALLOW",
            Decision::Deny => "DENY",
        };
        if decision == Decision::Deny {
            blocks += 1;
        }
        let vtxt = if v.kind == VerdictKind::None {
            "-".to_string()
        } else {
            format!("{:?} {} ({:.1})", v.kind, v.pattern, v.score)
        };
        println!("{:>6}  {:<8} {:<7} {:<26} {}", e.ts, format!("{:?}", e.op), decn, vtxt, v.reason);
    }

    println!("\n--- engine event log ---");
    for l in &engine.log {
        println!("  {}", l);
    }
    println!("\n{} DENY decision(s) issued.", blocks);
    ExitCode::SUCCESS
}
