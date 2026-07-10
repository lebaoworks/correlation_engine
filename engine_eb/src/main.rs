//! Replay tool for the endpoint–backend split core.
//!
//!   cargo run --bin edr-eb-replay -- ../engine/datasets/ransomware.evt [rules.rules]
//!
//! Feeds a `.evt` dataset through the endpoint (which ships to the backend) and,
//! on each block, prints the full storyline the backend reconstructed — the whole
//! point of the split: the endpoint blocks fast/locally, the backend explains.

use edr_engine::dataset;
use edr_engine_eb::{render_chain, Decision, Pipeline, VerdictKind};
use std::env;
use std::fs;
use std::process::ExitCode;

fn main() -> ExitCode {
    let path = match env::args().nth(1) {
        Some(p) => p,
        None => {
            eprintln!("usage: edr-eb-replay <dataset.evt> [rules.rules]");
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
    let events = match dataset::parse_str(&text) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("parse error: {}", e);
            return ExitCode::from(2);
        }
    };

    let mut pipe = match env::args().nth(2) {
        Some(rp) => match Pipeline::from_rules_file(&rp) {
            Ok(p) => {
                println!("(rules loaded from {})", rp);
                p
            }
            Err(e) => {
                eprintln!("rule error: {}", e);
                return ExitCode::from(2);
            }
        },
        None => Pipeline::new(),
    };

    println!("Replaying {} events from {}\n", events.len(), path);
    println!("{:>6}  {:<8} {:<7} {:<26} verdict", "ts", "op", "decn", "pattern/score");
    println!("{}", "-".repeat(70));

    let mut blocks = 0usize;
    let mut chains = Vec::new();
    for e in &events {
        let (decision, v, chain) = pipe.feed(e);
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
        if let Some(c) = chain {
            chains.push(c);
        }
    }

    if !chains.is_empty() {
        println!("\n--- backend: reconstructed storyline(s) on block ---\n");
        for c in &chains {
            print!("{}", render_chain(c));
            println!();
        }
    }

    println!("--- endpoint log ---");
    for l in &pipe.endpoint.log {
        println!("  {}", l);
    }

    println!(
        "\nendpoint: ACTIVE={} storylines={} shipped_events={} shipped_blocks={} swept={}",
        pipe.endpoint.active_len(),
        pipe.endpoint.storyline_count(),
        pipe.endpoint.shipped_events,
        pipe.endpoint.shipped_blocks,
        pipe.endpoint.swept,
    );
    println!("backend:  events_ingested={} chains={}", pipe.backend.events_ingested, pipe.backend.chains.len());
    println!("\n{} DENY decision(s) issued.", blocks);
    ExitCode::SUCCESS
}
