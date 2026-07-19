//! `engine_core` — lõi phát hiện theo `docs/engine_base.md`.
//!
//! Bản base: full provenance graph (node/cạnh sống mãi), storyline = thành phần
//! liên thông, automaton tuyến tính per-pattern, `DISARMED` tước quyền vĩnh viễn.
//!
//! Crate này `no_std + alloc`, không phụ thuộc gì ngoài `core`/`alloc` — nhúng
//! được vào cả usermode lẫn kernel mode. `TAG_TTP` là lớp platform-specific
//! (`engine.md §6.0`) nên nằm ngoài crate: caller tag TTP rồi truyền vào
//! [`Engine::on_event`]. Ruleset do `engine_rules` compile, giao xuống dạng
//! [`rules::RuleSet`] trực tiếp hoặc dạng bytes qua [`wire`].

#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod engine;
pub mod event;
pub mod rules;
pub mod wire;

pub use engine::{Engine, Verdict};
pub use event::{Event, Key, Kind, Op, OpSet, Ttp};
pub use rules::{Action, Pattern, RuleSet, Step, StepMatch};
