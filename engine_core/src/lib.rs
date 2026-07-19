//! `engine_core` — lõi phát hiện, implement lần lượt các bản thiết kế
//! `docs/engine_base.md` → `docs/engine_v*.md`.
//!
//! - [`base`] — `engine_base.md`: full provenance graph (node/cạnh sống mãi)
//!   + storyline + automaton tuyến tính + `DISARMED`.
//! - [`v0_0_1`] — `engine_v0.0.1.md`: bỏ graph, chỉ còn `LINE` map.
//! - [`v0_0_2`] — `engine_v0.0.2.md`: pattern = partial-order DAG (bitmask +
//!   `prereq_mask`). **Bản hiện hành** — re-export làm [`Engine`].
//!
//! Mọi bản cùng implement [`Detector`] và phải cho verdict giống hệt nhau
//! trên cùng luồng event (lưới regression + test vi sai ở `engine_replay`).
//!
//! Crate này `no_std + alloc`, không phụ thuộc gì ngoài `core`/`alloc` — nhúng
//! được vào cả usermode lẫn kernel mode. `TAG_TTP` là lớp platform-specific
//! (`engine.md §6.0`) nên nằm ngoài crate: caller tag TTP rồi truyền vào
//! [`Detector::on_event`]. Ruleset do `engine_rules` compile, giao xuống dạng
//! [`rules::RuleSet`] trực tiếp hoặc dạng bytes qua [`wire`].

#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod base;
pub mod detector;
pub mod event;
pub mod rules;
pub mod v0_0_1;
pub mod v0_0_2;
pub mod wire;

pub use detector::{Detector, Verdict};
pub use event::{Event, Key, Kind, Op, OpSet, Ttp};
pub use rules::{
    Action, DagPattern, DagRuleSet, DagStep, Pattern, RuleSet, Step, StepMatch,
};
pub use v0_0_2::Engine;
