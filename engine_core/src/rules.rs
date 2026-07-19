//! Pattern/Step (`engine_base.md §2`): dãy bước tuyến tính, mỗi bước tự mang
//! `action` riêng — không có severity/threshold gộp toàn automaton.

use alloc::string::String;
use alloc::vec::Vec;

use crate::event::{Op, OpSet, Ttp};

/// Hành vi cưỡng chế của một bước — rule chỉ có hai: `block` và `disarm`.
/// `ignore`/`inspect` KHÔNG phải action: chúng là [`crate::Verdict`] engine
/// trả về (`ignore` = event vô hại, không kích hoạt gì; `inspect` = event vừa
/// kích hoạt một bước pattern không mang hành vi cưỡng chế).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Action {
    Block,
    /// Chặn hành vi vừa xảy ra VÀ tước quyền các op này của actor, vĩnh viễn.
    Disarm(OpSet),
}

/// Điều kiện khớp của một bước trên `(op, ttp)` của event.
#[derive(Clone, Debug)]
pub struct StepMatch {
    /// Op phải thuộc tập này; tập rỗng = khớp mọi op.
    pub ops: OpSet,
    /// Mọi TTP liệt kê ở đây phải có mặt trong tập TTP của event.
    pub ttps: Vec<Ttp>,
}

impl StepMatch {
    pub fn matches(&self, op: Op, ttps: &[Ttp]) -> bool {
        (self.ops.is_empty() || self.ops.contains(op))
            && self.ttps.iter().all(|t| ttps.contains(t))
    }
}

#[derive(Clone, Debug)]
pub struct Step {
    pub matcher: StepMatch,
    /// `None` = bước chỉ báo hiệu: khớp thì verdict là `inspect`, không cưỡng chế.
    pub action: Option<Action>,
}

/// Một mẫu tấn công: dãy bước có thứ tự cố định, khớp tuần tự 1-1.
#[derive(Clone, Debug)]
pub struct Pattern {
    /// Tên để báo cáo/diagnostics; định danh runtime là chỉ số trong `RuleSet`.
    pub name: String,
    pub steps: Vec<Step>,
}

/// Tập pattern đã compile, giao cho [`crate::Engine`]. `pattern_id` = chỉ số.
#[derive(Clone, Debug, Default)]
pub struct RuleSet {
    pub patterns: Vec<Pattern>,
}
