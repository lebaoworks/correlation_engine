//! Pattern/Step cho các bản engine:
//! - Tuyến tính ([`Pattern`]/[`Step`], `engine_base.md §2`): dãy bước theo thứ
//!   tự cố định — dùng cho `base` và `v0_0_1`.
//! - DAG ([`DagPattern`]/[`DagStep`], `engine_v0.0.2.md §3`): thứ tự bộ phận
//!   qua `bit` + `prereq_mask` — dùng cho `v0_0_2`.
//!
//! Cả hai chia sẻ [`StepMatch`] (điều kiện khớp) và [`Action`] (hành vi cưỡng
//! chế). Mỗi bước tự mang `action` riêng — không có severity/threshold gộp.

use alloc::collections::BTreeSet;
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

/// Tập pattern tuyến tính đã compile, giao cho `base`/`v0_0_1`. `pattern_id` = chỉ số.
#[derive(Clone, Debug, Default)]
pub struct RuleSet {
    pub patterns: Vec<Pattern>,
}

// ---- Pattern DAG (`engine_v0.0.2.md §3`): thứ tự bộ phận thay cho tuyến tính ----

/// Một bước trong pattern DAG: khớp `matcher`, đặt bit `bit`, chỉ commit được
/// khi mọi bit trong `prereq_mask` đã bật. `prereq_mask == 0` ⟹ bước gốc.
#[derive(Clone, Debug)]
pub struct DagStep {
    pub matcher: StepMatch,
    /// Chỉ số bit (0..64) bước này bật khi commit.
    pub bit: u8,
    /// Bitmask các bit phải bật trước; 0 = bước gốc (điểm seed).
    pub prereq_mask: u64,
    /// `None` = bước chỉ báo hiệu (verdict `inspect` khi khớp).
    pub action: Option<Action>,
}

impl DagStep {
    /// Bit đơn của bước này, dạng mask.
    pub fn bit_mask(&self) -> u64 {
        1u64 << self.bit
    }
}

/// Một mẫu tấn công dạng DAG — precedence graph, tiến độ theo bitmask (k ≤ 64 bước).
#[derive(Clone, Debug)]
pub struct DagPattern {
    pub name: String,
    pub steps: Vec<DagStep>,
}

/// Tập pattern DAG đã compile, giao cho `v0_0_2`. `pattern_id` = chỉ số.
#[derive(Clone, Debug, Default)]
pub struct DagRuleSet {
    pub patterns: Vec<DagPattern>,
}

impl DagRuleSet {
    /// Tập TTP (đã sắp xếp, không trùng) mà **bất kỳ** bước nào của ruleset tham
    /// chiếu. Driver dùng để chỉ bật những tagger có TTP mà rule thật sự cần —
    /// tagging tự đồng bộ với rule, không tag TTP thừa (`docs/todo.md` P1 tinh
    /// thần "chỉ làm việc liên quan").
    pub fn referenced_ttps(&self) -> Vec<Ttp> {
        let mut set = BTreeSet::new();
        for p in &self.patterns {
            for s in &p.steps {
                for t in &s.matcher.ttps {
                    set.insert(*t);
                }
            }
        }
        set.into_iter().collect()
    }
}
