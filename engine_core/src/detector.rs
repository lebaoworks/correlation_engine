//! Khế ước phát hiện chung cho mọi bản `engine_v*`: cùng nhận một luồng
//! event đã tag TTP, cùng trả [`Verdict`] per-event. Các bản chỉ khác nhau
//! ở cấu trúc trạng thái giữ bên trong (graph, LINE, working-set…).

use alloc::collections::BTreeMap;

use crate::event::{Event, Key, OpSet, Ttp};
use crate::rules::{Action, Step};

/// Verdict của MỘT event — phản ứng mạnh nhất trong các bước vừa kích hoạt
/// tại đúng event đó (`engine_base.md §5`): `ignore < inspect < block < disarm`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Verdict {
    /// Event vô hại/vô dụng: không kích hoạt bước nào của pattern nào.
    Ignore,
    /// Event vừa kích hoạt (seed hoặc tiến) ít nhất một bước pattern,
    /// nhưng không bước nào mang hành vi cưỡng chế.
    Inspect,
    Block,
    Disarm,
}

/// Mọi bản engine đều là một `Detector`; hai bản đúng đắn phải cho verdict
/// giống hệt nhau trên cùng một luồng event (xem test vi sai ở `engine_replay`).
pub trait Detector {
    fn on_event(&mut self, e: &Event, ttps: &[Ttp]) -> Verdict;
}

/// `APPLY` (`engine_base.md §5`) — chung cho mọi bản: bước vừa kích hoạt →
/// verdict. Không action ⇒ chỉ báo hiệu (`inspect`); disarm tước quyền actor
/// TỪ BÂY GIỜ, vĩnh viễn.
pub(crate) fn apply(step: &Step, actor: Key, disarmed: &mut BTreeMap<Key, OpSet>) -> Verdict {
    match step.action {
        None => Verdict::Inspect,
        Some(Action::Block) => Verdict::Block,
        Some(Action::Disarm(ops)) => {
            let entry = disarmed.entry(actor).or_default();
            *entry = entry.union(ops);
            Verdict::Disarm
        }
    }
}
