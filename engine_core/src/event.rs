//! Mô hình event thô đi vào engine (`engine_base.md §0, §2`).

/// Định danh ổn định của một thực thể: `(pid, start_ts)` cho process, `FileId`
/// cho file… — engine không diễn giải, chỉ so sánh. 128 bit đủ chứa mọi dạng.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Key(pub u128);

/// Loại thực thể (`Node.kind`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Process,
    File,
    Socket,
    Other,
}

/// Loại thao tác của event. Mỗi op là một bit để gom thành [`OpSet`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum Op {
    Exec = 1 << 0,
    Create = 1 << 1,
    Write = 1 << 2,
    Read = 1 << 3,
    Open = 1 << 4,
    Connect = 1 << 5,
    Inject = 1 << 6,
    Dup = 1 << 7,
}

/// Tập op dạng bitmask — dùng cho `Step.match.ops` và `DISARMED[actor]`.
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub struct OpSet(pub u32);

impl OpSet {
    pub const EMPTY: OpSet = OpSet(0);

    pub fn single(op: Op) -> Self {
        OpSet(op as u32)
    }

    pub fn contains(self, op: Op) -> bool {
        self.0 & (op as u32) != 0
    }

    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub fn union(self, other: OpSet) -> Self {
        OpSet(self.0 | other.0)
    }

    pub fn insert(&mut self, op: Op) {
        self.0 |= op as u32;
    }
}

/// Technique (TTP) đã được tagger gán cho event — ví dụ `Ttp(1059)` cho T1059.
/// Engine chỉ so khớp id, không mang ngữ nghĩa MITRE.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Ttp(pub u32);

/// Một event thô: actor làm `op` lên object tại `ts`.
#[derive(Clone, Copy, Debug)]
pub struct Event {
    pub ts: u64,
    pub op: Op,
    pub actor: Key,
    pub actor_kind: Kind,
    pub object: Key,
    pub object_kind: Kind,
}
