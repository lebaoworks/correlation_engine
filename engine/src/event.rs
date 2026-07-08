//! Event model — normalized telemetry fed into the detection core.
//!
//! Mirrors engine.md §0. The kernel sensor (minifilter / bpf_lsm) produces these;
//! here we consume a normalized stream. File identity is a *token* standing in for
//! a FileId / (dev,inode) — never a path string (engine.md §2). Rename keeps the
//! same token; copy produces a new one, exactly as FileId behaves.

use std::collections::HashMap;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum Op {
    Exec,   // process spawn: actor=parent, object=child; attrs["image"] = image FileId
    Open,
    Read,
    Write,  // actor=process, object=file
    Connect,
    Inject,
    Create,
    Delete,
    Load,
    Dup,
}

impl Op {
    /// Only *causal* edges merge storylines (engine.md §3). "Touch" edges
    /// (read/open/connect) leave an edge for scoring but do not unify.
    pub fn is_causal(self) -> bool {
        matches!(self, Op::Exec | Op::Inject | Op::Create | Op::Dup | Op::Write)
    }

    pub fn parse(s: &str) -> Option<Op> {
        Some(match s {
            "exec" => Op::Exec,
            "open" => Op::Open,
            "read" => Op::Read,
            "write" => Op::Write,
            "connect" => Op::Connect,
            "inject" => Op::Inject,
            "create" => Op::Create,
            "delete" => Op::Delete,
            "load" => Op::Load,
            "dup" => Op::Dup,
            _ => return None,
        })
    }
}

/// Natural key of a graph node. For processes this is (pid, start_ts) to defeat
/// pid reuse; for files it is the FileId token, not a path.
#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub enum NodeKey {
    Process { pid: u32, start_ts: u64 },
    File { file_id: String },
    Socket { key: String },
    Other { kind: String, key: String },
}

impl NodeKey {
    pub fn kind(&self) -> &'static str {
        match self {
            NodeKey::Process { .. } => "process",
            NodeKey::File { .. } => "file",
            NodeKey::Socket { .. } => "socket",
            NodeKey::Other { .. } => "other",
        }
    }
}

/// A single normalized telemetry event.
#[derive(Clone, Debug)]
pub struct Event {
    pub ts: u64,
    pub op: Op,
    pub actor: NodeKey,   // always a process
    pub object: NodeKey,  // file / child process / socket ...
    pub attrs: HashMap<String, String>,
}

impl Event {
    pub fn attr(&self, k: &str) -> Option<&str> {
        self.attrs.get(k).map(|s| s.as_str())
    }
    pub fn attr_f64(&self, k: &str) -> Option<f64> {
        self.attrs.get(k).and_then(|s| s.parse().ok())
    }
    pub fn attr_bool(&self, k: &str) -> bool {
        matches!(self.attrs.get(k).map(|s| s.as_str()), Some("1") | Some("true"))
    }
    /// The image FileId of an exec (attrs["image"]), resolved to a File key.
    pub fn image_key(&self) -> Option<NodeKey> {
        self.attr("image").map(|id| NodeKey::File { file_id: id.to_string() })
    }
}
