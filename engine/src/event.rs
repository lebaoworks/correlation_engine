//! Event model — normalized telemetry fed into the detection core.
//!
//! Mirrors engine.md §0. The kernel sensor (minifilter / bpf_lsm) produces these;
//! here we consume a normalized stream. File identity is a *token* standing in for
//! a FileId / (dev,inode) — never a path string (engine.md §2). Rename keeps the
//! same token; copy produces a new one, exactly as FileId behaves.

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

/// Typed, closed-vocabulary event attributes. The engine only ever reads a fixed
/// set of attrs — the tagger predicate vocabulary (`rules.rs`) — so we store them
/// as typed fields instead of a per-event `HashMap<String,String>`: no hashmap and
/// no key-string allocation on the hot path. The `attr`/`attr_bool`/`attr_f64`
/// accessors on `Event` keep the taggers' string-keyed API unchanged.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Attrs {
    pub image: Option<String>,        // exec image FileId token (Op::Exec)
    pub cmd: Option<String>,          // exec command line
    pub target_image: Option<String>, // ProcessOpen target image
    pub dir: Option<String>,          // write directory (rate/spread accrual)
    pub entropy: Option<f64>,         // written-content entropy (enrichment)
    pub pe: bool,                     // written file is a PE (dropper gate)
    pub vm_read: bool,                // handle opened with PROCESS_VM_READ
    pub enumerate: bool,              // open/read is a directory enumeration (attr key "enum")
}

impl Attrs {
    /// Set a known attr from a string key/value — used by the `.evt` dataset loader
    /// and replay/test builders that carry attrs as text. Unknown keys are ignored:
    /// the vocabulary is closed by design (see `rules.rs`).
    pub fn set(&mut self, k: &str, v: impl Into<String>) {
        match k {
            "image" => self.image = Some(v.into()),
            "cmd" => self.cmd = Some(v.into()),
            "target_image" => self.target_image = Some(v.into()),
            "dir" => self.dir = Some(v.into()),
            "entropy" => self.entropy = v.into().parse().ok(),
            "pe" => self.pe = truthy(&v.into()),
            "vm_read" => self.vm_read = truthy(&v.into()),
            "enum" => self.enumerate = truthy(&v.into()),
            _ => {}
        }
    }
}

fn truthy(s: &str) -> bool {
    matches!(s, "1" | "true")
}

/// A single normalized telemetry event.
#[derive(Clone, Debug)]
pub struct Event {
    pub ts: u64,
    pub op: Op,
    pub actor: NodeKey,   // always a process
    pub object: NodeKey,  // file / child process / socket ...
    pub attrs: Attrs,
}

impl Event {
    pub fn attr(&self, k: &str) -> Option<&str> {
        match k {
            "image" => self.attrs.image.as_deref(),
            "cmd" => self.attrs.cmd.as_deref(),
            "target_image" => self.attrs.target_image.as_deref(),
            "dir" => self.attrs.dir.as_deref(),
            _ => None,
        }
    }
    pub fn attr_f64(&self, k: &str) -> Option<f64> {
        match k {
            "entropy" => self.attrs.entropy,
            _ => None,
        }
    }
    pub fn attr_bool(&self, k: &str) -> bool {
        match k {
            "pe" => self.attrs.pe,
            "vm_read" => self.attrs.vm_read,
            "enum" => self.attrs.enumerate,
            _ => false,
        }
    }
    /// The image FileId of an exec (`attrs.image`), resolved to a File key.
    pub fn image_key(&self) -> Option<NodeKey> {
        self.attr("image").map(|id| NodeKey::File { file_id: id.to_string() })
    }
}
