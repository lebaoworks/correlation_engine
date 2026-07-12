//! **Backend** — the forensic half (engine.md §8).
//!
//! Holds the *full* provenance graph: every node, every edge, never evicted. It
//! ingests the endpoint's shipped events; on a [`BlockReport`] it walks the whole
//! storyline that led to the denied action and renders it as an ordered chain for
//! the SOC — the "truy vết và hiển thị toàn bộ chuỗi" the endpoint cannot do itself
//! (the endpoint keeps no edges).

use crate::event::{NodeKey, Op};
use std::collections::HashMap;

use crate::wire::{BlockReport, Wire, WireEvent};

struct BNode {
    key: NodeKey,
    label: String,
    last_seen: u64,
}

struct BEdge {
    from: usize,
    to: usize,
    op: Op,
    ts: u64,
    causal: bool,
    ttps: Vec<String>,
}

/// One reconstructed attack chain, ordered by time.
#[derive(Clone, Debug)]
pub struct Chain {
    pub pattern: String,
    pub score: f64,
    pub reason: String,
    pub blocked_ts: u64,
    pub steps: Vec<ChainStep>,
    pub nodes: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct ChainStep {
    pub ts: u64,
    pub op: Op,
    pub from: String,
    pub to: String,
    pub ttps: Vec<String>,
    pub causal: bool,
    pub blocked: bool,
}

pub struct Backend {
    nodes: Vec<BNode>,
    index: HashMap<NodeKey, usize>,
    edges: Vec<BEdge>,
    dsu: Vec<usize>,
    pub events_ingested: u64,
    pub chains: Vec<Chain>,
}

impl Backend {
    pub fn new() -> Backend {
        Backend { nodes: Vec::new(), index: HashMap::new(), edges: Vec::new(), dsu: Vec::new(), events_ingested: 0, chains: Vec::new() }
    }

    /// Ingest one wire record. Returns a rebuilt `Chain` when it processed a block.
    pub fn ingest(&mut self, msg: Wire) -> Option<Chain> {
        match msg {
            Wire::Event(we) => {
                self.ingest_event(we);
                None
            }
            Wire::Block(br) => {
                let c = self.trace_chain(&br);
                if let Some(ref chain) = c {
                    self.chains.push(chain.clone());
                }
                c
            }
        }
    }

    fn ingest_event(&mut self, we: WireEvent) {
        self.events_ingested += 1;
        let e = &we.event;
        let a = self.node(&e.actor, e.ts);
        let o = self.node(&e.object, e.ts);

        // On exec, label the child (object) with its image basename for readability.
        if e.op == Op::Exec {
            if let Some(img) = e.attr("image") {
                self.nodes[o].label = format!("{} ({})", basename(img), proc_short(&e.object));
            }
        }

        let causal = e.op.is_causal();
        self.edges.push(BEdge { from: a, to: o, op: e.op, ts: e.ts, causal, ttps: we.ttps });
        if causal {
            self.union(a, o);
        }
    }

    // -- chain reconstruction on block (§8) ----------------------------------
    fn trace_chain(&mut self, br: &BlockReport) -> Option<Chain> {
        let anchor = *self.index.get(&br.event.actor)?;
        let root = self.find(anchor);

        // Snapshot component roots (path-compresses along the way).
        let roots: Vec<usize> = (0..self.nodes.len()).map(|i| self.find(i)).collect();
        let in_comp = |i: usize| roots[i] == root;

        // Edges whose actor (from) is in the storyline — includes causal edges and the
        // touch edges those members initiated (discovery reads, etc.).
        let mut idxs: Vec<usize> = (0..self.edges.len())
            .filter(|&i| in_comp(self.edges[i].from) || in_comp(self.edges[i].to))
            .collect();
        idxs.sort_by_key(|&i| (self.edges[i].ts, i));

        let steps: Vec<ChainStep> = idxs
            .iter()
            .map(|&i| {
                let ed = &self.edges[i];
                let blocked = ed.ts == br.event.ts
                    && ed.op == br.event.op
                    && self.nodes[ed.from].key == br.event.actor
                    && self.nodes[ed.to].key == br.event.object;
                ChainStep {
                    ts: ed.ts,
                    op: ed.op,
                    from: self.nodes[ed.from].label.clone(),
                    to: self.nodes[ed.to].label.clone(),
                    ttps: ed.ttps.clone(),
                    causal: ed.causal,
                    blocked,
                }
            })
            .collect();

        let mut nodes: Vec<String> =
            (0..self.nodes.len()).filter(|&i| in_comp(i)).map(|i| self.nodes[i].label.clone()).collect();
        nodes.sort();
        nodes.dedup();

        Some(Chain {
            pattern: br.pattern.clone(),
            score: br.score,
            reason: br.reason.clone(),
            blocked_ts: br.event.ts,
            steps,
            nodes,
        })
    }

    // -- graph plumbing ------------------------------------------------------
    fn node(&mut self, key: &NodeKey, ts: u64) -> usize {
        if let Some(&i) = self.index.get(key) {
            self.nodes[i].last_seen = self.nodes[i].last_seen.max(ts);
            return i;
        }
        let i = self.nodes.len();
        self.nodes.push(BNode { key: key.clone(), label: default_label(key), last_seen: ts });
        self.dsu.push(i);
        self.index.insert(key.clone(), i);
        i
    }

    fn find(&mut self, x: usize) -> usize {
        let mut r = x;
        while self.dsu[r] != r {
            r = self.dsu[r];
        }
        let mut c = x;
        while self.dsu[c] != c {
            let n = self.dsu[c];
            self.dsu[c] = r;
            c = n;
        }
        r
    }

    fn union(&mut self, a: usize, b: usize) {
        let (ra, rb) = (self.find(a), self.find(b));
        if ra != rb {
            self.dsu[rb] = ra;
        }
    }
}

impl Default for Backend {
    fn default() -> Self {
        Backend::new()
    }
}

/// Render a reconstructed chain as a human-readable forensic block.
pub fn render_chain(c: &Chain) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "=== STORYLINE (blocked)  pattern={}  score={:.1}  reason={} ===\n",
        c.pattern, c.score, c.reason
    ));
    for s in &c.steps {
        let tag = if s.ttps.is_empty() { String::new() } else { format!("  [{}]", s.ttps.join(",")) };
        let mark = if s.blocked { "   *** BLOCKED ***" } else { "" };
        let arrow = if s.causal { "->" } else { ".." };
        out.push_str(&format!(
            "  ts={:<6} {:<7} {:<28} {} {:<24}{}{}\n",
            s.ts,
            format!("{:?}", s.op).to_lowercase(),
            s.from,
            arrow,
            s.to,
            tag,
            mark
        ));
    }
    out.push_str(&format!("  nodes: {}\n", c.nodes.join(", ")));
    out
}

fn default_label(k: &NodeKey) -> String {
    match k {
        NodeKey::Process { pid, start_ts } => format!("proc {}.{}", pid, start_ts),
        NodeKey::File { file_id } => format!("file:{}", file_id),
        NodeKey::Socket { key } => format!("sock:{}", key),
        NodeKey::Other { kind, key } => format!("{}:{}", kind, key),
    }
}

fn proc_short(k: &NodeKey) -> String {
    match k {
        NodeKey::Process { pid, start_ts } => format!("{}.{}", pid, start_ts),
        _ => default_label(k),
    }
}

fn basename(path: &str) -> String {
    path.rsplit(['\\', '/']).next().unwrap_or(path).to_string()
}
