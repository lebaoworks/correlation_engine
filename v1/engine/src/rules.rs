//! Declarative rule set: TTP metadata, TTP taggers, and attack patterns — all
//! loaded from an external rule file at runtime (no recompile to add a pattern).
//!
//! Zero-dependency hand-written parser, consistent with `dataset.rs`. The tagger
//! predicate vocabulary is a **closed set** of conditions (not an expression
//! language): enough to express our techniques while staying bounded and auditable.
//! Adding a genuinely new predicate shape is the one thing that still needs code —
//! by design, since taggers are the platform-specific layer (see engine.md §4).
//!
//! ## Rule file grammar (one directive per line, `#` comments)
//! ```text
//! ttp <ID> tactic=<t> severity=<f> rarity=<f>
//! tagger <ID> <cond> <cond> ...
//! pattern <NAME> scope=<s> theta_alert=<f> theta_block=<f> root_gate=<g>
//! step <NAME> bit=<n> match=<ttp:ID|op:OP> prereq=<n,n> seg_window=<ms> \
//!      [enforceable] [optional] [block] [bind=<role>:<object|image|actor>]
//! ```
//! `step` lines attach to the most recent `pattern`. `block` marks the chokepoint.

use crate::event::{Event, Op};
use crate::pattern::{Mask, Pattern, RoleBinding, RoleSource, RootGate, Scope, Step, StepMatch};
use std::collections::{HashMap, HashSet, VecDeque};

pub type TtpId = String;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tactic {
    Execution,
    Discovery,
    DefenseEvasion,
    CredentialAccess,
    Impact,
    Staging,
}

impl Tactic {
    fn parse(s: &str) -> Option<Tactic> {
        Some(match s {
            "execution" => Tactic::Execution,
            "discovery" => Tactic::Discovery,
            "defense_evasion" => Tactic::DefenseEvasion,
            "credential_access" => Tactic::CredentialAccess,
            "impact" => Tactic::Impact,
            "staging" => Tactic::Staging,
            _ => return None,
        })
    }
    pub fn id(self) -> u8 {
        self as u8
    }
}

#[derive(Clone, Debug)]
pub struct TtpMeta {
    pub tactic: Tactic,
    pub severity: f64,
    pub rarity: f64,
}

/// Closed set of tagger conditions. All conditions of a tagger must hold to emit.
#[derive(Clone, Debug)]
enum Cond {
    OpIn(Vec<Op>),
    ImageBaseIn(Vec<String>),
    TargetImageBaseIn(Vec<String>),
    AttrTrue(String),
    EntropyGt(f64),
    WriteRateGe(usize),
    DirSpreadGe(usize),
    CmdRecoveryInhibit, // named builtin: the messy vssadmin/wbadmin/bcdedit cmd match
}

#[derive(Clone, Debug)]
struct Tagger {
    emits: TtpId,
    conds: Vec<Cond>,
}

/// Per-actor sliding counters for rate/spread predicates, updated O(1).
#[derive(Default)]
pub struct RateState {
    writes: VecDeque<(u64, String)>,
}

impl RateState {
    fn record_write(&mut self, ts: u64, dir: &str, window_ms: u64) {
        self.writes.push_back((ts, dir.to_string()));
        while let Some(&(t, _)) = self.writes.front() {
            if ts.saturating_sub(t) > window_ms {
                self.writes.pop_front();
            } else {
                break;
            }
        }
    }
    fn rate(&self) -> usize {
        self.writes.len()
    }
    fn distinct_dirs(&self) -> usize {
        self.writes.iter().map(|(_, d)| d.as_str()).collect::<HashSet<_>>().len()
    }
}

pub struct RuleSet {
    ttps: HashMap<TtpId, TtpMeta>,
    taggers: Vec<Tagger>,
    pub patterns: Vec<Pattern>,
}

impl RuleSet {
    /// TTP metadata; unknown ids fall back to a low-value staging default.
    pub fn meta(&self, id: &str) -> TtpMeta {
        self.ttps.get(id).cloned().unwrap_or(TtpMeta {
            tactic: Tactic::Staging,
            severity: 1.0,
            rarity: 0.15,
        })
    }

    /// Confirm which TTPs an event realizes (engine.md §4). Bounded, hot-path safe.
    pub fn tag(&self, e: &Event, rate: &mut RateState) -> Vec<TtpId> {
        // Accrue write rate/spread regardless of other conditions.
        if e.op == Op::Write {
            rate.record_write(e.ts, e.attr("dir").unwrap_or("/"), 1000);
        }
        let mut out = Vec::new();
        for tg in &self.taggers {
            if tg.conds.iter().all(|c| eval_cond(c, e, rate)) {
                out.push(tg.emits.clone());
            }
        }
        out
    }

    pub fn parse_str(input: &str) -> Result<RuleSet, String> {
        let mut ttps = HashMap::new();
        let mut taggers = Vec::new();
        let mut patterns: Vec<Pattern> = Vec::new();

        for (lineno, raw) in input.lines().enumerate() {
            let line = strip_comment(raw).trim();
            if line.is_empty() {
                continue;
            }
            let ctx = |m: String| format!("line {}: {}", lineno + 1, m);
            let mut toks = split_ws(line);
            let directive = toks.remove(0);
            match directive.as_str() {
                "ttp" => {
                    let (id, kv) = (toks.remove(0), kv_map(&toks));
                    let tactic = Tactic::parse(get(&kv, "tactic").map_err(&ctx)?)
                        .ok_or_else(|| ctx("bad tactic".into()))?;
                    ttps.insert(
                        id,
                        TtpMeta {
                            tactic,
                            severity: parse_f(&kv, "severity").map_err(&ctx)?,
                            rarity: parse_f(&kv, "rarity").map_err(&ctx)?,
                        },
                    );
                }
                "tagger" => {
                    let emits = toks.remove(0);
                    let conds = parse_conds(&toks).map_err(&ctx)?;
                    taggers.push(Tagger { emits, conds });
                }
                "pattern" => {
                    let name = toks.remove(0);
                    let kv = kv_map(&toks);
                    let scope = match get(&kv, "scope").map_err(&ctx)? {
                        "same_storyline" => Scope::SameStoryline,
                        "same_actor" => Scope::SameActor,
                        "free" => Scope::Free,
                        s => return Err(ctx(format!("bad scope '{}'", s))),
                    };
                    let root_gate = match kv.get("root_gate").map(|s| s.as_str()).unwrap_or("always") {
                        "always" => RootGate::Always,
                        "pe_write" => RootGate::PeWrite,
                        s => return Err(ctx(format!("bad root_gate '{}'", s))),
                    };
                    patterns.push(Pattern {
                        id: name,
                        steps: Vec::new(),
                        required_mask: 0,
                        scope,
                        block_at: None,
                        theta_alert: parse_f(&kv, "theta_alert").map_err(&ctx)?,
                        theta_block: parse_f(&kv, "theta_block").map_err(&ctx)?,
                        root_gate,
                    });
                }
                "step" => {
                    let p = patterns
                        .last_mut()
                        .ok_or_else(|| ctx("step before any pattern".into()))?;
                    let (step, is_block) = parse_step(&toks).map_err(&ctx)?;
                    let bit = step.bit;
                    if !step.optional {
                        p.required_mask |= 1 << bit;
                    }
                    if is_block {
                        p.block_at = Some(bit);
                    }
                    p.steps.push(step);
                }
                other => return Err(ctx(format!("unknown directive '{}'", other))),
            }
        }

        // validate prereq bits reference real steps
        for p in &patterns {
            let present: Mask = p.steps.iter().map(|s| 1u64 << s.bit).fold(0, |a, b| a | b);
            for s in &p.steps {
                if s.prereq_mask & !present != 0 {
                    return Err(format!("pattern {}: step {} prereq references unknown bit", p.id, s.name));
                }
            }
        }

        Ok(RuleSet { ttps, taggers, patterns })
    }
}

fn eval_cond(c: &Cond, e: &Event, rate: &RateState) -> bool {
    match c {
        Cond::OpIn(ops) => ops.contains(&e.op),
        Cond::ImageBaseIn(set) => e
            .attr("image")
            .map(|p| set.contains(&basename(p)))
            .unwrap_or(false),
        Cond::TargetImageBaseIn(set) => e
            .attr("target_image")
            .map(|p| set.contains(&basename(p)))
            .unwrap_or(false),
        Cond::AttrTrue(k) => e.attr_bool(k),
        Cond::EntropyGt(th) => e.attr_f64("entropy").map(|v| v > *th).unwrap_or(false),
        Cond::WriteRateGe(n) => rate.rate() >= *n,
        Cond::DirSpreadGe(n) => rate.distinct_dirs() >= *n,
        Cond::CmdRecoveryInhibit => cmd_recovery_inhibit(e.attr("cmd").unwrap_or("")),
    }
}

fn parse_conds(toks: &[String]) -> Result<Vec<Cond>, String> {
    let mut conds = Vec::new();
    for t in toks {
        let (k, v) = match t.split_once('=') {
            Some((k, v)) => (k, Some(v)),
            None => (t.as_str(), None),
        };
        let c = match k {
            "op" => Cond::OpIn(parse_op_set(v.unwrap_or(""))?),
            "image_base_in" => Cond::ImageBaseIn(lower_set(v.unwrap_or(""))),
            "target_image_base" => Cond::TargetImageBaseIn(lower_set(v.unwrap_or(""))),
            "attr_true" => Cond::AttrTrue(v.unwrap_or("").to_string()),
            "entropy_gt" => Cond::EntropyGt(v.unwrap_or("0").parse().map_err(|_| "bad entropy_gt")?),
            "write_rate_ge" => Cond::WriteRateGe(v.unwrap_or("0").parse().map_err(|_| "bad write_rate_ge")?),
            "dir_spread_ge" => Cond::DirSpreadGe(v.unwrap_or("0").parse().map_err(|_| "bad dir_spread_ge")?),
            "cmd_recovery_inhibit" => Cond::CmdRecoveryInhibit,
            other => return Err(format!("unknown tagger cond '{}'", other)),
        };
        conds.push(c);
    }
    Ok(conds)
}

fn parse_step(toks: &[String]) -> Result<(Step, bool), String> {
    let name = toks.first().ok_or("step missing name")?.clone();
    let mut bit = None;
    let mut matcher = None;
    let mut prereq_mask: Mask = 0;
    let mut seg_window = 0u64;
    let mut enforceable = false;
    let mut optional = false;
    let mut is_block = false;
    let mut bindings = Vec::new();

    for t in &toks[1..] {
        match t.split_once('=') {
            None => match t.as_str() {
                "enforceable" => enforceable = true,
                "optional" => optional = true,
                "block" => is_block = true,
                other => return Err(format!("unknown step flag '{}'", other)),
            },
            Some((k, v)) => match k {
                "bit" => bit = Some(v.parse::<u8>().map_err(|_| "bad bit")?),
                "seg_window" => seg_window = v.parse().map_err(|_| "bad seg_window")?,
                "prereq" => {
                    for b in v.split(',').filter(|s| !s.is_empty()) {
                        let b: u8 = b.parse().map_err(|_| "bad prereq bit")?;
                        prereq_mask |= 1 << b;
                    }
                }
                "match" => {
                    matcher = Some(match v.split_once(':') {
                        Some(("ttp", id)) => StepMatch::ByTtp(vec![id.to_string()]),
                        Some(("ttp_any", ids)) => {
                            StepMatch::ByTtp(ids.split('|').map(|s| s.to_string()).collect())
                        }
                        Some(("op", op)) => {
                            StepMatch::ByOp(Op::parse(op).ok_or("bad op in match")?)
                        }
                        _ => return Err("bad match (use ttp:ID | ttp_any:A|B | op:OP)".into()),
                    });
                }
                "bind" => {
                    let (role, src) = v.split_once(':').ok_or("bind needs role:source")?;
                    let source = match src {
                        "object" => RoleSource::Object,
                        "image" => RoleSource::Image,
                        "actor" => RoleSource::Actor,
                        _ => return Err("bind source must be object|image|actor".into()),
                    };
                    bindings.push(RoleBinding { role: role.to_string(), source });
                }
                other => return Err(format!("unknown step key '{}'", other)),
            },
        }
    }

    Ok((
        Step {
            bit: bit.ok_or("step missing bit")?,
            name,
            matcher: matcher.ok_or("step missing match")?,
            prereq_mask,
            seg_window,
            enforceable,
            optional,
            bindings,
        },
        is_block,
    ))
}

// ---- tiny parsing helpers ---------------------------------------------------

fn strip_comment(s: &str) -> &str {
    match s.find('#') {
        Some(i) => &s[..i],
        None => s,
    }
}
fn split_ws(s: &str) -> Vec<String> {
    s.split_whitespace().map(|x| x.to_string()).collect()
}
fn kv_map(toks: &[String]) -> HashMap<String, String> {
    toks.iter()
        .filter_map(|t| t.split_once('=').map(|(k, v)| (k.to_string(), v.to_string())))
        .collect()
}
fn get<'a>(kv: &'a HashMap<String, String>, k: &str) -> Result<&'a str, String> {
    kv.get(k).map(|s| s.as_str()).ok_or_else(|| format!("missing '{}'", k))
}
fn parse_f(kv: &HashMap<String, String>, k: &str) -> Result<f64, String> {
    get(kv, k)?.parse().map_err(|_| format!("bad number for '{}'", k))
}
fn parse_op_set(v: &str) -> Result<Vec<Op>, String> {
    v.split('|')
        .map(|s| Op::parse(s).ok_or_else(|| format!("bad op '{}'", s)))
        .collect()
}
fn lower_set(v: &str) -> Vec<String> {
    v.split(',').filter(|s| !s.is_empty()).map(|s| s.to_ascii_lowercase()).collect()
}
fn basename(path: &str) -> String {
    path.rsplit(['\\', '/']).next().unwrap_or(path).to_ascii_lowercase()
}
fn cmd_recovery_inhibit(cmd: &str) -> bool {
    let c = cmd.to_ascii_lowercase();
    (c.contains("delete") && (c.contains("shadow") || c.contains("catalog")))
        || c.contains("recoveryenabled no")
        || (c.contains("resize") && c.contains("shadowstorage"))
}
