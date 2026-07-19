//! `engine_rules` — compile rule dạng text thành [`engine_core::RuleSet`]
//! (giao trực tiếp in-process) hoặc bytes theo [`engine_core::wire`] (giao
//! xuống kernel / qua process khác).
//!
//! Định dạng rule, mỗi pattern một khối:
//!
//! ```text
//! # comment
//! pattern <tên>
//!     step [ops=exec|write] [ttps=T1059,T1083] [action=<block|disarm(op,...)>]
//!     ...
//! end
//! ```
//!
//! - `ops=` vắng mặt ⇒ bước khớp mọi op; nhiều op phân cách bằng `|`.
//! - `ttps=` vắng mặt ⇒ không ràng buộc TTP; mọi TTP liệt kê phải có mặt
//!   trong tập TTP của event. Chấp nhận `T1059` hoặc `1059`.
//! - Rule chỉ có hai hành vi cưỡng chế: `block` và `disarm(...)` (liệt kê op
//!   bị tước quyền). `action=` vắng mặt ⇒ bước chỉ báo hiệu — khớp thì engine
//!   trả verdict `inspect`. `ignore`/`inspect` không phải action: chúng là
//!   verdict do engine trả về (`ignore` = event vô hại, `inspect` = event vừa
//!   kích hoạt một pattern).

use engine_core::{Action, Op, OpSet, Pattern, RuleSet, Step, StepMatch, Ttp};

#[derive(Debug, PartialEq, Eq)]
pub struct CompileError {
    /// Dòng gây lỗi, đánh số từ 1.
    pub line: usize,
    pub msg: String,
}

impl std::fmt::Display for CompileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "dòng {}: {}", self.line, self.msg)
    }
}

impl std::error::Error for CompileError {}

/// Compile toàn bộ file rule thành `RuleSet`.
pub fn compile(src: &str) -> Result<RuleSet, CompileError> {
    let mut patterns: Vec<Pattern> = Vec::new();
    let mut current: Option<Pattern> = None;

    for (idx, raw) in src.lines().enumerate() {
        let lineno = idx + 1;
        let err = |msg: String| CompileError { line: lineno, msg };
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let keyword = line.split_whitespace().next().unwrap_or("");
        if keyword == "pattern" {
            let rest = &line["pattern".len()..];
            if current.is_some() {
                return Err(err("pattern trước chưa đóng bằng `end`".into()));
            }
            let name = rest.trim();
            if name.is_empty() || name.contains(char::is_whitespace) {
                return Err(err("cú pháp: `pattern <tên>` (tên không chứa khoảng trắng)".into()));
            }
            if patterns.iter().any(|p| p.name == name) {
                return Err(err(format!("pattern `{name}` bị định nghĩa lặp")));
            }
            current = Some(Pattern { name: name.to_string(), steps: Vec::new() });
        } else if line == "end" {
            let p = current.take().ok_or_else(|| err("`end` không có `pattern` mở".into()))?;
            if p.steps.is_empty() {
                return Err(err(format!("pattern `{}` không có bước nào", p.name)));
            }
            patterns.push(p);
        } else if keyword == "step" {
            let rest = &line["step".len()..];
            let p = current
                .as_mut()
                .ok_or_else(|| err("`step` phải nằm trong khối `pattern`..`end`".into()))?;
            p.steps.push(parse_step(rest.trim(), lineno)?);
        } else {
            return Err(err(format!("không hiểu dòng: `{line}`")));
        }
    }

    if let Some(p) = current {
        return Err(CompileError {
            line: src.lines().count(),
            msg: format!("pattern `{}` chưa đóng bằng `end`", p.name),
        });
    }
    Ok(RuleSet { patterns })
}

/// Compile rồi encode luôn theo wire format của `engine_core`.
pub fn compile_to_bytes(src: &str) -> Result<Vec<u8>, CompileError> {
    Ok(engine_core::wire::encode(&compile(src)?))
}

fn parse_step(rest: &str, lineno: usize) -> Result<Step, CompileError> {
    let err = |msg: String| CompileError { line: lineno, msg };
    let mut ops = OpSet::EMPTY;
    let mut ttps: Vec<Ttp> = Vec::new();
    let mut action: Option<Action> = None;

    for tok in rest.split_whitespace() {
        let (k, v) = tok
            .split_once('=')
            .ok_or_else(|| err(format!("token `{tok}` phải có dạng key=value")))?;
        match k {
            "ops" => {
                for name in v.split('|') {
                    ops.insert(parse_op(name).ok_or_else(|| err(format!("op lạ: `{name}`")))?);
                }
            }
            "ttps" => {
                for t in v.split(',') {
                    ttps.push(parse_ttp(t).ok_or_else(|| err(format!("ttp lạ: `{t}`")))?);
                }
            }
            "action" => {
                if action.is_some() {
                    return Err(err("action bị lặp".into()));
                }
                action = Some(parse_action(v, lineno)?);
            }
            other => return Err(err(format!("key lạ: `{other}`"))),
        }
    }

    Ok(Step { matcher: StepMatch { ops, ttps }, action })
}

fn parse_action(v: &str, lineno: usize) -> Result<Action, CompileError> {
    let err = |msg: String| CompileError { line: lineno, msg };
    match v {
        "block" => Ok(Action::Block),
        _ => {
            let inner = v
                .strip_prefix("disarm(")
                .and_then(|s| s.strip_suffix(')'))
                .ok_or_else(|| err(format!("action lạ: `{v}`")))?;
            let mut ops = OpSet::EMPTY;
            for name in inner.split(',') {
                ops.insert(parse_op(name.trim()).ok_or_else(|| err(format!("op lạ trong disarm: `{name}`")))?);
            }
            if ops.is_empty() {
                return Err(err("disarm() rỗng".into()));
            }
            Ok(Action::Disarm(ops))
        }
    }
}

fn parse_op(name: &str) -> Option<Op> {
    Some(match name {
        "exec" => Op::Exec,
        "create" => Op::Create,
        "write" => Op::Write,
        "read" => Op::Read,
        "open" => Op::Open,
        "connect" => Op::Connect,
        "inject" => Op::Inject,
        "dup" => Op::Dup,
        _ => return None,
    })
}

fn parse_ttp(t: &str) -> Option<Ttp> {
    let digits = t.strip_prefix('T').unwrap_or(t);
    digits.parse::<u32>().ok().map(Ttp)
}

#[cfg(test)]
mod tests {
    use super::*;

    const OK: &str = "\
# demo
pattern demo
    step ops=exec ttps=T1059
    step ops=write|create ttps=1486,T1490 action=disarm(write,exec)
end
";

    #[test]
    fn compiles_valid_source() {
        let rules = compile(OK).unwrap();
        assert_eq!(rules.patterns.len(), 1);
        let p = &rules.patterns[0];
        assert_eq!(p.name, "demo");
        assert_eq!(p.steps.len(), 2);
        assert!(p.steps[0].matcher.ops.contains(Op::Exec));
        assert_eq!(p.steps[0].matcher.ttps, vec![Ttp(1059)]);
        // không ghi action= ⇒ bước chỉ báo hiệu (verdict inspect khi khớp)
        assert_eq!(p.steps[0].action, None);
        assert!(p.steps[1].matcher.ops.contains(Op::Create));
        assert_eq!(p.steps[1].matcher.ttps, vec![Ttp(1486), Ttp(1490)]);
        assert!(matches!(p.steps[1].action, Some(Action::Disarm(ops)) if ops.contains(Op::Write) && ops.contains(Op::Exec)));
    }

    #[test]
    fn roundtrips_through_wire() {
        let bytes = compile_to_bytes(OK).unwrap();
        let rules = engine_core::wire::decode(&bytes).unwrap();
        assert_eq!(rules.patterns[0].name, "demo");
        assert_eq!(rules.patterns[0].steps.len(), 2);
    }

    #[test]
    fn rejects_bad_source() {
        assert!(compile("step action=block").is_err()); // step ngoài pattern
        assert!(compile("pattern p\nend").is_err()); // pattern rỗng
        assert!(compile("pattern p\n step action=fly\nend").is_err()); // action lạ
        assert!(compile("pattern p\n step action=ignore\nend").is_err()); // ignore là verdict, không phải action
        assert!(compile("pattern p\n step action=inspect\nend").is_err()); // inspect cũng là verdict
        assert!(compile("pattern p\n step ops=warp action=block\nend").is_err()); // op lạ
        assert!(compile("pattern p\n step action=block\n").is_err()); // thiếu end
        let e = compile("pattern p\n step action=block\nxyz\nend").unwrap_err();
        assert_eq!(e.line, 3);
    }
}
