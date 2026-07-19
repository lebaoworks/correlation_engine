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

use engine_core::{
    Action, DagPattern, DagRuleSet, DagStep, Op, OpSet, Pattern, RuleSet, Step, StepMatch, Ttp,
};

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

/// Compile rule DAG (`engine_v0.0.2`) thành [`engine_core::DagRuleSet`].
///
/// Cú pháp step thêm `bit=<n>` (bắt buộc, 0..64) và `prereq=<n,..>` (các bit
/// phải xong trước; vắng mặt ⇒ bước gốc). Ví dụ:
///
/// ```text
/// pattern ransomware_dag
///     step bit=0 ops=exec ttps=T1059
///     step bit=1 prereq=0 ops=read ttps=T1083
///     step bit=2 prereq=0 ops=exec ttps=T1490
///     step bit=3 prereq=1,2 ops=write ttps=T1486 action=disarm(write,exec)
/// end
/// ```
pub fn compile_dag(src: &str) -> Result<DagRuleSet, CompileError> {
    let mut patterns: Vec<DagPattern> = Vec::new();
    let mut current: Option<DagPattern> = None;

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
            current = Some(DagPattern { name: name.to_string(), steps: Vec::new() });
        } else if line == "end" {
            let p = current.take().ok_or_else(|| err("`end` không có `pattern` mở".into()))?;
            validate_dag(&p, lineno)?;
            patterns.push(p);
        } else if keyword == "step" {
            let rest = &line["step".len()..];
            let p = current
                .as_mut()
                .ok_or_else(|| err("`step` phải nằm trong khối `pattern`..`end`".into()))?;
            let s = parse_dag_step(rest.trim(), lineno)?;
            if p.steps.iter().any(|x| x.bit == s.bit) {
                return Err(err(format!("bit {} bị lặp trong pattern", s.bit)));
            }
            p.steps.push(s);
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
    Ok(DagRuleSet { patterns })
}

/// Compile rule DAG rồi encode theo wire format DAG (`ERD1`).
pub fn compile_dag_to_bytes(src: &str) -> Result<Vec<u8>, CompileError> {
    Ok(engine_core::wire::encode_dag(&compile_dag(src)?))
}

/// Kiểm DAG hợp lệ: có ít nhất một bước gốc, prereq chỉ trỏ tới bit đã khai,
/// và mọi bit tới được từ gốc (không chu trình / không mồ côi).
fn validate_dag(p: &DagPattern, lineno: usize) -> Result<(), CompileError> {
    let err = |msg: String| CompileError { line: lineno, msg };
    if p.steps.is_empty() {
        return Err(err(format!("pattern `{}` không có bước nào", p.name)));
    }
    let defined: u64 = p.steps.iter().map(|s| s.bit_mask()).fold(0, |a, b| a | b);
    if !p.steps.iter().any(|s| s.prereq_mask == 0) {
        return Err(err(format!("pattern `{}` không có bước gốc (prereq rỗng)", p.name)));
    }
    for s in &p.steps {
        if s.prereq_mask & !defined != 0 {
            return Err(err(format!("bit {} có prereq trỏ tới bit chưa khai", s.bit)));
        }
    }
    // reachability: khởi từ bit gốc, lan truyền qua prereq đã đủ (fixpoint)
    let mut reached: u64 = 0;
    loop {
        let mut grew = false;
        for s in &p.steps {
            if reached & s.bit_mask() == 0 && (s.prereq_mask & reached) == s.prereq_mask {
                reached |= s.bit_mask();
                grew = true;
            }
        }
        if !grew {
            break;
        }
    }
    if reached != defined {
        return Err(err(format!(
            "pattern `{}` có bit không tới được từ gốc (chu trình prereq?)",
            p.name
        )));
    }
    Ok(())
}

fn parse_dag_step(rest: &str, lineno: usize) -> Result<DagStep, CompileError> {
    let err = |msg: String| CompileError { line: lineno, msg };
    let mut bit: Option<u8> = None;
    let mut prereq_mask: u64 = 0;
    let mut ops = OpSet::EMPTY;
    let mut ttps: Vec<Ttp> = Vec::new();
    let mut action: Option<Action> = None;

    for tok in rest.split_whitespace() {
        let (k, v) = tok
            .split_once('=')
            .ok_or_else(|| err(format!("token `{tok}` phải có dạng key=value")))?;
        match k {
            "bit" => {
                let n: u8 = v.parse().map_err(|_| err(format!("bit không hợp lệ: `{v}`")))?;
                if n >= 64 {
                    return Err(err(format!("bit phải < 64: `{v}`")));
                }
                bit = Some(n);
            }
            "prereq" => {
                for p in v.split(',') {
                    let n: u8 = p.parse().map_err(|_| err(format!("prereq không hợp lệ: `{p}`")))?;
                    if n >= 64 {
                        return Err(err(format!("prereq bit phải < 64: `{p}`")));
                    }
                    prereq_mask |= 1u64 << n;
                }
            }
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

    let bit = bit.ok_or_else(|| err("step DAG thiếu `bit=`".into()))?;
    Ok(DagStep { matcher: StepMatch { ops, ttps }, bit, prereq_mask, action })
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

    const DAG_OK: &str = "\
# ransomware DAG — bit 1 ∥ bit 2 tự do thứ tự, bit 3 là mốc {1,2}
pattern ransomware_dag
    step bit=0 ops=exec ttps=T1059
    step bit=1 prereq=0 ops=read ttps=T1083
    step bit=2 prereq=0 ops=exec ttps=T1490
    step bit=3 prereq=1,2 ops=write ttps=T1486 action=disarm(write,exec)
end
";

    #[test]
    fn compiles_valid_dag() {
        let rules = compile_dag(DAG_OK).unwrap();
        let p = &rules.patterns[0];
        assert_eq!(p.name, "ransomware_dag");
        assert_eq!(p.steps.len(), 4);
        assert_eq!(p.steps[0].bit, 0);
        assert_eq!(p.steps[0].prereq_mask, 0); // gốc
        assert_eq!(p.steps[1].prereq_mask, 0b1); // cần bit 0
        assert_eq!(p.steps[3].prereq_mask, 0b110); // cần bit 1 và 2
        assert!(matches!(p.steps[3].action, Some(Action::Disarm(_))));
    }

    #[test]
    fn dag_roundtrips_through_wire() {
        let bytes = compile_dag_to_bytes(DAG_OK).unwrap();
        let rules = engine_core::wire::decode_dag(&bytes).unwrap();
        assert_eq!(rules.patterns[0].steps[3].prereq_mask, 0b110);
    }

    #[test]
    fn rejects_bad_dag() {
        assert!(compile_dag("pattern p\n step ops=exec\nend").is_err()); // thiếu bit=
        assert!(compile_dag("pattern p\n step bit=0\n step bit=0\nend").is_err()); // bit lặp
        assert!(compile_dag("pattern p\n step bit=1 prereq=0\nend").is_err()); // không có gốc
        assert!(compile_dag("pattern p\n step bit=0\n step bit=1 prereq=5\nend").is_err()); // prereq trỏ bit chưa khai
        // chu trình: bit1←bit2, bit2←bit1, không gốc
        assert!(compile_dag("pattern p\n step bit=0\n step bit=1 prereq=2\n step bit=2 prereq=1\nend").is_err());
    }
}
