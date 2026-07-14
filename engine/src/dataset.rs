//! Tiny hand-written loader for `.evt` datasets (no serde dependency).
//!
//! One event per line, `key=value` tokens, values may be double-quoted:
//!
//! ```text
//! ts=1000 op=exec actor=100.1 object=proc:200.1 image=C:\Win\powershell.exe cmd="-enc ..."
//! ```
//!
//! Structural keys: ts, op, actor, object, image. Everything else → attrs.
//!  * actor  : always a process, `<pid>.<start_ts>`
//!  * object : `proc:<pid>.<start>` | `file:<FileId>` | `sock:<key>`
//!  * image  : a File identity token for exec (kept in attrs["image"])

use crate::event::{Attrs, Event, NodeKey, Op};

pub fn parse_str(input: &str) -> Result<Vec<Event>, String> {
    let mut events = Vec::new();
    for (lineno, raw) in input.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        events.push(parse_line(line).map_err(|e| format!("line {}: {}", lineno + 1, e))?);
    }
    Ok(events)
}

fn parse_line(line: &str) -> Result<Event, String> {
    let toks = tokenize(line);
    let mut ts = None;
    let mut op = None;
    let mut actor = None;
    let mut object = None;
    let mut attrs = Attrs::default();

    for (k, v) in toks {
        match k.as_str() {
            "ts" => ts = Some(v.parse::<u64>().map_err(|_| "bad ts")?),
            "op" => op = Some(Op::parse(&v).ok_or_else(|| format!("bad op '{}'", v))?),
            "actor" => actor = Some(parse_process(&v)?),
            "object" => object = Some(parse_object(&v)?),
            _ => attrs.set(&k, v),
        }
    }

    Ok(Event {
        ts: ts.ok_or("missing ts")?,
        op: op.ok_or("missing op")?,
        actor: actor.ok_or("missing actor")?,
        object: object.ok_or("missing object")?,
        attrs,
    })
}

fn parse_process(v: &str) -> Result<NodeKey, String> {
    let (pid, start) = v.split_once('.').ok_or("process must be pid.start")?;
    Ok(NodeKey::Process {
        pid: pid.parse().map_err(|_| "bad pid")?,
        start_ts: start.parse().map_err(|_| "bad start_ts")?,
    })
}

fn parse_object(v: &str) -> Result<NodeKey, String> {
    let (kind, rest) = v.split_once(':').ok_or("object must be kind:key")?;
    match kind {
        "proc" => parse_process(rest),
        "file" => Ok(NodeKey::File { file_id: rest.to_string() }),
        "sock" => Ok(NodeKey::Socket { key: rest.to_string() }),
        other => Ok(NodeKey::Other { kind: other.to_string(), key: rest.to_string() }),
    }
}

/// Split into `key=value` pairs, honoring double quotes around values.
fn tokenize(line: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut chars = line.chars().peekable();
    while chars.peek().is_some() {
        // skip spaces
        while matches!(chars.peek(), Some(' ') | Some('\t')) {
            chars.next();
        }
        let mut key = String::new();
        while let Some(&c) = chars.peek() {
            if c == '=' {
                break;
            }
            key.push(c);
            chars.next();
        }
        if chars.peek() == Some(&'=') {
            chars.next(); // consume '='
        }
        let mut val = String::new();
        if chars.peek() == Some(&'"') {
            chars.next(); // opening quote
            while let Some(&c) = chars.peek() {
                chars.next();
                if c == '"' {
                    break;
                }
                val.push(c);
            }
        } else {
            while let Some(&c) = chars.peek() {
                if c == ' ' || c == '\t' {
                    break;
                }
                val.push(c);
                chars.next();
            }
        }
        if !key.is_empty() {
            out.push((key, val));
        }
    }
    out
}
