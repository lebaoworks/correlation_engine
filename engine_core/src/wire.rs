//! Wire format cho ruleset đã compile — kênh giao rule từ `engine_rules`
//! (usermode) xuống engine chạy ở nơi khác (kernel mode, process khác…).
//!
//! Định dạng phẳng, little-endian, version hoá bằng magic:
//!
//! ```text
//! b"ERL1"
//! u16 pattern_count
//!   per pattern: u16 name_len, name (utf8), u16 step_count
//!     per step:  u32 ops_mask, u8 ttp_count, u32 ttp[..],
//!                u8 action (0=không có 1=block 2=disarm),
//!                u32 disarm_mask (chỉ khi action == 2)
//! ```

use alloc::string::String;
use alloc::vec::Vec;

use crate::event::{OpSet, Ttp};
use crate::rules::{Action, Pattern, RuleSet, Step, StepMatch};

pub const MAGIC: &[u8; 4] = b"ERL1";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WireError {
    BadMagic,
    Truncated,
    BadUtf8,
    BadAction(u8),
    TrailingBytes,
}

pub fn encode(rules: &RuleSet) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&(rules.patterns.len() as u16).to_le_bytes());
    for p in &rules.patterns {
        out.extend_from_slice(&(p.name.len() as u16).to_le_bytes());
        out.extend_from_slice(p.name.as_bytes());
        out.extend_from_slice(&(p.steps.len() as u16).to_le_bytes());
        for s in &p.steps {
            out.extend_from_slice(&s.matcher.ops.0.to_le_bytes());
            out.push(s.matcher.ttps.len() as u8);
            for t in &s.matcher.ttps {
                out.extend_from_slice(&t.0.to_le_bytes());
            }
            match s.action {
                None => out.push(0),
                Some(Action::Block) => out.push(1),
                Some(Action::Disarm(ops)) => {
                    out.push(2);
                    out.extend_from_slice(&ops.0.to_le_bytes());
                }
            }
        }
    }
    out
}

pub fn decode(bytes: &[u8]) -> Result<RuleSet, WireError> {
    let mut r = Reader { bytes, pos: 0 };
    if r.take(4)? != MAGIC {
        return Err(WireError::BadMagic);
    }
    let pattern_count = r.u16()?;
    let mut patterns = Vec::with_capacity(pattern_count as usize);
    for _ in 0..pattern_count {
        let name_len = r.u16()? as usize;
        let name = core::str::from_utf8(r.take(name_len)?)
            .map_err(|_| WireError::BadUtf8)?;
        let step_count = r.u16()?;
        let mut steps = Vec::with_capacity(step_count as usize);
        for _ in 0..step_count {
            let ops = OpSet(r.u32()?);
            let ttp_count = r.u8()?;
            let mut ttps = Vec::with_capacity(ttp_count as usize);
            for _ in 0..ttp_count {
                ttps.push(Ttp(r.u32()?));
            }
            let action = match r.u8()? {
                0 => None,
                1 => Some(Action::Block),
                2 => Some(Action::Disarm(OpSet(r.u32()?))),
                other => return Err(WireError::BadAction(other)),
            };
            steps.push(Step { matcher: StepMatch { ops, ttps }, action });
        }
        patterns.push(Pattern { name: String::from(name), steps });
    }
    if r.pos != bytes.len() {
        return Err(WireError::TrailingBytes);
    }
    Ok(RuleSet { patterns })
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        let end = self.pos.checked_add(n).ok_or(WireError::Truncated)?;
        if end > self.bytes.len() {
            return Err(WireError::Truncated);
        }
        let out = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, WireError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, WireError> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }

    fn u32(&mut self) -> Result<u32, WireError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Op;
    use alloc::string::ToString;
    use alloc::vec;

    #[test]
    fn roundtrip() {
        let rules = RuleSet {
            patterns: vec![Pattern {
                name: "demo".to_string(),
                steps: vec![
                    Step {
                        matcher: StepMatch {
                            ops: OpSet::single(Op::Exec),
                            ttps: vec![Ttp(1059)],
                        },
                        action: None,
                    },
                    Step {
                        matcher: StepMatch { ops: OpSet::EMPTY, ttps: vec![] },
                        action: Some(Action::Disarm(
                            OpSet::single(Op::Write).union(OpSet::single(Op::Exec)),
                        )),
                    },
                ],
            }],
        };
        let bytes = encode(&rules);
        let back = decode(&bytes).unwrap();
        assert_eq!(back.patterns.len(), 1);
        assert_eq!(back.patterns[0].name, "demo");
        assert_eq!(back.patterns[0].steps.len(), 2);
        assert_eq!(back.patterns[0].steps[0].matcher.ttps, vec![Ttp(1059)]);
        assert!(back.patterns[0].steps[0].action.is_none());
        assert!(matches!(back.patterns[0].steps[1].action, Some(Action::Disarm(ops)) if ops.contains(Op::Write) && ops.contains(Op::Exec)));
    }

    #[test]
    fn rejects_garbage() {
        assert!(matches!(decode(b"XX"), Err(WireError::Truncated)));
        assert!(matches!(decode(b"XXXX\x00\x00"), Err(WireError::BadMagic)));
        let mut bytes = encode(&RuleSet::default());
        bytes.push(0);
        assert!(matches!(decode(&bytes), Err(WireError::TrailingBytes)));
    }
}
