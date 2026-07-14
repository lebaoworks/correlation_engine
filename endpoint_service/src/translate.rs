//! Translate decoded sensor events into normalized engine events (engine.md §0/§2).
//!
//! With wire format v2 this is a pure 1:1 field mapping: every sensor record
//! already carries the engine identity `(pid, create_time)` for actor and
//! target, and `ProcessOpen` carries the target image inline — no process
//! table, no lookups, no state. The only real work left is the FILETIME→ms
//! conversion and building the (small) attr map the engine API expects.

use edr_engine::event::{Attrs, Event, NodeKey, Op};

use crate::sensor::SensorEvent;

/// PROCESS_VM_READ — the access right that makes an LSASS handle a credential-dump.
const PROCESS_VM_READ: u32 = 0x0010;

/// FILETIME (100-ns since 1601) -> engine milliseconds (monotone, deltas preserved).
fn ms(ts: i64) -> u64 {
    (ts.max(0) / 10_000) as u64
}

fn proc(pid: u32, start: i64) -> NodeKey {
    NodeKey::Process { pid, start_ts: ms(start) }
}

fn ev(ts: u64, op: Op, actor: NodeKey, object: NodeKey, attrs: Attrs) -> Event {
    Event { ts, op, actor, object, attrs }
}

/// Map one sensor event to an engine event, **consuming** the record so the
/// decoded strings move straight into the engine `Event` — no second copy (the
/// decode in `sensor::parse_batch` already allocated them once). Returns `None`
/// for records the engine has no op for (process enumeration / exit).
pub fn to_engine_event(se: SensorEvent) -> Option<Event> {
    match se {
        SensorEvent::ProcessExist { .. } | SensorEvent::ProcessExit { .. } => None,

        SensorEvent::ProcessCreate { ts, pid, pid_start, child_pid, child_start, image, cmdline } => {
            Some(ev(
                ms(ts),
                Op::Exec,
                proc(pid, pid_start),
                proc(child_pid, child_start),
                Attrs { image: Some(image), cmd: Some(cmdline), ..Default::default() },
            ))
        }

        SensorEvent::FileOpen { ts, pid, pid_start, file_name } => Some(ev(
            ms(ts),
            Op::Open,
            proc(pid, pid_start),
            // File identity token: the path stands in for a FileId here (engine.md §2
            // wants a real FileId; the current sensor only reports the name).
            NodeKey::File { file_id: file_name },
            Attrs::default(),
        )),

        // First write to a file → Op::Write (dropper "write then exec", ransomware
        // write rate/spread). Entropy / PE-ness enrichment is future work, so no
        // `entropy`/`pe` attrs yet; the raw write still drives rate/spread + arming.
        SensorEvent::FileWrite { ts, pid, pid_start, file_name } => Some(ev(
            ms(ts),
            Op::Write,
            proc(pid, pid_start),
            NodeKey::File { file_id: file_name },
            Attrs::default(),
        )),

        SensorEvent::ProcessOpen { ts, pid, pid_start, target_pid, target_start, desired_access, target_image } => {
            let mut attrs = Attrs::default();
            if !target_image.is_empty() {
                attrs.target_image = Some(target_image);
            }
            if desired_access & PROCESS_VM_READ != 0 {
                attrs.vm_read = true;
            }
            Some(ev(
                ms(ts),
                Op::Read,
                proc(pid, pid_start),
                proc(target_pid, target_start),
                attrs,
            ))
        }

        SensorEvent::RemoteThreadCreate { ts, pid, pid_start, target_pid, target_start, .. } => Some(ev(
            ms(ts),
            Op::Inject,
            proc(pid, pid_start),
            proc(target_pid, target_start),
            Attrs::default(),
        )),
    }
}
