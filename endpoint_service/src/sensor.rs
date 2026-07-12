//! Wire format v2 of the kernel sensor (SnsDrv minifilter) — engine-ready records.
//!
//! Mirrors `sensor/windows_driver/SnsDrv/Event.hpp` (`Event::Wire`) and
//! `Worker.cpp` (frame `Header`). Designed so the inline path service→engine is
//! near-free: numeric fields sit at fixed, naturally aligned offsets; every
//! record carries the full engine identity `(pid, create_time)` for actor *and*
//! target (no pid→start-time table needed); records are `Size`-prefixed and
//! padded to 8 bytes so unknown types are skipped, not fatal.
//!
//! The driver ships every event **immediately as it occurs** (no batching, so
//! detection latency is one queue hop): one port message = one frame carrying
//! one record (`Count` = 1). The format still allows several records per frame;
//! the parser handles both (replay files may pack many records into one frame).
//!
//! ```text
//! frame  = TotalSize:u32le (incl. this 8-byte header) ++ Version:u16le(=2)
//!          ++ Count:u16le ++ records...
//! record = Size:u32le (incl. 32-byte header, multiple of 8)
//!          ++ Type:u8 ++ pad[3]
//!          ++ TimeStamp:i64le (FILETIME, 100-ns since 1601)
//!          ++ Pid:u32le ++ pad[4] ++ PidCreateTime:i64le      <- acting identity
//!          ++ type-specific body (fixed) ++ strings ++ pad to 8
//! string = Length:u16le (bytes) ++ Buffer (UTF-16LE)
//! ```
//!
//! Per-type body at offset 32 (see `Event.hpp` for the authoritative tables):
//! * `FileOpen`          — strings: FileName  (capture disabled for now)
//! * `FileWrite`         — strings: FileName  (first write per handle → Op::Write)
//! * `ProcessCreate`     — ChildPid:u32 pad:u32 ChildCreateTime:i64; strings: Image, CommandLine
//!                         (header identity = the PARENT process)
//! * `ProcessExit`       — none
//! * `ProcessOpen`       — TargetPid:u32 DesiredAccess:u32 TargetCreateTime:i64; strings: TargetImage
//! * `ProcessExist`      — strings: Image
//! * `RemoteThreadCreate`— TargetPid:u32 ThreadId:u32 TargetCreateTime:i64
//!
//! This module both **decodes** frames coming from the driver and **encodes**
//! them (used by `--demo` and the tests, and documents the exact byte layout).

pub const WIRE_VERSION: u16 = 2;
pub const BATCH_HEADER: usize = 8;
pub const RECORD_HEADER: usize = 32;

/// High bit of the frame `Count` field: the driver sent this frame on the
/// synchronous enforcement path and is blocked waiting for a verdict reply. The
/// service must call `reply()` for it; async telemetry frames (bit clear) need
/// no reply. The low 15 bits hold the real record count.
pub const FRAME_REPLY_EXPECTED: u16 = 0x8000;
const COUNT_MASK: u16 = 0x7fff;

pub const T_FILE_OPEN: u8 = 1;
pub const T_FILE_WRITE: u8 = 2;
pub const T_PROCESS_CREATE: u8 = 100;
pub const T_PROCESS_EXIT: u8 = 101;
pub const T_PROCESS_OPEN: u8 = 102;
pub const T_PROCESS_EXIST: u8 = 103;
pub const T_REMOTE_THREAD_CREATE: u8 = 104;

/// A decoded sensor record. Times are raw FILETIME (100-ns intervals since 1601).
/// `pid`/`pid_start` is the acting process identity; targets carry their own.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SensorEvent {
    FileOpen { ts: i64, pid: u32, pid_start: i64, file_name: String },
    /// First write to a file by this process (one per handle). Maps to `Op::Write`.
    FileWrite { ts: i64, pid: u32, pid_start: i64, file_name: String },
    /// `pid`/`pid_start` = the PARENT; the child is `child_pid`/`child_start` (= `ts`).
    ProcessCreate {
        ts: i64,
        pid: u32,
        pid_start: i64,
        child_pid: u32,
        child_start: i64,
        image: String,
        cmdline: String,
    },
    ProcessExit { ts: i64, pid: u32, pid_start: i64 },
    ProcessOpen {
        ts: i64,
        pid: u32,
        pid_start: i64,
        target_pid: u32,
        target_start: i64,
        desired_access: u32,
        target_image: String,
    },
    ProcessExist { ts: i64, pid: u32, pid_start: i64, image: String },
    RemoteThreadCreate {
        ts: i64,
        pid: u32,
        pid_start: i64,
        target_pid: u32,
        target_start: i64,
        thread_id: u32,
    },
}

// ---- decode -----------------------------------------------------------------

/// Parse a whole batch payload (starting at the batch header) into events.
/// Records of unknown type are skipped (forward compatibility).
pub fn parse_batch(payload: &[u8]) -> Result<Vec<SensorEvent>, String> {
    if payload.len() < BATCH_HEADER {
        return Err(format!("batch too short: {} bytes", payload.len()));
    }
    let total = u32_at(payload, 0) as usize;
    let version = u16_at(payload, 4);
    let count = (u16_at(payload, 6) & COUNT_MASK) as usize;
    if version != WIRE_VERSION {
        return Err(format!("unsupported wire version {} (want {})", version, WIRE_VERSION));
    }
    if total < BATCH_HEADER || total > payload.len() {
        return Err(format!("bad batch TotalSize {} (payload {} bytes)", total, payload.len()));
    }

    let mut out = Vec::with_capacity(count);
    let mut off = BATCH_HEADER;
    while off < total {
        if off + RECORD_HEADER > total {
            return Err(format!("truncated record header at offset {}", off));
        }
        let size = u32_at(payload, off) as usize;
        if size < RECORD_HEADER || size % 8 != 0 || off + size > total {
            return Err(format!("bad record Size {} at offset {}", size, off));
        }
        if let Some(ev) = decode_record(&payload[off..off + size])? {
            out.push(ev);
        }
        off += size;
    }
    Ok(out)
}

/// Decode one record (`rec` spans exactly `Size` bytes). Numeric fields are read
/// at fixed offsets; only strings need a walk. `Ok(None)` = unknown type, skip.
fn decode_record(rec: &[u8]) -> Result<Option<SensorEvent>, String> {
    let ty = rec[4];
    let ts = i64_at(rec, 8);
    let pid = u32_at(rec, 16);
    let pid_start = i64_at(rec, 24);
    let body = RECORD_HEADER;

    Ok(Some(match ty {
        T_FILE_OPEN => {
            let (file_name, _) = wstr_at(rec, body)?;
            SensorEvent::FileOpen { ts, pid, pid_start, file_name }
        }
        T_FILE_WRITE => {
            let (file_name, _) = wstr_at(rec, body)?;
            SensorEvent::FileWrite { ts, pid, pid_start, file_name }
        }
        T_PROCESS_CREATE => {
            let (image, next) = wstr_at(rec, body + 16)?;
            let (cmdline, _) = wstr_at(rec, next)?;
            SensorEvent::ProcessCreate {
                ts,
                pid,
                pid_start,
                child_pid: u32_at(rec, body),
                child_start: i64_at(rec, body + 8),
                image,
                cmdline,
            }
        }
        T_PROCESS_EXIT => SensorEvent::ProcessExit { ts, pid, pid_start },
        T_PROCESS_OPEN => {
            let (target_image, _) = wstr_at(rec, body + 16)?;
            SensorEvent::ProcessOpen {
                ts,
                pid,
                pid_start,
                target_pid: u32_at(rec, body),
                target_start: i64_at(rec, body + 8),
                desired_access: u32_at(rec, body + 4),
                target_image,
            }
        }
        T_PROCESS_EXIST => {
            let (image, _) = wstr_at(rec, body)?;
            SensorEvent::ProcessExist { ts, pid, pid_start, image }
        }
        T_REMOTE_THREAD_CREATE => SensorEvent::RemoteThreadCreate {
            ts,
            pid,
            pid_start,
            target_pid: u32_at(rec, body),
            target_start: i64_at(rec, body + 8),
            thread_id: u32_at(rec, body + 4),
        },
        _ => return Ok(None), // unknown type: Size lets us skip it
    }))
}

fn u16_at(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(b[off..off + 2].try_into().unwrap())
}
fn u32_at(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
}
fn i64_at(b: &[u8], off: usize) -> i64 {
    i64::from_le_bytes(b[off..off + 8].try_into().unwrap())
}

/// Length-prefixed UTF-16LE string at `off`; returns the string and the offset
/// just past it.
fn wstr_at(b: &[u8], off: usize) -> Result<(String, usize), String> {
    if off + 2 > b.len() {
        return Err(format!("truncated string length at offset {}", off));
    }
    let len = u16_at(b, off) as usize;
    if len % 2 != 0 {
        return Err(format!("odd string length {}", len));
    }
    let start = off + 2;
    if start + len > b.len() {
        return Err(format!("truncated string ({} bytes) at offset {}", len, start));
    }
    let units: Vec<u16> =
        b[start..start + len].chunks_exact(2).map(|p| u16::from_le_bytes([p[0], p[1]])).collect();
    Ok((String::from_utf16_lossy(&units), start + len))
}

// ---- encode (demo + tests; documents the layout) ----------------------------

fn push_wstr(v: &mut Vec<u8>, s: &str) {
    let w: Vec<u8> = s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    v.extend_from_slice(&(w.len() as u16).to_le_bytes());
    v.extend_from_slice(&w);
}

/// Common record header; the final Size is patched in by `finish`.
fn header(ty: u8, ts: i64, pid: u32, pid_start: i64) -> Vec<u8> {
    let mut v = Vec::with_capacity(RECORD_HEADER + 64);
    v.extend_from_slice(&0u32.to_le_bytes()); // Size placeholder
    v.push(ty);
    v.extend_from_slice(&[0u8; 3]);
    v.extend_from_slice(&ts.to_le_bytes());
    v.extend_from_slice(&pid.to_le_bytes());
    v.extend_from_slice(&[0u8; 4]);
    v.extend_from_slice(&pid_start.to_le_bytes());
    v
}

/// Pad to a multiple of 8 and write the record Size.
fn finish(mut v: Vec<u8>) -> Vec<u8> {
    while v.len() % 8 != 0 {
        v.push(0);
    }
    let size = (v.len() as u32).to_le_bytes();
    v[..4].copy_from_slice(&size);
    v
}

pub fn enc_file_open(ts: i64, pid: u32, pid_start: i64, file: &str) -> Vec<u8> {
    let mut v = header(T_FILE_OPEN, ts, pid, pid_start);
    push_wstr(&mut v, file);
    finish(v)
}
pub fn enc_file_write(ts: i64, pid: u32, pid_start: i64, file: &str) -> Vec<u8> {
    let mut v = header(T_FILE_WRITE, ts, pid, pid_start);
    push_wstr(&mut v, file);
    finish(v)
}
/// `ppid`/`ppid_start` = parent (the acting identity); the child's create time is `ts`.
pub fn enc_process_create(
    ts: i64,
    pid: u32,
    ppid: u32,
    ppid_start: i64,
    image: &str,
    cmd: &str,
) -> Vec<u8> {
    let mut v = header(T_PROCESS_CREATE, ts, ppid, ppid_start);
    v.extend_from_slice(&pid.to_le_bytes());
    v.extend_from_slice(&[0u8; 4]);
    v.extend_from_slice(&ts.to_le_bytes()); // ChildCreateTime == TimeStamp
    push_wstr(&mut v, image);
    push_wstr(&mut v, cmd);
    finish(v)
}
pub fn enc_process_exit(ts: i64, pid: u32, pid_start: i64) -> Vec<u8> {
    finish(header(T_PROCESS_EXIT, ts, pid, pid_start))
}
pub fn enc_process_open(
    ts: i64,
    pid: u32,
    pid_start: i64,
    target_pid: u32,
    target_start: i64,
    access: u32,
    target_image: &str,
) -> Vec<u8> {
    let mut v = header(T_PROCESS_OPEN, ts, pid, pid_start);
    v.extend_from_slice(&target_pid.to_le_bytes());
    v.extend_from_slice(&access.to_le_bytes());
    v.extend_from_slice(&target_start.to_le_bytes());
    push_wstr(&mut v, target_image);
    finish(v)
}
pub fn enc_process_exist(ts: i64, pid: u32, creation: i64, image: &str) -> Vec<u8> {
    let mut v = header(T_PROCESS_EXIST, ts, pid, creation);
    push_wstr(&mut v, image);
    finish(v)
}
pub fn enc_remote_thread(
    ts: i64,
    pid: u32,
    pid_start: i64,
    target_pid: u32,
    target_start: i64,
    thread_id: u32,
) -> Vec<u8> {
    let mut v = header(T_REMOTE_THREAD_CREATE, ts, pid, pid_start);
    v.extend_from_slice(&target_pid.to_le_bytes());
    v.extend_from_slice(&thread_id.to_le_bytes());
    v.extend_from_slice(&target_start.to_le_bytes());
    finish(v)
}

/// Does this frame want a verdict reply (was it sent on the enforcement path)?
pub fn expects_reply(payload: &[u8]) -> bool {
    payload.len() >= BATCH_HEADER && (u16_at(payload, 6) & FRAME_REPLY_EXPECTED) != 0
}

/// Wrap serialized records into one telemetry frame (async, no reply expected).
pub fn build_batch(events: &[Vec<u8>]) -> Vec<u8> {
    build_frame(events, false)
}

/// Wrap serialized records into one frame, tagging whether a verdict reply is
/// expected (the driver sets this for synchronous enforcement frames).
pub fn build_frame(events: &[Vec<u8>], reply_expected: bool) -> Vec<u8> {
    let total: usize = BATCH_HEADER + events.iter().map(|e| e.len()).sum::<usize>();
    let mut count = events.len() as u16 & COUNT_MASK;
    if reply_expected {
        count |= FRAME_REPLY_EXPECTED;
    }
    let mut v = Vec::with_capacity(total);
    v.extend_from_slice(&(total as u32).to_le_bytes());
    v.extend_from_slice(&WIRE_VERSION.to_le_bytes());
    v.extend_from_slice(&count.to_le_bytes());
    for e in events {
        v.extend_from_slice(e);
    }
    v
}
