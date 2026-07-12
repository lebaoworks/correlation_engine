//! Event sources feeding the service. Each yields raw **batch payloads** (the
//! `TotalSize`-prefixed frame the driver sends) and optionally accepts a per-batch
//! block decision to hand back to the sensor.

use std::collections::VecDeque;
use std::io::{self, Read};

pub trait EventSource {
    /// Next batch payload (starting with the `TotalSize` u32), or `None` at end.
    fn next_batch(&mut self) -> io::Result<Option<Vec<u8>>>;
    /// Return the batch's block decision to the sensor. No-op for read-only sources.
    fn reply(&mut self, _deny: bool) -> io::Result<()> {
        Ok(())
    }
    /// Push a control frame (ARM/DISARM/SetSelf records, see `control`) *down* to
    /// the sensor's arm table. No-op for sources that can't talk back (files/stdin).
    fn push_control(&mut self, _frame: &[u8]) -> io::Result<()> {
        Ok(())
    }
    fn name(&self) -> &str;
}

/// Reads self-framed batches from any byte stream (file / stdin). A batch is
/// `TotalSize:u32le` followed by `TotalSize - 4` more bytes.
pub struct ReaderSource<R: Read> {
    r: R,
    label: String,
}

impl<R: Read> ReaderSource<R> {
    pub fn new(r: R, label: impl Into<String>) -> ReaderSource<R> {
        ReaderSource { r, label: label.into() }
    }
}

impl<R: Read> EventSource for ReaderSource<R> {
    fn next_batch(&mut self) -> io::Result<Option<Vec<u8>>> {
        let mut hdr = [0u8; 4];
        match read_exact_or_eof(&mut self.r, &mut hdr)? {
            false => return Ok(None), // clean EOF at a batch boundary
            true => {}
        }
        let total = u32::from_le_bytes(hdr) as usize;
        if total < 4 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "batch TotalSize < 4"));
        }
        let mut buf = vec![0u8; total];
        buf[..4].copy_from_slice(&hdr);
        self.r.read_exact(&mut buf[4..])?;
        Ok(Some(buf))
    }
    fn name(&self) -> &str {
        &self.label
    }
}

/// In-memory batches (used by `--demo` and tests).
pub struct VecSource {
    batches: VecDeque<Vec<u8>>,
}

impl VecSource {
    pub fn new(batches: Vec<Vec<u8>>) -> VecSource {
        VecSource { batches: batches.into() }
    }
}

impl EventSource for VecSource {
    fn next_batch(&mut self) -> io::Result<Option<Vec<u8>>> {
        Ok(self.batches.pop_front())
    }
    fn name(&self) -> &str {
        "demo"
    }
}

/// Read exactly `buf.len()` bytes; returns `Ok(false)` if EOF happens *before any*
/// byte (a clean end), `Err` if EOF happens mid-frame.
fn read_exact_or_eof<R: Read>(r: &mut R, buf: &mut [u8]) -> io::Result<bool> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) => {
                if filled == 0 {
                    return Ok(false);
                }
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "partial batch header"));
            }
            Ok(n) => filled += n,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(true)
}
