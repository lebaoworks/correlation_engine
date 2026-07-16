//! Shared-memory transport from the SnsDrv sensor (`#[cfg(windows)]` only).
//!
//! Telemetry arrives through a lock-free ring the driver allocates from non-paged
//! pool and maps into this process (see [`crate::ringbuf`] for the layout and the
//! commit protocol). The minifilter port is still here, but only for the control
//! plane — registration and verdicts — which is a few messages a second against a
//! telemetry stream that never touches a syscall at all.
//!
//! ```text
//!   driver callback ── writes ──▶ ring slot ── reads ──▶ this module ──▶ engine
//!                          └─ doorbell (only when the consumer is asleep) ─┘
//!
//!   this module ── FilterSendMessage ──▶ driver     (register / verdict, rare)
//! ```
//!
//! Why the ring is not symmetric — why commands still go down as messages — is
//! covered in the design notes: the kernel has no thread waiting on a down-ring, so
//! one would have to be re-introduced, and it would add a thread hop to the verdict
//! path, which is the one path where a thread is blocked in the kernel waiting.
//!
//! This module is **not built or tested on non-Windows hosts**; the protocol it
//! speaks is, via `ringbuf`.

#![cfg(windows)]

use std::io;
use std::os::raw::c_void;

use crate::control;
use crate::ringbuf::{Consumer, Empty, Ring, DATA_OFFSET};
use crate::sensor;
use crate::source::EventSource;
use crate::winport::{
    CloseHandle, CreateEventW, FilterConnectCommunicationPort, FilterSendMessage, Handle,
    WaitForSingleObject,
};
use log::{debug, info, warn};

const INVALID_HANDLE: Handle = usize::MAX as Handle;

/// Data-region size. Must be a power of two, and the driver enforces its own bounds
/// on top of this. Non-paged pool is a finite machine-wide resource, so this buys
/// buffering (~10k events at ~100 bytes each) rather than being sized generously:
/// the consumer drains far faster than the sensor can fill, and a ring that is
/// chronically full means the engine is the bottleneck, not this number.
const RING_BYTES: u32 = 1 << 20; // 1 MiB

/// Busy-wait this many times before publishing SLEEPING and blocking. Under load
/// the next record lands within a few hundred cycles, so spinning here is what
/// keeps the doorbell — and therefore the kernel — out of the steady state.
const SPINS_BEFORE_SLEEP: u32 = 4_000;

/// Doorbell wait quantum. This is **not** a safety net for a missed wakeup (see the
/// fence discussion in `ringbuf`) — it exists because nothing signals us if the
/// driver unloads while we sleep, so we surface periodically to re-check that the
/// ring is still the ring we registered.
const DOORBELL_WAIT_MS: u32 = 500;

const WAIT_FAILED: u32 = 0xFFFF_FFFF;

pub struct RingSource {
    port: Handle,
    doorbell: Handle,
    consumer: Consumer,
    /// `ReqId` of the frame most recently handed out, for [`EventSource::reply`].
    last_req_id: u32,
    label: String,
}

impl RingSource {
    /// Connect to `port_name` (e.g. `\\SnsDrvPort`) and bring up the shared ring.
    pub fn connect(port_name: &str) -> io::Result<RingSource> {
        let wide: Vec<u16> = port_name.encode_utf16().chain(std::iter::once(0)).collect();
        let mut port: Handle = INVALID_HANDLE;
        debug!("[ring] FilterConnectCommunicationPort(\"{}\") ...", port_name);
        let hr = unsafe {
            FilterConnectCommunicationPort(
                wide.as_ptr(),
                0,
                std::ptr::null(),
                0,
                std::ptr::null(),
                &mut port,
            )
        };
        if hr < 0 {
            return Err(hresult("FilterConnectCommunicationPort", hr));
        }

        // Register our own pid first so the driver exempts it from enforcement: a
        // self-triggered sync-enforce would deadlock (see EnforcementPlane.md), and
        // everything below this line runs as that pid.
        debug!("[ring] registering self pid {} ...", std::process::id());
        send_control(port, &control::encode_set_self(std::process::id()), None).inspect_err(
            |_| unsafe {
                CloseHandle(port);
            },
        )?;

        // Auto-reset: if the driver rings the doorbell in the window between our
        // re-check and the wait, the signal must stick so the wait returns at once.
        let doorbell = unsafe { CreateEventW(std::ptr::null(), 0, 0, std::ptr::null()) };
        if doorbell.is_null() {
            unsafe { CloseHandle(port) };
            return Err(io::Error::new(io::ErrorKind::Other, "CreateEventW(doorbell) failed"));
        }

        let cleanup = |e: io::Error| {
            unsafe {
                CloseHandle(doorbell);
                CloseHandle(port);
            }
            e
        };

        // The driver allocates the ring and maps it into us, replying with the
        // mapped address. We never send an address down — the driver owning both
        // ends of the mapping is what keeps a compromised service from steering a
        // kernel write (see `ringbuf`'s safety invariant).
        debug!("[ring] C_REGISTER_RING {} bytes ...", RING_BYTES);
        let mut mapped: u64 = 0;
        let out = unsafe {
            std::slice::from_raw_parts_mut(&mut mapped as *mut u64 as *mut u8, size_of::<u64>())
        };
        let frame = control::encode_register_ring(RING_BYTES, doorbell as u64);
        let n = send_control(port, &frame, Some(out)).map_err(cleanup)?;
        if n as usize != size_of::<u64>() || mapped == 0 {
            return Err(cleanup(io::Error::new(
                io::ErrorKind::Other,
                format!("driver returned {} bytes / address {:#x} for the ring", n, mapped),
            )));
        }

        let len = DATA_OFFSET + RING_BYTES as usize;
        let ring = unsafe { Ring::from_raw(mapped as *mut u8, len) }
            .map_err(|e| cleanup(io::Error::new(io::ErrorKind::InvalidData, e)))?;
        info!("[ring] mapped at {:#x}, {} KiB data region", mapped, ring.data_size() / 1024);

        Ok(RingSource {
            port,
            doorbell,
            consumer: Consumer::new(ring),
            last_req_id: 0,
            label: port_name.to_string(),
        })
    }

    /// Block until a producer publishes, or until the wait quantum lapses.
    fn wait_doorbell(&mut self) {
        // Publish SLEEPING and re-check: `should_sleep` is the consumer half of the
        // Dekker pattern documented in `ringbuf`. If it says no, a record landed in
        // the window and blocking now would be the lost wakeup.
        if !self.consumer.should_sleep() {
            return;
        }
        let r = unsafe { WaitForSingleObject(self.doorbell, DOORBELL_WAIT_MS) };
        self.consumer.awake();
        if r == WAIT_FAILED {
            warn!("[ring] WaitForSingleObject(doorbell) failed; falling back to polling");
        }
    }
}

impl EventSource for RingSource {
    fn next_batch(&mut self) -> io::Result<Option<Vec<u8>>> {
        let mut spins = 0u32;
        loop {
            match self.consumer.next() {
                Ok(f) => {
                    // Copy out before advancing: past `advance` these bytes are
                    // fair game for producers. One ~100-byte memcpy per event, in
                    // exchange for the syscall and context switch this replaced.
                    let payload = self.consumer.bytes(f).to_vec();
                    self.consumer.advance(f);
                    self.last_req_id = sensor::req_id(&payload);
                    return Ok(Some(payload));
                }
                // A producer reserved this slot and is mid-write. It commits within
                // a few instructions, so never sleep on this — but do yield after a
                // while in case it was preempted holding the reservation.
                Err(Empty::Uncommitted) => {
                    spins += 1;
                    if spins % SPINS_BEFORE_SLEEP == 0 {
                        std::thread::yield_now();
                    } else {
                        std::hint::spin_loop();
                    }
                }
                Err(Empty::NoData) => {
                    if spins < SPINS_BEFORE_SLEEP {
                        spins += 1;
                        std::hint::spin_loop();
                    } else {
                        self.wait_doorbell();
                        spins = 0;
                    }
                }
            }
        }
    }

    fn reply(&mut self, deny: bool) -> io::Result<()> {
        // Answers the ring record tagged FRAME_REPLY_EXPECTED that `next_batch`
        // last handed out. The driver matches `req_id` to the thread it has blocked
        // and wakes it; this syscall is the whole cost of the enforcement path.
        send_control(self.port, &control::encode_verdict(self.last_req_id, deny), None)?;
        Ok(())
    }

    fn push_control(&mut self, frame: &[u8]) -> io::Result<()> {
        if frame.is_empty() {
            return Ok(());
        }
        send_control(self.port, frame, None)?;
        Ok(())
    }

    fn name(&self) -> &str {
        &self.label
    }
}

impl Drop for RingSource {
    fn drop(&mut self) {
        // Closing the port triggers the driver's disconnect notify, which unmaps and
        // frees the ring. Nothing here may touch the mapping afterwards.
        unsafe {
            CloseHandle(self.port);
            CloseHandle(self.doorbell);
        }
    }
}

/// One control message down to the driver, optionally collecting a reply.
/// Returns the number of bytes written into `out`.
fn send_control(port: Handle, frame: &[u8], out: Option<&mut [u8]>) -> io::Result<u32> {
    // Pass a real lpBytesReturned even when we expect no output: some fltlib builds
    // dereference it unconditionally, and a NULL there faults the caller
    // (0xC0000005) instead of returning an error.
    let mut bytes_returned: u32 = 0;
    let (out_ptr, out_len) = match out {
        Some(b) => (b.as_mut_ptr() as *mut c_void, b.len() as u32),
        None => (std::ptr::null_mut(), 0),
    };
    let hr = unsafe {
        FilterSendMessage(
            port,
            frame.as_ptr() as *const c_void,
            frame.len() as u32,
            out_ptr,
            out_len,
            &mut bytes_returned,
        )
    };
    if hr < 0 {
        return Err(hresult("FilterSendMessage", hr));
    }
    Ok(bytes_returned)
}

fn hresult(what: &str, hr: i32) -> io::Error {
    io::Error::new(io::ErrorKind::Other, format!("{} 0x{:08x}", what, hr))
}
