//! Windows minifilter transport (`#[cfg(windows)]` only).
//!
//! Connects to the SnsDrv communication port (`\SnsDrvPort`), receives batches via
//! `FilterGetMessage`, and replies a 1-byte block decision via `FilterReplyMessage`.
//!
//! NOTE: the current driver sends notify-only (`FltSendMessage(..., NULL, 0, ...)`),
//! so replies are ignored until the driver is updated to request one (i.e. pass a
//! reply buffer and act on it in the pre-op callback). The reply path is implemented
//! here so it works the moment the driver opts in. This module is **not built or
//! tested on non-Windows hosts.**

#![cfg(windows)]

use std::io;
use std::os::raw::c_void;

use crate::source::EventSource;
use log::debug;

type Handle = *mut c_void;
const INVALID_HANDLE: Handle = usize::MAX as Handle;

// FILTER_MESSAGE_HEADER { ULONG ReplyLength; ULONGLONG MessageId; } -> 16 bytes (8-align).
const MSG_HEADER: usize = 16;
// Max payload we accept per message (matches driver SERIALIZED_BUFFER_SIZE 512 KB).
const BUF: usize = 512 * 1024 + MSG_HEADER;

#[link(name = "fltlib")]
extern "system" {
    fn FilterConnectCommunicationPort(
        lpPortName: *const u16,
        dwOptions: u32,
        lpContext: *const c_void,
        wSizeOfContext: u16,
        lpSecurityAttributes: *const c_void,
        hPort: *mut Handle,
    ) -> i32; // HRESULT
    fn FilterGetMessage(
        hPort: Handle,
        lpMessageBuffer: *mut c_void,
        dwMessageBufferSize: u32,
        lpOverlapped: *mut c_void,
    ) -> i32;
    fn FilterReplyMessage(hPort: Handle, lpReplyBuffer: *const c_void, dwReplyBufferSize: u32) -> i32;
    fn FilterSendMessage(
        hPort: Handle,
        lpInBuffer: *const c_void,
        dwInBufferSize: u32,
        lpOutBuffer: *mut c_void,
        dwOutBufferSize: u32,
        lpBytesReturned: *mut u32,
    ) -> i32; // HRESULT
}
#[link(name = "kernel32")]
extern "system" {
    fn CloseHandle(h: Handle) -> i32;
}

pub struct WinPortSource {
    port: Handle,
    buf: Vec<u8>,
    last_msg_id: u64,
    label: String,
}

impl WinPortSource {
    /// Connect to `port_name` (e.g. `\\SnsDrvPort`).
    pub fn connect(port_name: &str) -> io::Result<WinPortSource> {
        let wide: Vec<u16> = port_name.encode_utf16().chain(std::iter::once(0)).collect();
        let mut port: Handle = INVALID_HANDLE;
        // Progress markers on stderr (unbuffered) so if a FltMgr call faults the last
        // line printed pinpoints which one.
        debug!("[winport] FilterConnectCommunicationPort(\"{}\") ...", port_name);
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
            return Err(io::Error::new(io::ErrorKind::Other, format!("FilterConnectCommunicationPort 0x{:08x}", hr)));
        }
        debug!("[winport] port connected; registering self pid {} ...", std::process::id());
        let mut src = WinPortSource { port, buf: vec![0u8; BUF], last_msg_id: 0, label: port_name.to_string() };
        // Register our own pid so the driver exempts it from enforcement (a
        // self-triggered sync-enforce would deadlock — see EnforcementPlane.md).
        let self_frame = crate::control::encode_set_self(std::process::id());
        if let Err(e) = src.push_control(&self_frame) {
            return Err(io::Error::new(io::ErrorKind::Other, format!("register self pid: {}", e)));
        }
        debug!("[winport] self pid registered; ready");
        Ok(src)
    }
}

impl EventSource for WinPortSource {
    fn next_batch(&mut self) -> io::Result<Option<Vec<u8>>> {
        let hr = unsafe {
            FilterGetMessage(self.port, self.buf.as_mut_ptr() as *mut c_void, self.buf.len() as u32, std::ptr::null_mut())
        };
        if hr < 0 {
            return Err(io::Error::new(io::ErrorKind::Other, format!("FilterGetMessage 0x{:08x}", hr)));
        }
        // FILTER_MESSAGE_HEADER: MessageId at offset 8 (after ULONG ReplyLength + pad).
        self.last_msg_id = u64::from_le_bytes(self.buf[8..16].try_into().unwrap());
        // Payload begins right after the header and starts with our TotalSize field.
        let total = u32::from_le_bytes(self.buf[MSG_HEADER..MSG_HEADER + 4].try_into().unwrap()) as usize;
        let end = MSG_HEADER + total;
        Ok(Some(self.buf[MSG_HEADER..end].to_vec()))
    }

    fn reply(&mut self, deny: bool) -> io::Result<()> {
        // FILTER_REPLY_HEADER { HRESULT Status; ULONGLONG MessageId; } (16 bytes) + 1 decision byte.
        let mut reply = [0u8; MSG_HEADER + 1];
        reply[0..4].copy_from_slice(&0i32.to_le_bytes()); // Status = STATUS_SUCCESS
        reply[8..16].copy_from_slice(&self.last_msg_id.to_le_bytes());
        reply[16] = if deny { 1 } else { 0 };
        let hr = unsafe { FilterReplyMessage(self.port, reply.as_ptr() as *const c_void, reply.len() as u32) };
        if hr < 0 {
            return Err(io::Error::new(io::ErrorKind::Other, format!("FilterReplyMessage 0x{:08x}", hr)));
        }
        Ok(())
    }

    fn push_control(&mut self, frame: &[u8]) -> io::Result<()> {
        if frame.is_empty() {
            return Ok(());
        }
        // Unsolicited user→kernel message; handled by the driver's MessageNotifyCallback.
        // Pass a real lpBytesReturned even though we expect no output: some fltlib
        // builds dereference it unconditionally, and a NULL there faults the caller
        // (0xC0000005) instead of returning an error.
        let mut bytes_returned: u32 = 0;
        let hr = unsafe {
            FilterSendMessage(
                self.port,
                frame.as_ptr() as *const c_void,
                frame.len() as u32,
                std::ptr::null_mut(),
                0,
                &mut bytes_returned,
            )
        };
        if hr < 0 {
            return Err(io::Error::new(io::ErrorKind::Other, format!("FilterSendMessage 0x{:08x}", hr)));
        }
        Ok(())
    }

    fn name(&self) -> &str {
        &self.label
    }
}

impl Drop for WinPortSource {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.port);
        }
    }
}
