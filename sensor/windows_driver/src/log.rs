//! Minimal kernel tracing — a stand-in for the C++ side's WPP.
//!
//! WPP needs an ETW manifest and the tracing preprocessor; for this port a plain
//! `DbgPrintEx` line (visible in WinDbg / DebugView) is enough. `kprint!` formats
//! into a fixed stack buffer — no allocation, callable at DISPATCH_LEVEL — and is a
//! no-op string on overflow rather than a panic.

use core::ffi::c_char;
use core::fmt::{self, Write};

use wdk_sys::ntddk::DbgPrintEx;

// DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL — a driver-owned channel that shows by
// default under a kernel debugger.
const COMPONENT_ID: u32 = 77;
const LEVEL: u32 = 0;

/// A `core::fmt::Write` sink over a fixed stack buffer, always NUL-terminated.
pub struct StackFmt {
    buf: [u8; 256],
    len: usize,
}

impl StackFmt {
    pub const fn new() -> Self {
        StackFmt { buf: [0; 256], len: 0 }
    }
    pub fn as_ptr(&self) -> *const c_char {
        self.buf.as_ptr() as *const c_char
    }
}

impl Write for StackFmt {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let bytes = s.as_bytes();
        // Leave room for the trailing NUL; silently truncate past that.
        let room = self.buf.len().saturating_sub(self.len + 1);
        let n = bytes.len().min(room);
        self.buf[self.len..self.len + n].copy_from_slice(&bytes[..n]);
        self.len += n;
        self.buf[self.len] = 0;
        Ok(())
    }
}

/// Emit one debugger line. Prefer the `kprint!` macro.
pub fn emit(args: fmt::Arguments) {
    let mut w = StackFmt::new();
    let _ = w.write_fmt(args);
    unsafe {
        DbgPrintEx(COMPONENT_ID, LEVEL, b"SnsDrv: %s\n\0".as_ptr() as *const c_char, w.as_ptr());
    }
}

#[macro_export]
macro_rules! kprint {
    ($($arg:tt)*) => { $crate::log::emit(format_args!($($arg)*)) };
}
