//! SnsDrv — kernel-mode EDR sensor (minifilter), in Rust.
//!
//! Rust port of `windows_driver2/SnsDrv` (C++), intended to eventually replace it.
//! It registers a minifilter and, on the first write to each handle, hands a
//! `FileWrite` event to the in-kernel detection engine seam (`engine::submit`). The
//! detection engine itself is being moved into the kernel; until it lands, `submit`
//! is a stub. The `\SnsDrvPort` control port is kept open but carries no commands.
//!
//! The process/thread/handle monitors are still TODO (see readme.md).
//!
//! Bring-up mirrors `Entry.cpp`'s `Driver`: `MiniFilter::Filter` → control `Port`.
//! Teardown is the reverse, driven by the minifilter unload callback.
//!
//! All kernel bindings come from `wdk-sys` (+ the `fltmgr` shim); the panic handler
//! from `wdk-panic`.
//!
//! # No heap
//!
//! This driver deliberately uses **no dynamic allocation** — there is no
//! `#[global_allocator]`. A kernel image must never bugcheck on out-of-memory, and
//! Rust's infallible `Box`/`Vec` do exactly that (`handle_alloc_error` diverges).
//! The only long-lived object, [`Driver`], is two pointers, so it lives in a static
//! slot. If a later phase needs heap, allocate with `ExAllocatePool2` (fallible,
//! returns null) or `Box::try_new_in` and handle the failure — never infallibly.

#![no_std]
#![allow(non_snake_case)]

use wdk_panic as _;

// `compiler_builtins`' libm references `fma`/`fmaf`, which the kernel image has no
// C math library to satisfy (we link `/NODEFAULTLIB`). The driver performs no
// floating-point work, so these are never actually called — providing the symbols
// only unblocks the linker. (A real FP path in the kernel would need
// KeSaveFloatingPointState anyway.)
#[no_mangle]
extern "C" fn fma(x: f64, y: f64, z: f64) -> f64 {
    x * y + z
}
#[no_mangle]
extern "C" fn fmaf(x: f32, y: f32, z: f32) -> f32 {
    x * y + z
}

mod engine;
mod event;
mod fltmgr;
mod log;
mod minifilter;
mod port;

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicPtr, Ordering};

use wdk_sys::{NTSTATUS, PDRIVER_OBJECT, UNICODE_STRING};

use crate::fltmgr::{PFLT_FILTER, STATUS_SUCCESS};
use minifilter::Filter;
use port::Port;

// ---- globals: reachable from the static extern callbacks --------------------

/// The FltMgr filter handle — the pre-write callback needs it to allocate its
/// stream-handle dedup context.
static GLOBAL_FILTER: AtomicPtr<core::ffi::c_void> = AtomicPtr::new(core::ptr::null_mut());

pub(crate) fn global_filter() -> PFLT_FILTER {
    GLOBAL_FILTER.load(Ordering::Acquire) as PFLT_FILTER
}
pub(crate) fn set_global_filter(f: PFLT_FILTER) {
    GLOBAL_FILTER.store(f as *mut core::ffi::c_void, Ordering::Release);
}

// ---- the driver singleton ---------------------------------------------------

/// Owns every component. Field order is the teardown order (Rust drops in
/// declaration order): the port first (stop accepting connections), then the filter
/// (its drop calls `FltUnregisterFilter`).
struct Driver {
    port: Option<Port>,
    filter: Option<Filter>,
}

impl Driver {
    fn new(driver: PDRIVER_OBJECT) -> Result<Driver, NTSTATUS> {
        // Minifilter — publishes GLOBAL_FILTER and starts filtering (callbacks can
        // fire from here on; the engine seam is always available).
        let filter = Filter::register(driver)?;

        // Control port (empty for now).
        let port = match Port::create(filter.handle()) {
            Ok(p) => p,
            Err(s) => {
                drop(filter); // unregister → no more callbacks
                return Err(s);
            }
        };

        Ok(Driver { port: Some(port), filter: Some(filter) })
    }
}

impl Drop for Driver {
    fn drop(&mut self) {
        drop(self.port.take()); // stop accepting connections
        drop(self.filter.take()); // FltUnregisterFilter
    }
}

/// The one long-lived instance, stored inline (no heap — see the module docs on why
/// the kernel must not allocate infallibly). Touched only by `DriverEntry` and the
/// unload callback, which never run concurrently, so plain interior mutability is
/// sound here.
struct DriverSlot(UnsafeCell<Option<Driver>>);
unsafe impl Sync for DriverSlot {}
static DRIVER: DriverSlot = DriverSlot(UnsafeCell::new(None));

/// Drop the driver singleton. Called from the minifilter unload callback.
pub(crate) fn teardown() {
    // SAFETY: the unload callback runs once, after `DriverEntry` has returned and
    // with no other accessor of the slot live.
    unsafe {
        (*DRIVER.0.get()).take();
    }
}

// ---- entry point ------------------------------------------------------------

/// `DriverEntry` — FltMgr locates this by name via the WDK link settings.
///
/// # Safety
/// Called by the kernel at `PASSIVE_LEVEL` with a valid driver object.
#[export_name = "DriverEntry"]
pub unsafe extern "C" fn driver_entry(
    driver: PDRIVER_OBJECT,
    _registry_path: *const UNICODE_STRING,
) -> NTSTATUS {
    kprint!("DriverEntry: initializing");
    match Driver::new(driver) {
        Ok(d) => {
            // SAFETY: DriverEntry runs once, before any unload; no concurrent access.
            *DRIVER.0.get() = Some(d);
            kprint!("DriverEntry: ready");
            STATUS_SUCCESS
        }
        Err(status) => {
            kprint!("DriverEntry: failed 0x{:08x}", status as u32);
            status
        }
    }
}
