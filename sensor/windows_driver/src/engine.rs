//! In-kernel detection engine — seam (stub for now).
//!
//! The sensor's callbacks funnel every observation through [`submit`]. Today that is
//! a placeholder: it traces the event and counts it. The real detection engine is
//! being moved into the kernel and will plug in **here** — `submit` is the single
//! choke point the rest of the driver depends on, so nothing else changes when the
//! engine lands (the callbacks never learn where the event goes).
//!
//! Keep `submit` cheap and non-blocking: it runs in filter/callback context at
//! IRQL <= APC_LEVEL, on the caller's hot path.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::event::Event;
use crate::kprint;

/// How many events the seam has seen. Cheap liveness signal until the engine lands.
static SEEN: AtomicU64 = AtomicU64::new(0);

/// Hand one observation to the engine. Stub: trace + count.
///
/// TODO(engine-in-kernel): replace the body with a call into the detection engine.
/// The `Event` borrows kernel memory (e.g. a `UNICODE_STRING` buffer) valid only for
/// this call — the engine must copy anything it needs to retain before returning.
pub fn submit(evt: &Event) {
    let n = SEEN.fetch_add(1, Ordering::Relaxed) + 1;
    kprint!("engine::submit #{} {} pid={}", n, evt.body.kind(), evt.actor.pid);
}
