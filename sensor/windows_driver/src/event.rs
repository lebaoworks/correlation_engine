//! Event domain model — what the callbacks hand to the in-kernel engine.
//!
//! Formerly `wire.rs` serialized these into the shared ring for the user-mode
//! service. That transport is gone: the detection engine is moving into the kernel,
//! so callbacks pass the `Event` **struct** straight to `engine::submit` (see
//! `engine.rs`). No byte serialization lives here anymore — the engine consumes the
//! typed value directly. String fields borrow UTF-16 already in kernel form (e.g. a
//! `UNICODE_STRING` buffer), so building an event allocates nothing.

/// A process identity: pid plus its creation FILETIME (defeats pid reuse).
#[derive(Clone, Copy)]
pub struct Actor {
    pub pid: u32,
    pub create_time: i64,
}

/// The type-specific part of an event.
pub enum Body<'a> {
    /// First write to a file on a handle — the enforceable chokepoint.
    FileWrite { name: &'a [u16] },
    /// File open (reserved; not emitted yet).
    FileOpen { name: &'a [u16] },
    /// Process exit — identity is entirely in the header fields.
    ProcessExit,
    /// Process create — `actor` is the **parent**; body carries the child.
    ProcessCreate { child: Actor, image: &'a [u16], cmdline: &'a [u16] },
    /// A handle opened to another process.
    ProcessOpen { target: Actor, desired_access: u32, image: &'a [u16] },
    /// A thread created in another process (classic injection).
    RemoteThreadCreate { target: Actor, thread_id: u32 },
}

impl Body<'_> {
    /// Short label for tracing.
    pub fn kind(&self) -> &'static str {
        match self {
            Body::FileWrite { .. } => "FileWrite",
            Body::FileOpen { .. } => "FileOpen",
            Body::ProcessExit => "ProcessExit",
            Body::ProcessCreate { .. } => "ProcessCreate",
            Body::ProcessOpen { .. } => "ProcessOpen",
            Body::RemoteThreadCreate { .. } => "RemoteThreadCreate",
        }
    }
}

/// One event. `actor` is the acting process (the parent, for `ProcessCreate`);
/// `timestamp` is a FILETIME (100-ns since 1601).
pub struct Event<'a> {
    pub timestamp: i64,
    pub actor: Actor,
    pub body: Body<'a>,
}
