//! Minifilter registration + the first-write chokepoint.
//!
//! Rust twin of `windows_driver2/SnsDrv/MiniFilter.cpp` (the filter half; the empty
//! control port lives in `port.rs`). We register a single pre-operation callback on
//! `IRP_MJ_WRITE` and hand a `FileWrite` event to the in-kernel engine (`engine::
//! submit`) the **first** time a handle is written, deduplicated with a stream-handle
//! context so a busy writer produces one event, not one per buffer.
//!
//! All kernel/FltMgr types and functions come from `wdk-sys`.

use core::ffi::c_void;
use core::ptr;

use wdk_sys::ntddk::{
    KeQuerySystemTimePrecise, PsGetCurrentProcessId, PsGetProcessCreateTimeQuadPart,
};
use wdk_sys::{NTSTATUS, PDRIVER_OBJECT, PFILE_OBJECT, UNICODE_STRING};

use crate::event::{Actor, Body, Event};
// FltMgr surface — the one API wdk-sys does not provide (see fltmgr.rs).
use crate::fltmgr::{
    FltAllocateContext, FltGetFileNameInformation, FltGetStreamHandleContext,
    FltParseFileNameInformation, FltRegisterFilter, FltReleaseContext,
    FltReleaseFileNameInformation, FltSetStreamHandleContext, FltStartFiltering,
    FltUnregisterFilter, IoGetCurrentProcess, FLT_CONTEXT_END, FLT_CONTEXT_REGISTRATION,
    FLT_FILE_NAME_INFORMATION, FLT_FILE_NAME_NORMALIZED, FLT_FILE_NAME_QUERY_DEFAULT,
    FLT_OPERATION_REGISTRATION, FLT_PREOP_CALLBACK_STATUS, FLT_PREOP_SUCCESS_NO_CALLBACK,
    FLT_REGISTRATION, FLT_REGISTRATION_VERSION, FLT_SET_CONTEXT_KEEP_IF_EXISTS,
    FLT_STREAMHANDLE_CONTEXT, IRP_MJ_OPERATION_END, IRP_MJ_WRITE, NON_PAGED_POOL_NX,
    PCFLT_RELATED_OBJECTS, PFLT_CALLBACK_DATA, PFLT_CONTEXT, PFLT_FILTER, PFLT_INSTANCE,
    STATUS_SUCCESS,
};

/// Cap a file path at 1024 UTF-16 units so an event borrows a bounded slice.
const MAX_NAME_U16: usize = 1024;

/// The registered filter. One per driver; dropped on unload.
pub struct Filter {
    filter: PFLT_FILTER,
}

impl Filter {
    /// Register with FltMgr and start filtering.
    pub fn register(driver: PDRIVER_OBJECT) -> Result<Filter, NTSTATUS> {
        // Zero then set only the fields we use — robust to wdk-sys struct differences.
        let mut reg: FLT_REGISTRATION = unsafe { core::mem::zeroed() };
        reg.Size = core::mem::size_of::<FLT_REGISTRATION>() as u16;
        reg.Version = FLT_REGISTRATION_VERSION as u16;
        reg.OperationRegistration = OPERATIONS.0.as_ptr();
        reg.ContextRegistration = CONTEXTS.0.as_ptr();
        reg.FilterUnloadCallback = Some(filter_unload);
        reg.InstanceSetupCallback = Some(instance_setup);
        reg.InstanceQueryTeardownCallback = Some(instance_query_teardown);

        let mut filter: PFLT_FILTER = ptr::null_mut();
        let status = unsafe { FltRegisterFilter(driver, &reg, &mut filter) };
        if status != STATUS_SUCCESS {
            return Err(status);
        }
        // Publish the filter handle for the pre-op callback (needs it to allocate the
        // dedup context) before filtering starts.
        crate::set_global_filter(filter);

        let status = unsafe { FltStartFiltering(filter) };
        if status != STATUS_SUCCESS {
            crate::set_global_filter(ptr::null_mut());
            unsafe { FltUnregisterFilter(filter) };
            return Err(status);
        }
        Ok(Filter { filter })
    }

    /// The FltMgr filter handle (for creating the control port).
    pub fn handle(&self) -> PFLT_FILTER {
        self.filter
    }
}

impl Drop for Filter {
    fn drop(&mut self) {
        crate::set_global_filter(ptr::null_mut());
        unsafe { FltUnregisterFilter(self.filter) };
    }
}

// ---- static registration tables (must stay valid for the filter's life) -----

#[repr(transparent)]
struct Ops([FLT_OPERATION_REGISTRATION; 2]);
unsafe impl Sync for Ops {}

static OPERATIONS: Ops = Ops([
    FLT_OPERATION_REGISTRATION {
        MajorFunction: IRP_MJ_WRITE as u8,
        Flags: 0,
        PreOperation: Some(pre_write),
        PostOperation: None,
        Reserved1: ptr::null_mut(),
    },
    // Terminator.
    FLT_OPERATION_REGISTRATION {
        MajorFunction: IRP_MJ_OPERATION_END as u8,
        Flags: 0,
        PreOperation: None,
        PostOperation: None,
        Reserved1: ptr::null_mut(),
    },
]);

#[repr(transparent)]
struct Contexts([FLT_CONTEXT_REGISTRATION; 2]);
unsafe impl Sync for Contexts {}

static CONTEXTS: Contexts = Contexts([
    FLT_CONTEXT_REGISTRATION {
        ContextType: FLT_STREAMHANDLE_CONTEXT,
        Flags: 0,
        ContextCleanupCallback: ptr::null_mut(),
        Size: 8, // marker only; contents unused
        PoolTag: 0x4B4E5253, // "SRNK"
        ContextAllocateCallback: ptr::null_mut(),
        ContextFreeCallback: ptr::null_mut(),
        Reserved1: ptr::null_mut(),
    },
    FLT_CONTEXT_REGISTRATION {
        ContextType: FLT_CONTEXT_END,
        Flags: 0,
        ContextCleanupCallback: ptr::null_mut(),
        Size: 0,
        PoolTag: 0,
        ContextAllocateCallback: ptr::null_mut(),
        ContextFreeCallback: ptr::null_mut(),
        Reserved1: ptr::null_mut(),
    },
]);

// ---- filter/instance lifecycle callbacks ------------------------------------

unsafe extern "C" fn filter_unload(_flags: u32) -> NTSTATUS {
    // FltMgr's unload path. Tearing down the driver singleton drops the `Filter`,
    // which calls `FltUnregisterFilter` — the documented thing to do from here.
    crate::teardown();
    STATUS_SUCCESS
}

unsafe extern "C" fn instance_setup(
    _flt: PCFLT_RELATED_OBJECTS,
    _flags: u32,
    _dev_type: u32,
    _fs_type: u32,
) -> NTSTATUS {
    STATUS_SUCCESS // attach to every volume offered
}

unsafe extern "C" fn instance_query_teardown(
    _flt: PCFLT_RELATED_OBJECTS,
    _flags: u32,
) -> NTSTATUS {
    STATUS_SUCCESS
}

// ---- the first-write chokepoint ---------------------------------------------

unsafe extern "C" fn pre_write(
    data: PFLT_CALLBACK_DATA,
    flt_objects: PCFLT_RELATED_OBJECTS,
    _completion: *mut *mut c_void,
) -> FLT_PREOP_CALLBACK_STATUS {
    let no_cb = FLT_PREOP_SUCCESS_NO_CALLBACK as FLT_PREOP_CALLBACK_STATUS;

    let objects = &*flt_objects;
    let instance = objects.Instance;
    let file_object = objects.FileObject;
    if instance.is_null() || file_object.is_null() {
        return no_cb;
    }

    // First-write dedup: if this handle already has our stream-handle context, we've
    // emitted for it. Otherwise plant one; a race resolves to exactly one setter.
    if already_emitted(instance, file_object) {
        return no_cb;
    }

    // Resolve the normalized file name.
    let mut name_info: *mut FLT_FILE_NAME_INFORMATION = ptr::null_mut();
    let status = FltGetFileNameInformation(
        data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &mut name_info,
    );
    if status != STATUS_SUCCESS || name_info.is_null() {
        return no_cb;
    }
    FltParseFileNameInformation(name_info);
    let name = unicode_slice(&(*name_info).Name, MAX_NAME_U16);

    let mut timestamp: i64 = 0;
    KeQuerySystemTimePrecise(&mut timestamp as *mut i64 as *mut _);
    let actor = Actor {
        pid: PsGetCurrentProcessId() as usize as u32,
        create_time: PsGetProcessCreateTimeQuadPart(IoGetCurrentProcess()),
    };
    let evt = Event { timestamp, actor, body: Body::FileWrite { name } };
    crate::engine::submit(&evt);

    FltReleaseFileNameInformation(name_info);
    no_cb
}

/// True if this handle already carries our marker context; otherwise plant one and
/// return false so exactly the first writer emits.
unsafe fn already_emitted(instance: PFLT_INSTANCE, file_object: PFILE_OBJECT) -> bool {
    let mut existing: PFLT_CONTEXT = ptr::null_mut();
    if FltGetStreamHandleContext(instance, file_object, &mut existing) == STATUS_SUCCESS {
        FltReleaseContext(existing);
        return true;
    }

    let filter = crate::global_filter();
    if filter.is_null() {
        return true; // can't dedup without the filter → skip rather than double-emit
    }
    let mut ctx: PFLT_CONTEXT = ptr::null_mut();
    if FltAllocateContext(filter, FLT_STREAMHANDLE_CONTEXT, 8, NON_PAGED_POOL_NX, &mut ctx)
        != STATUS_SUCCESS
    {
        return true; // allocation failed → skip rather than double-emit
    }
    let mut old: PFLT_CONTEXT = ptr::null_mut();
    let set = FltSetStreamHandleContext(
        instance,
        file_object,
        FLT_SET_CONTEXT_KEEP_IF_EXISTS as _,
        ctx,
        &mut old,
    );
    FltReleaseContext(ctx);
    if !old.is_null() {
        FltReleaseContext(old);
    }
    // If someone set it first (context-already-defined), they emit; we don't.
    set != STATUS_SUCCESS
}

/// Borrow a `UNICODE_STRING`'s buffer as `&[u16]`, capped at `max` units. The slice
/// is valid only until the caller releases the underlying name information.
unsafe fn unicode_slice(u: &UNICODE_STRING, max: usize) -> &'static [u16] {
    if u.Buffer.is_null() || u.Length == 0 {
        return &[];
    }
    let n = (u.Length as usize / 2).min(max);
    core::slice::from_raw_parts(u.Buffer, n)
}
