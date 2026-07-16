//! Minimal FltMgr (minifilter) FFI — the one gap `wdk-sys` doesn't cover.
//!
//! `wdk-sys` 0.5 binds `ntddk`/`wdf`/`windows` but has **no filesystem-minifilter
//! surface** (no `fltKernel.h`, no `fltmgr` feature). Everything else in this driver
//! comes from `wdk-sys`; only the `Flt*` API is declared here, reusing `wdk-sys`
//! base types (`NTSTATUS`, `UNICODE_STRING`, `PVOID`, …) so the two interoperate.
//! Symbols resolve from `fltMgr.lib` (linked in `build.rs`).
//!
//! Struct layouts are the documented x64 WDK layouts; validate against `fltKernel.h`
//! if FltMgr ever rejects a registration.
#![allow(non_snake_case, non_camel_case_types, dead_code)]

use wdk_sys::{
    NTSTATUS, OBJECT_ATTRIBUTES, PDRIVER_OBJECT, PEPROCESS, PFILE_OBJECT, PSECURITY_DESCRIPTOR,
    PVOID, UNICODE_STRING,
};

// ---- NTSTATUS values wdk-sys does not define (plain ABI constants) ----------

pub const STATUS_SUCCESS: NTSTATUS = 0;
pub const STATUS_NOT_SUPPORTED: NTSTATUS = 0xC000_00BBu32 as NTSTATUS;
pub const STATUS_UNSUCCESSFUL: NTSTATUS = 0xC000_0001u32 as NTSTATUS;

// Object-attribute flags (from wdm.h; declared here to keep the shim self-contained).
pub const OBJ_CASE_INSENSITIVE: u32 = 0x0000_0040;
pub const OBJ_KERNEL_HANDLE: u32 = 0x0000_0200;

// ---- opaque FltMgr handles --------------------------------------------------

pub type PFLT_FILTER = PVOID;
pub type PFLT_PORT = PVOID;
pub type PFLT_INSTANCE = PVOID;
pub type PFLT_VOLUME = PVOID;
pub type PFLT_CALLBACK_DATA = PVOID;
pub type PFLT_CONTEXT = PVOID;

// ---- pre/post-op return codes (enum _FLT_PREOP_CALLBACK_STATUS) --------------

pub type FLT_PREOP_CALLBACK_STATUS = i32;
pub const FLT_PREOP_SUCCESS_WITH_CALLBACK: FLT_PREOP_CALLBACK_STATUS = 0;
pub const FLT_PREOP_SUCCESS_NO_CALLBACK: FLT_PREOP_CALLBACK_STATUS = 1;
pub const FLT_PREOP_COMPLETE: FLT_PREOP_CALLBACK_STATUS = 4;
pub type FLT_POSTOP_CALLBACK_STATUS = i32;

// ---- operation / context registration flags & ids ---------------------------

pub const IRP_MJ_WRITE: u8 = 0x04;
pub const IRP_MJ_OPERATION_END: u8 = 0x80;

pub const FLT_STREAMHANDLE_CONTEXT: u16 = 0x0004;
pub const FLT_CONTEXT_END: u16 = 0xFFFF;

pub const FLT_FILE_NAME_NORMALIZED: u32 = 0x0000_0001;
pub const FLT_FILE_NAME_QUERY_DEFAULT: u32 = 0x0100_0000;

pub const FLT_SET_CONTEXT_KEEP_IF_EXISTS: u32 = 0;

/// `FLT_REGISTRATION_VERSION` (v2.3, Win8+); matches [`FLT_REGISTRATION`] below.
pub const FLT_REGISTRATION_VERSION: u16 = 0x0203;

pub const FLT_PORT_ALL_ACCESS: u32 = 0x001F_0000 | 0x0007;

/// NonPagedPoolNx as an `int` — mirrors `wdk_sys::_POOL_TYPE::NonPagedPoolNx`.
pub const NON_PAGED_POOL_NX: i32 = 512;

// ---- structures -------------------------------------------------------------

/// Subset of `FLT_RELATED_OBJECTS` — only what the callbacks read. Pointers start at
/// offset 8 (two USHORTs + padding), matching the header.
#[repr(C)]
pub struct FLT_RELATED_OBJECTS {
    pub Size: u16,
    pub TransactionContext: u16,
    pub Filter: PFLT_FILTER,
    pub Volume: PFLT_VOLUME,
    pub Instance: PFLT_INSTANCE,
    pub FileObject: PFILE_OBJECT,
    pub Transaction: PVOID,
}
pub type PCFLT_RELATED_OBJECTS = *const FLT_RELATED_OBJECTS;

/// Prefix of `FLT_FILE_NAME_INFORMATION` up to `Name`. Note the `Format:u32` between
/// `NamesParsed` and `Name` — omitting it (as an earlier draft did) mis-locates Name.
#[repr(C)]
pub struct FLT_FILE_NAME_INFORMATION {
    pub Size: u16,
    pub NamesParsed: u16,
    pub Format: u32,
    pub Name: UNICODE_STRING,
    // ...Volume/Share/Extension/Stream/etc. omitted; only Name is read.
}
pub type PFLT_FILE_NAME_INFORMATION = *mut FLT_FILE_NAME_INFORMATION;

// Callback typedefs (x64 kernel ABI == extern "C").
pub type PFLT_PRE_OPERATION_CALLBACK = Option<
    unsafe extern "C" fn(
        Data: PFLT_CALLBACK_DATA,
        FltObjects: PCFLT_RELATED_OBJECTS,
        CompletionContext: *mut PVOID,
    ) -> FLT_PREOP_CALLBACK_STATUS,
>;
pub type PFLT_POST_OPERATION_CALLBACK = Option<
    unsafe extern "C" fn(
        Data: PFLT_CALLBACK_DATA,
        FltObjects: PCFLT_RELATED_OBJECTS,
        CompletionContext: PVOID,
        Flags: u32,
    ) -> FLT_POSTOP_CALLBACK_STATUS,
>;
pub type PFLT_FILTER_UNLOAD_CALLBACK = Option<unsafe extern "C" fn(Flags: u32) -> NTSTATUS>;
pub type PFLT_INSTANCE_SETUP_CALLBACK = Option<
    unsafe extern "C" fn(
        FltObjects: PCFLT_RELATED_OBJECTS,
        Flags: u32,
        VolumeDeviceType: u32,
        VolumeFilesystemType: u32,
    ) -> NTSTATUS,
>;
pub type PFLT_INSTANCE_QUERY_TEARDOWN_CALLBACK =
    Option<unsafe extern "C" fn(FltObjects: PCFLT_RELATED_OBJECTS, Flags: u32) -> NTSTATUS>;

#[repr(C)]
pub struct FLT_OPERATION_REGISTRATION {
    pub MajorFunction: u8,
    pub Flags: u32,
    pub PreOperation: PFLT_PRE_OPERATION_CALLBACK,
    pub PostOperation: PFLT_POST_OPERATION_CALLBACK,
    pub Reserved1: PVOID,
}

#[repr(C)]
pub struct FLT_CONTEXT_REGISTRATION {
    pub ContextType: u16,
    pub Flags: u8,
    pub ContextCleanupCallback: PVOID,
    pub Size: usize,
    pub PoolTag: u32,
    pub ContextAllocateCallback: PVOID,
    pub ContextFreeCallback: PVOID,
    pub Reserved1: PVOID,
}

#[repr(C)]
pub struct FLT_REGISTRATION {
    pub Size: u16,
    pub Version: u16,
    pub Flags: u32,
    pub ContextRegistration: *const FLT_CONTEXT_REGISTRATION,
    pub OperationRegistration: *const FLT_OPERATION_REGISTRATION,
    pub FilterUnloadCallback: PFLT_FILTER_UNLOAD_CALLBACK,
    pub InstanceSetupCallback: PFLT_INSTANCE_SETUP_CALLBACK,
    pub InstanceQueryTeardownCallback: PFLT_INSTANCE_QUERY_TEARDOWN_CALLBACK,
    pub InstanceTeardownStartCallback: PVOID,
    pub InstanceTeardownCompleteCallback: PVOID,
    pub GenerateFileNameCallback: PVOID,
    pub NormalizeNameComponentCallback: PVOID,
    pub NormalizeContextCleanupCallback: PVOID,
    pub TransactionNotificationCallback: PVOID,
    pub NormalizeNameComponentExCallback: PVOID,
    pub SectionNotificationCallback: PVOID,
}

// Port callback typedefs.
pub type PFLT_CONNECT_NOTIFY = Option<
    unsafe extern "C" fn(
        ClientPort: PFLT_PORT,
        ServerPortCookie: PVOID,
        ConnectionContext: PVOID,
        SizeOfContext: u32,
        ConnectionPortCookie: *mut PVOID,
    ) -> NTSTATUS,
>;
pub type PFLT_DISCONNECT_NOTIFY = Option<unsafe extern "C" fn(ConnectionCookie: PVOID)>;
pub type PFLT_MESSAGE_NOTIFY = Option<
    unsafe extern "C" fn(
        PortCookie: PVOID,
        InputBuffer: PVOID,
        InputBufferLength: u32,
        OutputBuffer: PVOID,
        OutputBufferLength: u32,
        ReturnOutputBufferLength: *mut u32,
    ) -> NTSTATUS,
>;

// ---- imports ----------------------------------------------------------------

extern "C" {
    // `PsGetCurrentProcess` is a macro for this in ntddk.h, so wdk-sys never binds it.
    pub fn IoGetCurrentProcess() -> PEPROCESS;

    pub fn FltRegisterFilter(
        Driver: PDRIVER_OBJECT,
        Registration: *const FLT_REGISTRATION,
        RetFilter: *mut PFLT_FILTER,
    ) -> NTSTATUS;
    pub fn FltStartFiltering(Filter: PFLT_FILTER) -> NTSTATUS;
    pub fn FltUnregisterFilter(Filter: PFLT_FILTER);

    pub fn FltBuildDefaultSecurityDescriptor(
        SecurityDescriptor: *mut PSECURITY_DESCRIPTOR,
        DesiredAccess: u32,
    ) -> NTSTATUS;
    pub fn FltFreeSecurityDescriptor(SecurityDescriptor: PSECURITY_DESCRIPTOR);
    pub fn FltCreateCommunicationPort(
        Filter: PFLT_FILTER,
        ServerPort: *mut PFLT_PORT,
        ObjectAttributes: *mut OBJECT_ATTRIBUTES,
        ServerPortCookie: PVOID,
        ConnectNotifyCallback: PFLT_CONNECT_NOTIFY,
        DisconnectNotifyCallback: PFLT_DISCONNECT_NOTIFY,
        MessageNotifyCallback: PFLT_MESSAGE_NOTIFY,
        MaxConnections: i32,
    ) -> NTSTATUS;
    pub fn FltCloseCommunicationPort(ServerPort: PFLT_PORT);

    pub fn FltGetFileNameInformation(
        CallbackData: PFLT_CALLBACK_DATA,
        NameOptions: u32,
        FileNameInformation: *mut PFLT_FILE_NAME_INFORMATION,
    ) -> NTSTATUS;
    pub fn FltParseFileNameInformation(FileNameInformation: PFLT_FILE_NAME_INFORMATION) -> NTSTATUS;
    pub fn FltReleaseFileNameInformation(FileNameInformation: PFLT_FILE_NAME_INFORMATION);

    pub fn FltAllocateContext(
        Filter: PFLT_FILTER,
        ContextType: u16,
        ContextSize: usize,
        PoolType: i32,
        ReturnedContext: *mut PFLT_CONTEXT,
    ) -> NTSTATUS;
    pub fn FltSetStreamHandleContext(
        Instance: PFLT_INSTANCE,
        FileObject: PFILE_OBJECT,
        Operation: u32,
        NewContext: PFLT_CONTEXT,
        OldContext: *mut PFLT_CONTEXT,
    ) -> NTSTATUS;
    pub fn FltGetStreamHandleContext(
        Instance: PFLT_INSTANCE,
        FileObject: PFILE_OBJECT,
        Context: *mut PFLT_CONTEXT,
    ) -> NTSTATUS;
    pub fn FltReleaseContext(Context: PFLT_CONTEXT);
}
