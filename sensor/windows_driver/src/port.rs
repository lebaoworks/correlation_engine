//! Control port `\SnsDrvPort` — kept open, but with no commands.
//!
//! Rust twin of the `MiniFilter::Port` half of `windows_driver2/SnsDrv/
//! MiniFilter.cpp`, reduced to a bare channel. The old control plane (ring
//! registration, arm/disarm, verdicts) is gone: the detection engine is moving into
//! the kernel, so there is no user-mode side to register a ring or answer verdicts.
//! The port is retained as a connect/disconnect endpoint reserved for future control
//! traffic; any message it receives today is rejected.
//!
//! All kernel/FltMgr types and functions come from `wdk-sys`.

use core::ffi::c_void;
use core::ptr;

use wdk_sys::{NTSTATUS, OBJECT_ATTRIBUTES, PSECURITY_DESCRIPTOR, UNICODE_STRING};

// FltMgr surface — the one API wdk-sys does not provide (see fltmgr.rs).
use crate::fltmgr::{
    FltBuildDefaultSecurityDescriptor, FltCloseCommunicationPort, FltCreateCommunicationPort,
    FltFreeSecurityDescriptor, FLT_PORT_ALL_ACCESS, OBJ_CASE_INSENSITIVE, OBJ_KERNEL_HANDLE,
    PFLT_FILTER, PFLT_PORT, STATUS_NOT_SUPPORTED, STATUS_SUCCESS,
};

// UTF-16 for "\SnsDrvPort" (11 units).
static PORT_NAME_U16: [u16; 11] =
    [0x5C, 0x53, 0x6E, 0x73, 0x44, 0x72, 0x76, 0x50, 0x6F, 0x72, 0x74];

/// The server communication port. One per driver; closed on drop.
pub struct Port {
    server: PFLT_PORT,
}

impl Port {
    /// Create `\SnsDrvPort` on `filter` with a single-connection limit.
    pub fn create(filter: PFLT_FILTER) -> Result<Port, NTSTATUS> {
        let mut name = UNICODE_STRING {
            Length: (PORT_NAME_U16.len() * 2) as u16,
            MaximumLength: (PORT_NAME_U16.len() * 2) as u16,
            Buffer: PORT_NAME_U16.as_ptr() as *mut u16,
        };

        let mut sd: PSECURITY_DESCRIPTOR = ptr::null_mut();
        let status = unsafe { FltBuildDefaultSecurityDescriptor(&mut sd, FLT_PORT_ALL_ACCESS) };
        if status != STATUS_SUCCESS {
            return Err(status);
        }

        let mut oa: OBJECT_ATTRIBUTES = unsafe { core::mem::zeroed() };
        oa.Length = core::mem::size_of::<OBJECT_ATTRIBUTES>() as u32;
        oa.ObjectName = &mut name;
        oa.Attributes = OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE;
        oa.SecurityDescriptor = sd;

        let mut server: PFLT_PORT = ptr::null_mut();
        let status = unsafe {
            FltCreateCommunicationPort(
                filter,
                &mut server,
                &mut oa,
                ptr::null_mut(),
                Some(connect_notify),
                Some(disconnect_notify),
                Some(message_notify),
                1, // MaxConnections
            )
        };
        // The port keeps its own copy of the SD's contents; free ours regardless.
        unsafe { FltFreeSecurityDescriptor(sd) };
        if status != STATUS_SUCCESS {
            return Err(status);
        }
        Ok(Port { server })
    }
}

impl Drop for Port {
    fn drop(&mut self) {
        unsafe { FltCloseCommunicationPort(self.server) };
    }
}

// ---- port callbacks ---------------------------------------------------------

unsafe extern "C" fn connect_notify(
    client_port: PFLT_PORT,
    _server_cookie: *mut c_void,
    _ctx: *mut c_void,
    _ctx_size: u32,
    connection_cookie: *mut *mut c_void,
) -> NTSTATUS {
    // Accept the connection; remember the client port as the cookie.
    *connection_cookie = client_port;
    STATUS_SUCCESS
}

unsafe extern "C" fn disconnect_notify(_cookie: *mut c_void) {
    // Nothing to tear down: no ring, no arm state pushed from user mode.
}

unsafe extern "C" fn message_notify(
    _port_cookie: *mut c_void,
    _input: *mut c_void,
    _input_len: u32,
    _output: *mut c_void,
    _output_len: u32,
    ret_len: *mut u32,
) -> NTSTATUS {
    if !ret_len.is_null() {
        *ret_len = 0;
    }
    // No commands are defined yet; reject anything sent.
    STATUS_NOT_SUPPORTED
}
