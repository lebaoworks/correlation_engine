/********************
*     Includes      *
********************/

#include "MiniFilter.hpp"

// Logging via tracing
#include "trace.h"
#include "MiniFilter.tmh"

/*********************
*     Global Vars    *
*********************/
#pragma data_seg("NONPAGED")
static Event::EventNotifyCallback GlobalEventCallback = nullptr;
static Event::SyncEnforceCallback GlobalEnforce = nullptr;
static Arm::Table* GlobalArms = nullptr;
static PFLT_FILTER GlobalFilter = NULL;   // for FltAllocateContext on the write path
#pragma data_seg()


/*********************
*   Implementations  *
*********************/

// Filter
namespace MiniFilter
{
    _IRQL_requires_(PASSIVE_LEVEL)
    _IRQL_requires_same_
    NTSTATUS FLTAPI FilterUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
    {
        TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "MiniFilter: Unload with flags: %X", Flags);

        // Allow filter unload
        return STATUS_SUCCESS;
    }

    _IRQL_requires_(PASSIVE_LEVEL)
    _IRQL_requires_same_
    NTSTATUS FLTAPI FilterInstanceSetupCallback(
        _In_ PCFLT_RELATED_OBJECTS FltObjects,
        _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
        _In_ DEVICE_TYPE VolumeDeviceType,
        _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType)
    {
        UNREFERENCED_PARAMETER(Flags);
        TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "MiniFilter: Setup Instance: %p, VolumeType: %X, FileSystemType: %X",
            FltObjects->Instance,
            VolumeDeviceType,
            VolumeFilesystemType);

        // Let's instance attach to volume device
        return STATUS_SUCCESS;
    }

    _IRQL_requires_(PASSIVE_LEVEL)
    _IRQL_requires_same_
    NTSTATUS FLTAPI FilterInstanceQueryTeardown(
        _In_ PCFLT_RELATED_OBJECTS FltObjects,
        _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags)
    {
        TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "Instance Query Teardown: %p, Flags: %X, Volume: %p",
            FltObjects,
            Flags,
            FltObjects->Volume);

        // Allow detach from volume
        return STATUS_SUCCESS;
    }

    _IRQL_requires_(PASSIVE_LEVEL)
    _IRQL_requires_same_
    void FLTAPI FilterInstanceTeardownCompleteCallback(
        _In_ PCFLT_RELATED_OBJECTS FltObjects,
        _In_ FLT_INSTANCE_TEARDOWN_FLAGS Reason)
    {
        TraceEvents(TRACE_LEVEL_VERBOSE, TRACE_DRIVER, "Instance Teardown Complete: %p, Reason: %X",
            FltObjects->Instance,
            Reason);
    }

    // IRP_MJ_CREATE pre-op. File-open capture is disabled for now (open-to-query is
    // very high volume and no rule blocks on it yet); kept registered as scaffolding.
    _IRQL_requires_(PASSIVE_LEVEL)
    _IRQL_requires_same_
    FLT_PREOP_CALLBACK_STATUS FLTAPI FilterOperation_Pre_Create(
        _Inout_ PFLT_CALLBACK_DATA Data,
        _In_    PCFLT_RELATED_OBJECTS FltObjects,
        _Out_   PVOID* CompletionContext)
    {
        UNREFERENCED_PARAMETER(Data);
        UNREFERENCED_PARAMETER(FltObjects);
        *CompletionContext = NULL;
        return FLT_PREOP_SUCCESS_NO_CALLBACK; // nop
    }

    // Emit + (optionally) enforce a first-write event. Split out and annotated
    // PASSIVE so the name lookup / event build stays in a PASSIVE-only context; the
    // pre-op below only calls it after confirming IRQL == PASSIVE and non-paging I/O.
    _IRQL_requires_(PASSIVE_LEVEL)
    _IRQL_requires_same_
    static FLT_PREOP_CALLBACK_STATUS EmitFirstWrite(
        _Inout_ PFLT_CALLBACK_DATA Data)
    {
        PFLT_FILE_NAME_INFORMATION name_info = NULL;
        if (FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &name_info) != STATUS_SUCCESS)
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        defer{ FltReleaseFileNameInformation(name_info); };

        auto result = krn::make<Event::FileWriteEvent>();
        if (result.status() != STATUS_SUCCESS)
            return FLT_PREOP_SUCCESS_NO_CALLBACK;

        auto& event = result.value();
        // Acting identity (pid + create time) is filled by the base Event ctor.
        event.FileName = name_info->Name;

        ULONG pid = event.ProcessId;
        INT64 start_ms = event.ProcessCreateTime.QuadPart / 10000;

        // One of the two captured event types (with ProcessOpen) — log at info.
        TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "MiniFilter: first write pid=%lu file=%wZ", pid, &name_info->Name);

        // Armed write identity → enforce synchronously; deny fails the write.
        bool exempt = (GlobalArms != nullptr) && GlobalArms->IsServicePid(pid);
        if (!exempt && GlobalArms != nullptr && GlobalEnforce != nullptr &&
            GlobalArms->IsArmed(pid, start_ms, Arm::OP_WRITE))
        {
            bool deny = false;
            GlobalEnforce(event, &deny); // sync send also delivers to the engine
            if (deny)
            {
                Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                Data->IoStatus.Information = 0;
                TraceEvents(TRACE_LEVEL_WARNING, TRACE_DRIVER, "MiniFilter: DENIED first write pid=%lu", pid);
                return FLT_PREOP_COMPLETE; // block the write
            }
        }
        else
        {
            krn::unique_ptr<Event::Event> evt(result.release());
            GlobalEventCallback(evt); // async telemetry
        }
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // IRP_MJ_WRITE pre-op: fire once per handle on the first (non-paging) write.
    // Registered with SKIP_PAGING_IO; the runtime IRQL guard is belt-and-suspenders.
    _IRQL_requires_max_(APC_LEVEL)
    _IRQL_requires_same_
    FLT_PREOP_CALLBACK_STATUS FLTAPI FilterOperation_Pre_Write(
        _Inout_ PFLT_CALLBACK_DATA Data,
        _In_    PCFLT_RELATED_OBJECTS FltObjects,
        _Out_   PVOID* CompletionContext)
    {
        *CompletionContext = NULL;

        // FltSendMessage + name lookup need PASSIVE; and paging writes are the cache
        // manager flushing, not the process's write — neither is our moment.
        if (KeGetCurrentIrql() != PASSIVE_LEVEL) return FLT_PREOP_SUCCESS_NO_CALLBACK;
        if (Data->Iopb->IrpFlags & IRP_PAGING_IO)  return FLT_PREOP_SUCCESS_NO_CALLBACK;
        if (FltObjects->FileObject == NULL)        return FLT_PREOP_SUCCESS_NO_CALLBACK;

        // First write on this handle? A stream-handle context marks handles we have
        // already reported, collapsing the many writes of one file to one event.
        PVOID existing = NULL;
        if (FltGetStreamHandleContext(FltObjects->Instance, FltObjects->FileObject, &existing) == STATUS_SUCCESS)
        {
            FltReleaseContext(existing);
            return FLT_PREOP_SUCCESS_NO_CALLBACK; // already reported this handle
        }
        PVOID marker = NULL;
        if (GlobalFilter != NULL &&
            FltAllocateContext(GlobalFilter, FLT_STREAMHANDLE_CONTEXT, sizeof(BYTE), NonPagedPool, &marker) == STATUS_SUCCESS)
        {
            *(BYTE*)marker = 1;
            // Best-effort: if the volume doesn't support contexts we simply report
            // more than once — never fewer. KEEP_IF_EXISTS avoids a double report race.
            FltSetStreamHandleContext(FltObjects->Instance, FltObjects->FileObject, FLT_SET_CONTEXT_KEEP_IF_EXISTS, marker, NULL);
            FltReleaseContext(marker);
        }

        return EmitFirstWrite(Data);
    }

    #pragma data_seg("NONPAGED")
    static const FLT_CONTEXT_REGISTRATION FilterContextRegistration[] = {
        {
            FLT_STREAMHANDLE_CONTEXT,       //  ContextType: one-shot first-write marker
            0,                              //  Flags
            NULL,                           //  ContextCleanupCallback
            sizeof(BYTE),                   //  SizeOfContext
            'EVT0',                         //  PoolTag
            NULL,                           //  ContextAllocateCallback
            NULL,                           //  ContextFreeCallback
            NULL                            //  Reserved
        },
        { FLT_CONTEXT_END }
    };

    static FLT_OPERATION_REGISTRATION FilterCallbacks[] = {
        {
            IRP_MJ_CREATE,                  //  MajorFunction
            0,                              //  Flags
            FilterOperation_Pre_Create,     //  PreOperation (nop for now)
            NULL,                           //  PostOperation
        },
        {
            IRP_MJ_WRITE,                                   //  MajorFunction
            FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO,    //  Flags: skip paging I/O
            FilterOperation_Pre_Write,                      //  PreOperation
            NULL,                                           //  PostOperation
        },
        { IRP_MJ_OPERATION_END }
    };

    static const FLT_REGISTRATION FilterRegistration = {
        sizeof(FLT_REGISTRATION),               //  Size
        FLT_REGISTRATION_VERSION,               //  Version
        0,                                      //  Flags

        FilterContextRegistration,              //  Context Registration
        FilterCallbacks,                        //  Operation Registration

        FilterUnload,                           //  FilterUnload

        FilterInstanceSetupCallback,            //  InstanceSetup
        FilterInstanceQueryTeardown,            //  InstanceQueryTeardown
        NULL,                                   //  InstanceTeardownStart
        FilterInstanceTeardownCompleteCallback, //  InstanceTeardownComplete

        NULL,                                   //  GenerateFileName
        NULL,                                   //  NormalizeNameComponentCallback
        NULL,                                   //  NormalizeContextCleanupCallback
        NULL,                                   //  TransactionNotificationCallback
        NULL,                                   //  NormalizeNameComponentExCallback
        NULL,                                   //  SectionNotificationCallback
    };
    #pragma data_seg()


    _IRQL_requires_(PASSIVE_LEVEL)
    _IRQL_requires_same_
    Filter::Filter(
        _In_ DRIVER_OBJECT* DriverObject,
        _In_ Event::EventNotifyCallback Callback,
        _In_ Arm::Table& Arms,
        _In_ Event::SyncEnforceCallback Enforce)
    {
        auto& status = failable::_status;
        GlobalEventCallback = Callback;
        GlobalArms = &Arms;
        GlobalEnforce = Enforce;

        status = ::FltRegisterFilter(DriverObject, &FilterRegistration, &_filter);
        if (status != STATUS_SUCCESS)
        {
            TraceEvents(TRACE_LEVEL_ERROR, TRACE_DRIVER, "FltRegisterFilter() -> status: %!STATUS!", status);
            return;
        }
        defer{ if (status != STATUS_SUCCESS) ::FltUnregisterFilter(_filter); };
        GlobalFilter = _filter; // needed by the write path to allocate stream contexts

        status = FltStartFiltering(_filter);
        if (status != STATUS_SUCCESS)
            TraceEvents(TRACE_LEVEL_ERROR, TRACE_DRIVER, "FltStartFiltering() -> status: %!STATUS!", status);
    }

    _IRQL_requires_(PASSIVE_LEVEL)
    _IRQL_requires_same_
    Filter::~Filter()
    {
        if (this->status() != STATUS_SUCCESS)
            return;

        FltUnregisterFilter(_filter);
    }
}

// Port
namespace MiniFilter
{
    struct PortCookie : public krn::tag<'EVT0'>
    {
        Port::ConnectNotifyCallback ConnectNotify;
        PFLT_FILTER Filter;
        Arm::Table* ArmTable;
        PortCookie(Port::ConnectNotifyCallback ConnectNotify, PFLT_FILTER Filter, Arm::Table* ArmTable)
            : ConnectNotify(ConnectNotify), Filter(Filter), ArmTable(ArmTable) {}
    };

    // Safely copy `len` bytes from a user-mode buffer. Isolated (no C++ unwinding
    // objects) so it can use structured exception handling.
    #pragma warning(push)
    #pragma warning(disable : 6001)
    static NTSTATUS SafeCopyIn(_Out_writes_bytes_(len) PVOID dst, _In_ PVOID src, _In_ ULONG len)
    {
        __try
        {
            ProbeForRead(src, len, 1);
            RtlCopyMemory(dst, src, len);
            return STATUS_SUCCESS;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return STATUS_ACCESS_VIOLATION;
        }
    }
    #pragma warning(pop)

    // Control-plane sink: the service pushes ARM/DISARM/SetSelf records here via
    // FilterSendMessage. Layout mirrors service/src/control.rs (16-byte records).
    _IRQL_requires_max_(APC_LEVEL)
    static NTSTATUS FLTAPI ControlMessageNotify(
        _In_ PVOID PortCookie_,
        _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
        _In_ ULONG InputBufferLength,
        _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
        _In_ ULONG OutputBufferLength,
        _Out_ PULONG ReturnOutputBufferLength)
    {
        UNREFERENCED_PARAMETER(OutputBuffer);
        UNREFERENCED_PARAMETER(OutputBufferLength);
        *ReturnOutputBufferLength = 0;

        constexpr ULONG REC = 16;
        constexpr ULONG MAX_BYTES = REC * 512; // bound one control frame

        // Filter Manager hands this callback the *connection* cookie (set by
        // FilterConnectNotify to the client PFLT_PORT), NOT the server PortCookie.
        // Casting it to PortCookie* and reading ->ArmTable yields a garbage pointer
        // and bugchecks in SetServicePid (0x3B AV). Reach the arm table through the
        // driver-lifetime global instead (same table used by the enforcement path).
        UNREFERENCED_PARAMETER(PortCookie_);
        if (GlobalArms == nullptr)
            return STATUS_SUCCESS;
        if (InputBuffer == nullptr || InputBufferLength == 0 || InputBufferLength % REC != 0)
            return STATUS_INVALID_PARAMETER;

        ULONG len = InputBufferLength < MAX_BYTES ? InputBufferLength : MAX_BYTES;

        // Copy the frame into a nonpaged pool buffer rather than the kernel stack:
        // at 16*512 = 8 KB a stack array risks overflowing the ~12 KB kernel stack
        // on this already-deep FLTMGR dispatch path.
        BYTE* local = static_cast<BYTE*>(ExAllocatePool2(POOL_FLAG_NON_PAGED, len, 'EVT0'));
        if (local == nullptr)
            return STATUS_INSUFFICIENT_RESOURCES;
        defer{ ExFreePool(local); };
        if (SafeCopyIn(local, InputBuffer, len) != STATUS_SUCCESS)
            return STATUS_ACCESS_VIOLATION;

        for (ULONG off = 0; off + REC <= len; off += REC)
        {
            BYTE   kind = local[off + 0];
            BYTE   op = local[off + 1];
            UINT32 pid = *(UINT32*)(local + off + 4);
            INT64  start_ms = *(INT64*)(local + off + 8);
            switch (kind)
            {
            case 1: GlobalArms->Arm(pid, start_ms, op); break;      // C_ARM
            case 2: GlobalArms->Disarm(pid, start_ms); break;       // C_DISARM
            case 3: GlobalArms->SetServicePid(pid); break;          // C_SET_SELF
            default: break;                                              // unknown → skip
            }
        }
        return STATUS_SUCCESS;
    }
    struct Cookie : public krn::tag<'EVT0'>
    {
        PFLT_FILTER Filter;
        PFLT_PORT   ClientPort = NULL;
        Cookie(PFLT_FILTER Filter, PFLT_PORT Port) : Filter(Filter), ClientPort(Port) {}
    };

    _IRQL_requires_(PASSIVE_LEVEL)
    _IRQL_requires_same_
    NTSTATUS FLTAPI FilterConnectNotify(
        _In_ PFLT_PORT ClientPort,
        _In_ PVOID ServerPortCookie,
        _In_reads_bytes_(SizeOfContext) PVOID ConnectionContext,
        _In_ ULONG SizeOfContext,
        _Outptr_ PVOID* ConnectionCookie)
    {
        UNREFERENCED_PARAMETER(ConnectionContext);
        UNREFERENCED_PARAMETER(SizeOfContext);

        TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "MiniPort: Client connected: %p", ClientPort);

        // Set Port as connection cookie to be used in disconnect 
        *ConnectionCookie = ClientPort;

        // Retrieve port cookie to get filter and connect notify callback
        auto portCookie = reinterpret_cast<PortCookie*>(ServerPortCookie);

        // Create a connection object to represent this connection, which will be freed on disconnect.
        auto connection =  krn::make<Connection>(portCookie->Filter, ClientPort);
        if (connection.status() != STATUS_SUCCESS)
        {
            TraceEvents(TRACE_LEVEL_ERROR, TRACE_DRIVER, "MiniPort: Create Connection failed -> Status: %!STATUS!", connection.status());
            return connection.status();
        }
        return portCookie->ConnectNotify(connection);
    }

    _IRQL_requires_(PASSIVE_LEVEL)
    _IRQL_requires_same_
    VOID FLTAPI FilterDisconnectNotify(_In_ PVOID ConnectionCookie)
    {
        auto ClientPort = reinterpret_cast<PFLT_PORT>(ConnectionCookie);
        TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "MiniPort: Client disconnected: %p", ClientPort);
    }

    _IRQL_requires_(PASSIVE_LEVEL)
    _IRQL_requires_same_
    Port::Port(
        _In_ const Filter&          Filter,
        _In_ UNICODE_STRING*        PortName,
        _In_ ConnectNotifyCallback  ConnectNotifyCallback,
        _In_ Arm::Table&            ArmTable
    ) noexcept
    {
        auto& status = failable::_status;

        // Create port cookie
        auto result = krn::make<PortCookie>(ConnectNotifyCallback, Filter._filter, &ArmTable);
        status = result.status();
        if (status != STATUS_SUCCESS)
        {
            TraceEvents(TRACE_LEVEL_ERROR, TRACE_DRIVER, "MiniPort: Create Port Cookie failed -> Status: %X", status);
            return;
        }
        _cookie = result.release();
        defer{ if (status != STATUS_SUCCESS) delete reinterpret_cast<PortCookie*>(_cookie); };

        // Build Security Descriptor
        PSECURITY_DESCRIPTOR sd;
        status = ::FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
        if (status != STATUS_SUCCESS)
        {
            TraceEvents(TRACE_LEVEL_ERROR, TRACE_DRIVER, "MiniPort: Build SecurityDescriptor failed -> Status: %X", status);
            return;
        }
        RtlSetDaclSecurityDescriptor(sd, TRUE, NULL, FALSE);
        defer{ ::FltFreeSecurityDescriptor(sd); };

        // Initialize Object Attributes
        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, PortName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, sd);

        // Open Communication Port
        status = ::FltCreateCommunicationPort(
            Filter._filter,             // Filter
            &_port,                     // ServerPort
            &oa,                        // ObjectAttributes
            _cookie,                    // ServerPortCookie
            FilterConnectNotify,        // ConnectNotifyCallback
            FilterDisconnectNotify,     // DisconnectNotifyCallback
            ControlMessageNotify,       // MessageNotifyCallback: ARM/DISARM/SetSelf pushdown
            1);                         // MaxConnections
        if (status != STATUS_SUCCESS)
        {
            TraceEvents(TRACE_LEVEL_ERROR, TRACE_DRIVER, "MiniPort: Create Port failed -> Status: %X", status);
            return;
        }
    }

    Port::~Port()
    {
        if (this->status() != STATUS_SUCCESS)
            return;

        FltCloseCommunicationPort(_port);
        delete reinterpret_cast<PortCookie*>(_cookie);
    }
}

// Connection
namespace MiniFilter
{
    Connection::Connection(
        _In_ PFLT_FILTER Filter,
        _In_ PFLT_PORT   Port) noexcept : _filter(Filter), _port(Port) {}

    Connection::~Connection()
    {
        FltCloseClientPort(_filter, &_port);
    }

    NTSTATUS Connection::Send(
        _In_reads_bytes_(BufferSize) PVOID Buffer,
        _In_ ULONG BufferSize) noexcept
    {
        // Use a relative timeout
        // A negative LARGE_INTEGER represents relative time in 100-nanosecond units.
        LARGE_INTEGER timeout;
        timeout.QuadPart = -5 * 1000 * 1000 * 10; // 5 seconds

        return FltSendMessage(_filter, &_port, Buffer, BufferSize, NULL, 0, &timeout);
    }

    _IRQL_requires_max_(APC_LEVEL)
    NTSTATUS Connection::SendWithReply(
        _In_reads_bytes_(BufferSize) PVOID Buffer,
        _In_ ULONG BufferSize,
        _Out_ bool* Deny) noexcept
    {
        *Deny = false;

        // Bounded stall: enforcement holds the operation until the service replies
        // with a single decision byte (1 = deny). On timeout or error we fail open
        // (leave *Deny = false) so a slow/absent service can never wedge the system.
        // 20 ms was too tight — the service round-trips through the engine (and,
        // before it was reordered, the backend TCP hop) before replying, so it
        // routinely overran and the enforce failed open. 1 s is ample headroom; the
        // common case still replies in well under a millisecond, so no real stall.
        LARGE_INTEGER timeout;
        timeout.QuadPart = -1000 * 1000 * 10; // 1 s

        BYTE  verdict = 0;
        ULONG reply_size = sizeof(verdict);
        NTSTATUS status = FltSendMessage(_filter, &_port, Buffer, BufferSize, &verdict, &reply_size, &timeout);
        if (status == STATUS_SUCCESS && reply_size >= sizeof(verdict) && verdict != 0)
            *Deny = true;
        return status;
    }
}