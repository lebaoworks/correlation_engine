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
// The shared telemetry ring. Registered/unregistered on the port's connect and
// disconnect, and reached from the control path (both live in this file).
static Ring::Buffer* GlobalRing = nullptr;
static Engine::Instance* GlobalEngine = nullptr;
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
    // Proxy entropy NGUYÊN (không FP kernel): index-of-coincidence trên histogram
    // byte. Dữ liệu mã hoá/nén phân bố ~đều → Σcᵢ² nhỏ (≈ n²/256); văn bản/zero →
    // Σcᵢ² lớn. Cao entropy ⟺ IC < 1/64 ⟺ Σcᵢ²·64 < n². Lấy mẫu ≤ 4KB.
    static bool IsHighEntropy(_In_reads_bytes_(len) const BYTE* buf, _In_ ULONG len)
    {
        if (buf == nullptr)
            return false;
        ULONG n = len < 4096 ? len : 4096;
        if (n < 256)
            return false; // quá ngắn để phán
        ULONG hist[256] = {};
        for (ULONG i = 0; i < n; i++)
            hist[buf[i]]++;
        UINT64 sumsq = 0;
        for (ULONG i = 0; i < 256; i++)
            sumsq += (UINT64)hist[i] * hist[i];
        return sumsq * 64 < (UINT64)n * n;
    }

    // Đọc buffer có thể chạm vùng nhớ không hợp lệ → bọc SEH, fail-safe = false.
    // Hàm riêng, không có object C++ (tránh C2712 khi trộn SEH với unwind).
    static bool SafeHighEntropy(_In_opt_ const BYTE* buf, _In_ ULONG len)
    {
        bool result = false;
        __try { result = IsHighEntropy(buf, len); }
        __except (EXCEPTION_EXECUTE_HANDLER) { result = false; }
        return result;
    }

    static FLT_PREOP_CALLBACK_STATUS EmitFirstWrite(
        _Inout_ PFLT_CALLBACK_DATA Data)
    {
        PFLT_FILE_NAME_INFORMATION name_info = NULL;
        if (FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &name_info) != STATUS_SUCCESS)
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        defer{ FltReleaseFileNameInformation(name_info); };

        // On the stack: both sinks serialize into the ring before returning, so the
        // event never outlives this frame. That is one pool allocation per event
        // gone (the old path had to heap-allocate it to hand to the worker queue).
        Event::FileWriteEvent event;
        // Acting identity (pid + create time) is filled by the base Event ctor.
        event.FileName = name_info->Name;

        // Entropy của nội dung ghi (→ tagger T1486). Buffer lấy qua MDL (an toàn ở
        // mọi context) hoặc WriteBuffer; đọc bọc SEH nên không bao giờ crash.
        {
            const BYTE* wbuf = nullptr;
            ULONG wlen = Data->Iopb->Parameters.Write.Length;
            if (Data->Iopb->Parameters.Write.MdlAddress != nullptr)
                wbuf = (const BYTE*)MmGetSystemAddressForMdlSafe(
                    Data->Iopb->Parameters.Write.MdlAddress, NormalPagePriority | MdlMappingNoExecute);
            else
                wbuf = (const BYTE*)Data->Iopb->Parameters.Write.WriteBuffer;
            event.HighEntropy = SafeHighEntropy(wbuf, wlen);
        }

        ULONG pid = event.ProcessId;

        // One of the two captured event types (with ProcessOpen) — log at info.
        TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "MiniFilter: first write pid=%lu file=%wZ", pid, &name_info->Name);

        // Feed EVERY first-write to the in-kernel engine (via GlobalEnforce): the
        // engine advances on every event, not only armed ones. Deny (fail the write)
        // if its verdict is BLOCK/DISARM. Also ship async telemetry for forensic.
        bool exempt = (GlobalArms != nullptr) && GlobalArms->IsServicePid(pid);
        if (GlobalEventCallback != nullptr)
            GlobalEventCallback(event); // forensic telemetry
        if (!exempt && GlobalEnforce != nullptr)
        {
            bool deny = false;
            GlobalEnforce(event, &deny); // feed engine inline, take its verdict
            if (deny)
            {
                Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                Data->IoStatus.Information = 0;
                TraceEvents(TRACE_LEVEL_WARNING, TRACE_DRIVER, "MiniFilter: DENIED first write pid=%lu (engine)", pid);
                return FLT_PREOP_COMPLETE; // block the write
            }
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

    // Emit a directory-enumeration (recon / T1083) event and feed the engine.
    // A listing is a SIGNAL, not an enforceable chokepoint — advance the engine but
    // never deny (we do not fail directory queries).
    static FLT_PREOP_CALLBACK_STATUS EmitDirEnum(_Inout_ PFLT_CALLBACK_DATA Data)
    {
        PFLT_FILE_NAME_INFORMATION name_info = NULL;
        if (FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &name_info) != STATUS_SUCCESS)
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        defer{ FltReleaseFileNameInformation(name_info); };

        Event::FileReadEvent event;
        event.FileName = name_info->Name;
        ULONG pid = event.ProcessId;

        TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "MiniFilter: dir enum pid=%lu dir=%wZ", pid, &name_info->Name);

        bool exempt = (GlobalArms != nullptr) && GlobalArms->IsServicePid(pid);
        if (GlobalEventCallback != nullptr)
            GlobalEventCallback(event); // forensic telemetry
        if (!exempt && GlobalEnforce != nullptr)
        {
            bool deny = false;
            GlobalEnforce(event, &deny); // advance engine; reads are not denied
        }
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // IRP_MJ_DIRECTORY_CONTROL pre-op: fire once per handle on the first
    // QUERY_DIRECTORY (collapse the many query calls of one listing to one event).
    _IRQL_requires_max_(APC_LEVEL)
    _IRQL_requires_same_
    FLT_PREOP_CALLBACK_STATUS FLTAPI FilterOperation_Pre_DirCtrl(
        _Inout_ PFLT_CALLBACK_DATA Data,
        _In_    PCFLT_RELATED_OBJECTS FltObjects,
        _Out_   PVOID* CompletionContext)
    {
        *CompletionContext = NULL;

        if (KeGetCurrentIrql() != PASSIVE_LEVEL)                    return FLT_PREOP_SUCCESS_NO_CALLBACK;
        if (Data->Iopb->MinorFunction != IRP_MN_QUERY_DIRECTORY)   return FLT_PREOP_SUCCESS_NO_CALLBACK;
        if (FltObjects->FileObject == NULL)                        return FLT_PREOP_SUCCESS_NO_CALLBACK;

        // One enum event per handle (same one-shot marker as the write path).
        PVOID existing = NULL;
        if (FltGetStreamHandleContext(FltObjects->Instance, FltObjects->FileObject, &existing) == STATUS_SUCCESS)
        {
            FltReleaseContext(existing);
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
        PVOID marker = NULL;
        if (GlobalFilter != NULL &&
            FltAllocateContext(GlobalFilter, FLT_STREAMHANDLE_CONTEXT, sizeof(BYTE), NonPagedPool, &marker) == STATUS_SUCCESS)
        {
            *(BYTE*)marker = 1;
            FltSetStreamHandleContext(FltObjects->Instance, FltObjects->FileObject, FLT_SET_CONTEXT_KEEP_IF_EXISTS, marker, NULL);
            FltReleaseContext(marker);
        }
        return EmitDirEnum(Data);
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
        {
            IRP_MJ_DIRECTORY_CONTROL,                       //  MajorFunction: QUERY_DIRECTORY = recon
            0,                                              //  Flags
            FilterOperation_Pre_DirCtrl,                    //  PreOperation
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
        PFLT_FILTER Filter;
        Arm::Table* ArmTable;
        PortCookie(PFLT_FILTER Filter, Arm::Table* ArmTable)
            : Filter(Filter), ArmTable(ArmTable) {}
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

    // Ditto, outbound: used to hand the ring's mapped address back to the service.
    // Also isolated — a caller holding a `defer` cannot host SEH (C2712).
    static NTSTATUS SafeCopyOut(_Out_writes_bytes_all_(len) PVOID dst, _In_reads_bytes_(len) const void* src, _In_ ULONG len)
    {
        __try
        {
            ProbeForWrite(dst, len, 1);
            RtlCopyMemory(dst, src, len);
            return STATUS_SUCCESS;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return STATUS_ACCESS_VIOLATION;
        }
    }
    #pragma warning(pop)

    // Control-plane sink: the service pushes ARM/DISARM/SetSelf/RegisterRing/Verdict
    // records here via FilterSendMessage. Layout mirrors endpoint_service/src/
    // control.rs — every kind is exactly 16 bytes, so this stays a flat loop.
    //
    // This is the *whole* user→kernel channel. It stays a message channel rather
    // than a second ring because the kernel has no thread waiting on one: a down-ring
    // would mean re-introducing the very worker thread the ring deleted, and it would
    // add a thread hop to the verdict path — the one path where a thread is already
    // blocked in the kernel waiting. The traffic here is a few records a second
    // against millions of events a second going the other way.
    _IRQL_requires_max_(APC_LEVEL)
    static NTSTATUS FLTAPI ControlMessageNotify(
        _In_ PVOID PortCookie_,
        _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
        _In_ ULONG InputBufferLength,
        _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
        _In_ ULONG OutputBufferLength,
        _Out_ PULONG ReturnOutputBufferLength)
    {
        *ReturnOutputBufferLength = 0;

        constexpr ULONG REC = 16;
        constexpr ULONG MAX_BYTES = REC * 512; // bound one control frame

        // Control kinds — must match endpoint_service/src/control.rs.
        constexpr BYTE C_ARM = 1;
        constexpr BYTE C_DISARM = 2;
        constexpr BYTE C_SET_SELF = 3;
        constexpr BYTE C_REGISTER_RING = 4;
        constexpr BYTE C_VERDICT = 5;
        constexpr BYTE C_SET_RULES = 6;
        constexpr ULONG MAX_RULE_BYTES = 64 * 1024; // wire ruleset blob (variable length)

        // Filter Manager hands this callback the *connection* cookie (set by
        // FilterConnectNotify to the client PFLT_PORT), NOT the server PortCookie.
        // Casting it to PortCookie* and reading ->ArmTable yields a garbage pointer
        // and bugchecks in SetServicePid (0x3B AV). Reach the arm table through the
        // driver-lifetime global instead (same table used by the enforcement path).
        UNREFERENCED_PARAMETER(PortCookie_);
        if (InputBuffer == nullptr || InputBufferLength == 0)
            return STATUS_INVALID_PARAMETER;

        // Peek the kind to route the variable-length rules blob away from the
        // fixed 16-byte record frames (arm/verdict).
        BYTE kind0 = 0;
        if (SafeCopyIn(&kind0, InputBuffer, 1) != STATUS_SUCCESS)
            return STATUS_ACCESS_VIOLATION;

        if (kind0 == C_SET_RULES)
        {
            // { kind:u8@0, pad[3], WireLen:u32@4, wirebytes@8.. } → engine_create.
            // The wire bytes are the DAG ruleset ("ERD1") from engine_rules.
            if (GlobalEngine == nullptr)
                return STATUS_DEVICE_NOT_READY;
            if (InputBufferLength < 8)
                return STATUS_INVALID_PARAMETER;
            ULONG cap = InputBufferLength < (MAX_RULE_BYTES + 8) ? InputBufferLength : (MAX_RULE_BYTES + 8);
            BYTE* rbuf = static_cast<BYTE*>(ExAllocatePool2(POOL_FLAG_NON_PAGED, cap, 'EVT0'));
            if (rbuf == nullptr)
                return STATUS_INSUFFICIENT_RESOURCES;
            defer{ ExFreePool(rbuf); };
            if (SafeCopyIn(rbuf, InputBuffer, cap) != STATUS_SUCCESS)
                return STATUS_ACCESS_VIOLATION;
            ULONG wire_len = *(UINT32*)(rbuf + 4);
            if (wire_len > cap - 8)
                wire_len = cap - 8; // clamp to what we actually copied
            return GlobalEngine->Load(rbuf + 8, wire_len);
        }

        if (GlobalArms == nullptr)
            return STATUS_SUCCESS;
        if (InputBufferLength % REC != 0)
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

        NTSTATUS status = STATUS_SUCCESS;
        for (ULONG off = 0; off + REC <= len; off += REC)
        {
            BYTE   kind = local[off + 0];
            BYTE   op = local[off + 1];
            UINT32 pid = *(UINT32*)(local + off + 4);
            INT64  start_ms = *(INT64*)(local + off + 8);
            switch (kind)
            {
            case C_ARM:      GlobalArms->Arm(pid, start_ms, op); break;
            case C_DISARM:   GlobalArms->Disarm(pid, start_ms); break;
            case C_SET_SELF: GlobalArms->SetServicePid(pid); break;

            case C_REGISTER_RING:
            {
                // { pad[3], RingBytes:u32 @4, DoorbellHandle:u64 @8 }. We run in the
                // service's context here, which is exactly what the mapping and the
                // handle reference both require.
                if (GlobalRing == nullptr)
                {
                    status = STATUS_DEVICE_NOT_READY;
                    break;
                }
                ULONG  ring_bytes = *(UINT32*)(local + off + 4);
                HANDLE doorbell = (HANDLE)(ULONG_PTR)(*(UINT64*)(local + off + 8));

                PVOID mapped = nullptr;
                status = GlobalRing->Register(ring_bytes, doorbell, &mapped);
                if (status != STATUS_SUCCESS)
                    break;

                // Reply with the mapped address. The service never sends an address
                // down — the driver owning both ends of the mapping is what keeps a
                // compromised service from steering a kernel write (see Ring.hpp).
                if (OutputBuffer == nullptr || OutputBufferLength < sizeof(UINT64))
                {
                    GlobalRing->Unregister();
                    status = STATUS_BUFFER_TOO_SMALL;
                    break;
                }
                UINT64 addr = (UINT64)(ULONG_PTR)mapped;
                status = SafeCopyOut(OutputBuffer, &addr, sizeof(addr));
                if (status != STATUS_SUCCESS)
                {
                    // The service cannot learn where the ring is, so it can never
                    // drain it — tear the mapping down rather than leak it.
                    GlobalRing->Unregister();
                    break;
                }
                *ReturnOutputBufferLength = sizeof(UINT64);
                break;
            }

            case C_VERDICT:
            {
                // { Deny:u8 @1, pad[2], ReqId:u32 @4 }. Wakes the callback thread
                // blocked in Ring::EnforceSync. An unknown ReqId is not an error —
                // the waiter may have already timed out and failed open.
                if (GlobalRing == nullptr)
                    break;
                UINT32 req_id = *(UINT32*)(local + off + 4);
                GlobalRing->CompleteVerdict(req_id, op != 0);
                break;
            }

            default: break; // unknown → skip
            }
        }
        return status;
    }
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
        UNREFERENCED_PARAMETER(ServerPortCookie);

        TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "MiniPort: Client connected: %p", ClientPort);

        // The client port is all we need to remember: the ring is set up later, by
        // the service's C_REGISTER_RING, because the mapping must happen in the
        // service's context and this callback is the wrong place to demand a size.
        *ConnectionCookie = ClientPort;
        return STATUS_SUCCESS;
    }

    _IRQL_requires_(PASSIVE_LEVEL)
    _IRQL_requires_same_
    VOID FLTAPI FilterDisconnectNotify(_In_ PVOID ConnectionCookie)
    {
        auto ClientPort = reinterpret_cast<PFLT_PORT>(ConnectionCookie);
        TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "MiniPort: Client disconnected: %p", ClientPort);

        // The service is gone, so its ring mapping must go with it. This waits out
        // any producer still inside a publish before freeing anything. Callbacks that
        // fire after this point find no ring and fall through as no-ops; enforcement
        // fails open.
        if (GlobalRing != nullptr)
            GlobalRing->Unregister();

        FltCloseClientPort(GlobalFilter, &ClientPort);
    }

    _IRQL_requires_(PASSIVE_LEVEL)
    _IRQL_requires_same_
    Port::Port(
        _In_ const Filter&     Filter,
        _In_ UNICODE_STRING*   PortName,
        _In_ Arm::Table&       ArmTable,
        _In_ Ring::Buffer&     RingBuffer,
        _In_ Engine::Instance& Engine
    ) noexcept
    {
        auto& status = failable::_status;

        // Publish the ring for the control path (C_REGISTER_RING / C_VERDICT) and
        // for disconnect. Both live in this file, so a global is the honest shape —
        // FltMgr gives the message callback the *connection* cookie, not this one.
        GlobalRing = &RingBuffer;
        GlobalEngine = &Engine; // for C_SET_RULES pushdown

        // Create port cookie
        auto result = krn::make<PortCookie>(Filter._filter, &ArmTable);
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

    _IRQL_requires_(PASSIVE_LEVEL)
    _IRQL_requires_same_
    Port::~Port()
    {
        if (this->status() != STATUS_SUCCESS)
            return;

        FltCloseCommunicationPort(_port);
        delete reinterpret_cast<PortCookie*>(_cookie);
        GlobalRing = nullptr;
        GlobalEngine = nullptr;
    }
}