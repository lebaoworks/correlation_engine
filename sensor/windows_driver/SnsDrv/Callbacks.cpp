/********************
*     Includes      *
********************/

#include "Callbacks.hpp"

// Logging via tracing
#include "trace.h"
#include "Callbacks.tmh"

/*********************
*    Declarations    *
*********************/

/*********************
*     Global Vars    *
*********************/
#pragma data_seg("NONPAGED")
static Event::EventNotifyCallback GlobalEventCallback = nullptr;
static Event::SyncEnforceCallback GlobalEnforce = nullptr;
static Arm::Table* GlobalArms = nullptr;
static const UNICODE_STRING LsassSuffix = RTL_CONSTANT_STRING(L"\\lsass.exe");
#pragma data_seg()

/*********************
*   Implementations  *
*********************/
namespace Process
{
    /* Creation time of a process by pid (0 if the process is gone). Used to fill
       the wire identity (Pid, PidCreateTime) when the acting/target process is
       not the current one. */
    _IRQL_requires_max_(APC_LEVEL)
    _IRQL_requires_same_
    static INT64 CreateTimeByPid(_In_ HANDLE Pid)
    {
        PEPROCESS process;
        if (PsLookupProcessByProcessId(Pid, &process) != STATUS_SUCCESS)
            return 0;
        INT64 time = PsGetProcessCreateTimeQuadPart(process);
        ObDereferenceObject(process);
        return time;
    }

    #define PROCESS_TERMINATE                  (0x0001)
    #define PROCESS_CREATE_THREAD              (0x0002)  
    #define PROCESS_SET_SESSIONID              (0x0004)  
    #define PROCESS_VM_OPERATION               (0x0008)  
    #define PROCESS_VM_READ                    (0x0010)  
    #define PROCESS_VM_WRITE                   (0x0020)  
    #define PROCESS_DUP_HANDLE                 (0x0040)  
    #define PROCESS_CREATE_PROCESS             (0x0080)  
    #define PROCESS_SET_QUOTA                  (0x0100)  
    #define PROCESS_SET_INFORMATION            (0x0200)  
    #define PROCESS_QUERY_INFORMATION          (0x0400)  
    #define PROCESS_SUSPEND_RESUME             (0x0800)  
    #define PROCESS_QUERY_LIMITED_INFORMATION  (0x1000)  
    #define PROCESS_SET_LIMITED_INFORMATION    (0x2000)  

    _IRQL_requires_(PASSIVE_LEVEL)
    _IRQL_requires_same_
    OB_PREOP_CALLBACK_STATUS ObPre_ProcessHandleCreation (
        _In_ PVOID RegistrationContext,
        _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation)
    {
        UNREFERENCED_PARAMETER(RegistrationContext);

        ULONG pid = HandleToUlong(PsGetCurrentProcessId());
        ULONG target_pid = HandleToUlong(PsGetProcessId((PEPROCESS)OperationInformation->Object));
        ULONG access = OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess;

        constexpr ULONG sensitive_access = PROCESS_TERMINATE |
            PROCESS_CREATE_THREAD |
            PROCESS_VM_OPERATION |
            PROCESS_VM_READ |
            PROCESS_VM_WRITE |
            PROCESS_DUP_HANDLE |
            PROCESS_CREATE_PROCESS |
            PROCESS_SET_QUOTA |
            PROCESS_SET_INFORMATION |
            PROCESS_SUSPEND_RESUME |
            PROCESS_SET_LIMITED_INFORMATION;

        // Filter out handle creations to reduce noise
        if ((pid == target_pid) ||                  // Skip handle creations to self
            (access & sensitive_access) == 0)       // Skip handle creations that do not request any sensitive access rights
            return OB_PREOP_SUCCESS;

        // Only monitor handle creations to lsass.exe
        PUNICODE_STRING image_path = NULL;
        NTSTATUS status = SeLocateProcessImageName((PEPROCESS)OperationInformation->Object, &image_path);
        if (status != STATUS_SUCCESS)
            return OB_PREOP_SUCCESS;
        defer{ ExFreePool(image_path); };

        if (image_path->Length >= LsassSuffix.Length)
        {
            USHORT offset = image_path->Length - LsassSuffix.Length;

            UNICODE_STRING sub;
            sub.Length = LsassSuffix.Length;
            sub.MaximumLength = LsassSuffix.Length;
            sub.Buffer = (PWCH)((BYTE*)image_path->Buffer + offset);

            if (RtlCompareUnicodeString(&sub, &LsassSuffix, TRUE) == 0)
            {
                TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "Process: process handle creation (lsass): ProcessId: %6lu, TargetProcessId: %6lu, DesiredAccess: 0x%08X", pid, target_pid, access);

                auto result = krn::make<Event::ProcessOpenEvent>();
                if (result.status() == STATUS_SUCCESS)
                {
                    auto& event = result.value();
                    // Acting identity (pid + create time) is filled by the base
                    // Event ctor from the current process context.
                    event.TargetProcessId = target_pid;
                    event.DesiredAccess = access;
                    event.TargetCreateTime.QuadPart = PsGetProcessCreateTimeQuadPart((PEPROCESS)OperationInformation->Object);
                    event.TargetImage = *image_path;

                    // An lsass handle-open with sensitive access is the static
                    // single-step chokepoint (it can't be pre-armed: the first
                    // matching event *is* the block). Enforce it synchronously —
                    // unless we're the service itself (self-deadlock guard).
                    bool exempt = (GlobalArms != nullptr) && GlobalArms->IsServicePid(pid);
                    if (!exempt && GlobalEnforce != nullptr)
                    {
                        bool deny = false;
                        GlobalEnforce(event, &deny); // sync send also delivers to the engine
                        if (deny)
                        {
                            // Strip the dangerous rights so the returned handle
                            // cannot read lsass memory — the credential dump fails.
                            OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~sensitive_access;
                            TraceEvents(TRACE_LEVEL_WARNING, TRACE_DRIVER, "Process: DENIED lsass open pid=%lu (stripped access)", pid);
                        }
                    }
                    else
                    {
                        krn::unique_ptr<Event::Event> evt(result.release());
                        GlobalEventCallback(evt); // async telemetry
                    }
                }
            }
        }
        return OB_PREOP_SUCCESS;
    }

    #pragma data_seg("NONPAGED")
    OB_OPERATION_REGISTRATION OperationRegistration[] = {
        {
            .ObjectType = NULL,                             // Place holder for PsProcessType, cause PsProcessType is exported at runtime
            .Operations = OB_OPERATION_HANDLE_CREATE,       // Register for handle creation
            .PreOperation = ObPre_ProcessHandleCreation,    // No pre-operation callback
            .PostOperation = NULL                           // No post-operation callback, we will filter in the pre-operation callback
        }
    };

    OB_CALLBACK_REGISTRATION CallbackRegistration = {
        .Version = OB_FLT_REGISTRATION_VERSION,             
        .OperationRegistrationCount = sizeof(OperationRegistration) / sizeof(OperationRegistration[0]),
        .Altitude = RTL_CONSTANT_STRING(L"370160"),
        .RegistrationContext = NULL,
        .OperationRegistration = OperationRegistration,
    };
    #pragma data_seg()

    _IRQL_requires_(PASSIVE_LEVEL)
    _IRQL_requires_same_
    VOID CreateProcessNotify(
        _Inout_ PEPROCESS Process,
        _In_ HANDLE ProcessId,
        _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
    {
        // ProcessCreate is captured (with ProcessOpen + FileWrite) — log info.
        if (CreateInfo != NULL)
        {
            ULONG pid = HandleToUlong(ProcessId);
            TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "Process: process create: ProcessId: %6lu, ImageName: %wZ", pid, CreateInfo->ImageFileName);

            auto result = krn::make<Event::ProcessCreateEvent>();
            if (result.status() == STATUS_SUCCESS)
            {
                auto& event = result.value();
                event.TimeStamp.QuadPart = PsGetProcessCreateTimeQuadPart(Process);
                // Acting identity = the PARENT (may differ from the current
                // context when the parent handle was spoofed, so look it up).
                event.ProcessId = HandleToUlong(CreateInfo->ParentProcessId);
                event.ProcessCreateTime.QuadPart = CreateTimeByPid(CreateInfo->ParentProcessId);
                event.ChildProcessId = pid;
                event.ChildCreateTime.QuadPart = event.TimeStamp.QuadPart;
                event.ImageName = *CreateInfo->ImageFileName;
                if (CreateInfo->CommandLine)
                    event.CommandLine = *CreateInfo->CommandLine;

                // Multi-step chokepoint (e.g. dropper write→exec): the engine may
                // have armed the PARENT identity for exec. If so, enforce this spawn
                // synchronously and deny by failing the creation.
                UINT32 parent = HandleToUlong(CreateInfo->ParentProcessId);
                INT64  parent_start_ms = event.ProcessCreateTime.QuadPart / 10000;
                bool exempt = (GlobalArms != nullptr) && GlobalArms->IsServicePid(parent);
                if (!exempt && GlobalArms != nullptr && GlobalEnforce != nullptr &&
                    GlobalArms->IsArmed(parent, parent_start_ms, Arm::OP_EXEC))
                {
                    bool deny = false;
                    GlobalEnforce(event, &deny); // sync send also delivers to the engine
                    if (deny)
                    {
                        CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
                        TraceEvents(TRACE_LEVEL_WARNING, TRACE_DRIVER, "Process: DENIED spawn by armed parent pid=%lu", parent);
                    }
                }
                else
                {
                    krn::unique_ptr<Event::Event> evt(result.release());
                    GlobalEventCallback(evt); // async telemetry
                }
            }
        }
        // Process termination — NOP (log verbose, emit nothing).
        else
        {
            ULONG pid = HandleToUlong(ProcessId);
            TraceEvents(TRACE_LEVEL_VERBOSE, TRACE_DRIVER, "Process: process exit (nop): ProcessId: %6lu", pid);
        }
    }

    _IRQL_requires_max_(APC_LEVEL)
    _IRQL_requires_same_
    VOID CreateThreadNotify(
        _In_ HANDLE ProcessId,
        _In_ HANDLE ThreadId,
        _In_ BOOLEAN Create)
    {
        // Creation only
        if (Create == FALSE)
            return;

        // Routine run in the context of the thread that created the new thread
        
        // Skip safe thread creations to reduce noise
        ULONG current_pid = HandleToUlong(PsGetCurrentProcessId());
        if (current_pid == 4 ||                         // System thread or process's inital thread,
            current_pid == HandleToULong(ProcessId))    // Skip thread creations to self
            return;

        // NOP: RemoteThreadCreate capture disabled (see CreateProcessNotify) —
        // log verbose, emit nothing.
        TraceEvents(TRACE_LEVEL_VERBOSE, TRACE_DRIVER, "Process: remote thread create (nop): ProcessId: %6lu, TargetProcessId: %6lu, ThreadId: %6lu", HandleToUlong(PsGetCurrentProcessId()), HandleToUlong(ProcessId), HandleToUlong(ThreadId));
    }
}
namespace Process
{
    _IRQL_requires_(PASSIVE_LEVEL)
    _IRQL_requires_same_
    Monitor::Monitor(
        _In_ Event::EventNotifyCallback Callback,
        _In_ Arm::Table& Arms,
        _In_ Event::SyncEnforceCallback Enforce) noexcept
    {
        GlobalEventCallback = Callback;
        GlobalArms = &Arms;
        GlobalEnforce = Enforce;
        auto& status = failable::_status;

        {
            OperationRegistration[0].ObjectType = PsProcessType;   // Set the ObjectType to PsProcessType

            // Register the callbacks
            // [NOTE] If ObRegisterCallbacks return STATUS_ACCESS_DEINED, add flag /INTEGRITYCHECK in linker settings.
            //      Refer: https://stackoverflow.com/a/78987826
            status = ObRegisterCallbacks(&CallbackRegistration, &_handle);
            if (status != STATUS_SUCCESS)
            {
                TraceEvents(TRACE_LEVEL_ERROR, TRACE_DRIVER, "Register handle callbacks failed -> status: %!STATUS!", status);
                return;
            }
        }
        defer{ if (status != STATUS_SUCCESS) ObUnRegisterCallbacks(_handle); };

        {
            status = PsSetCreateProcessNotifyRoutineEx(CreateProcessNotify, FALSE);
            if (status != STATUS_SUCCESS)
            {
                TraceEvents(TRACE_LEVEL_ERROR, TRACE_DRIVER, "Register process notify routine failed -> status: %!STATUS!", status);
                return;
            }
        }
        defer{ if (status != STATUS_SUCCESS) PsSetCreateProcessNotifyRoutineEx(CreateProcessNotify, TRUE); };

        {
            status = PsSetCreateThreadNotifyRoutine(CreateThreadNotify);
            if (status != STATUS_SUCCESS)
            {
                TraceEvents(TRACE_LEVEL_ERROR, TRACE_DRIVER, "Register thread notify routine failed -> status: %!STATUS!", status);
                return;
            }
        }
        defer{ if (status != STATUS_SUCCESS) PsRemoveCreateThreadNotifyRoutine(CreateThreadNotify); };
    }

    _IRQL_requires_(PASSIVE_LEVEL)
    _IRQL_requires_same_
    Monitor::~Monitor()
    {
        if (this->status() != STATUS_SUCCESS)
            return;

        PsRemoveCreateThreadNotifyRoutine(CreateThreadNotify);
        PsSetCreateProcessNotifyRoutineEx(CreateProcessNotify, TRUE);
        ObUnRegisterCallbacks(_handle);
    }
}
