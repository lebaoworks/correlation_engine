#pragma once

/********************
*     Includes      *
********************/

#include <krn.hpp>
#include <ntintsafe.h>



namespace Event
{
    //
    //    Enum
    //

    enum Types
    {
        Invalid = 0,

        // File related events 1-99
        FileOpen = 1,   // reserved: capture currently disabled (nop), kept for later
        FileWrite = 2,  // first write to a file (per handle) — enforceable chokepoint

        // Process related events 100-199
        ProcessCreate = 100,
        ProcessExit,
        ProcessOpen,
        ProcessExist,       // reserved (103): not emitted by this driver
        RemoteThreadCreate,

    };

    struct Event;

    _IRQL_requires_max_(APC_LEVEL)
    _IRQL_requires_same_
    using EventNotifyCallback = NTSTATUS(*)(krn::unique_ptr<Event>&);

    // Enforcement path: serialize `evt`, send it synchronously to the service and
    // return its verdict in `*Deny` (TRUE = deny the operation). Used only for the
    // rare armed / static-chokepoint events, so latency stays off the hot path.
    _IRQL_requires_max_(APC_LEVEL)
    using SyncEnforceCallback = NTSTATUS(*)(const Event& evt, bool* Deny);

    using String = krn::UnicodeStringBase<krn::tag<'EVT1'>>;
}

//
// Wire format v2 — engine-ready records.
//
// Design goals (the service feeds these records inline into the detection
// engine, so translation must be near-free):
//   * All numeric fields sit at fixed offsets and are naturally aligned; the
//     service reads them directly without a byte-cursor parse.
//   * Every record carries the acting process identity (Pid, PidCreateTime)
//     and — where a target exists — the target identity inline, so the
//     service needs no pid→start-time table (also defeats pid reuse).
//   * Each record is Size-prefixed and padded to a multiple of 8, so unknown
//     record types can be skipped and successive records stay 8-aligned.
//   * Strings stay UTF-16LE (no kernel-side conversion) at the record tail.
//
namespace Event
{
    namespace Wire
    {
        constexpr UINT16 Version = 2;

        inline constexpr ULONG Align8(ULONG n) { return (n + 7) & ~7ul; }

        /* Common record header (32 bytes, all fields naturally aligned)

        +--------+------+------------------------------+-----------------------------------------------+
        | Offset | Size | Field                        | Description                                   |
        +--------+------+------------------------------+-----------------------------------------------+
        | 0      | 4    | Size (U32)                   | Total record bytes incl. header, multiple of 8|
        | 4      | 1    | Type (U8)                    | Event::Types                                  |
        | 5      | 3    | Reserved                     | Zero                                          |
        | 8      | 8    | TimeStamp (I64)              | FILETIME (100-ns since 1601)                  |
        | 16     | 4    | ProcessId (U32)              | Acting process id                             |
        | 20     | 4    | Reserved                     | Zero                                          |
        | 24     | 8    | ProcessCreateTime (I64)      | Acting process creation time (identity)       |
        +--------+------+------------------------------+-----------------------------------------------+
        Strings (at the tail of a record): Length:U16 (bytes) ++ UTF-16LE data.
        */
        struct Header
        {
            UINT32 Size;
            BYTE   Type;
            BYTE   Reserved0;
            UINT16 Reserved1;
            INT64  TimeStamp;
            UINT32 ProcessId;
            UINT32 Reserved2;
            INT64  ProcessCreateTime;
        };
        static_assert(sizeof(Header) == 32, "wire header must be 32 bytes");

        /* ProcessCreate body (16 bytes at offset 32); header identity = parent.
           Strings: ImageName ++ CommandLine (of the child). */
        struct ProcessCreateBody
        {
            UINT32 ChildProcessId;
            UINT32 Reserved;
            INT64  ChildCreateTime; // == TimeStamp; child identity
        };
        static_assert(sizeof(ProcessCreateBody) == 16, "bad body size");

        /* ProcessOpen body (16 bytes at offset 32). Strings: TargetImage. */
        struct ProcessOpenBody
        {
            UINT32 TargetProcessId;
            UINT32 DesiredAccess;
            INT64  TargetCreateTime; // target identity
        };
        static_assert(sizeof(ProcessOpenBody) == 16, "bad body size");

        /* RemoteThreadCreate body (16 bytes at offset 32). No strings. */
        struct RemoteThreadBody
        {
            UINT32 TargetProcessId;
            UINT32 ThreadId;
            INT64  TargetCreateTime; // target identity
        };
        static_assert(sizeof(RemoteThreadBody) == 16, "bad body size");

        // FileOpen: no body; strings: FileName.
        // ProcessExit: no body, no strings (identity in header).
    }
}

namespace Event
{
    struct Event : public krn::tag<'EVT1'>
    {
        BYTE Type = Invalid;
        LARGE_INTEGER TimeStamp;
        // Acting process identity. Defaulted from the current thread's process:
        // every notify callback runs in the acting process' context except
        // process-create (parent may differ), which overrides these.
        ULONG ProcessId = 0;
        LARGE_INTEGER ProcessCreateTime;

        Event() noexcept
        {
            KeQuerySystemTime(&TimeStamp);
            ProcessId = HandleToUlong(PsGetCurrentProcessId());
            ProcessCreateTime.QuadPart = PsGetProcessCreateTimeQuadPart(PsGetCurrentProcess());
        }

        virtual ~Event() {}

        NTSTATUS Serialize(
            _Inout_ PVOID Buffer,
            _In_ ULONG BufferSize) const
        {
            const ULONG total = SerializedSize();
            if (BufferSize < total)
                return STATUS_BUFFER_TOO_SMALL;

            Wire::Header header{};
            header.Size = total;
            header.Type = Type;
            header.TimeStamp = TimeStamp.QuadPart;
            header.ProcessId = ProcessId;
            header.ProcessCreateTime = ProcessCreateTime.QuadPart;
            RtlCopyMemory(Buffer, &header, sizeof(header));

            BYTE* ptr = (BYTE*)Buffer + sizeof(header);
            NTSTATUS status = Serialize_(ptr, BufferSize - sizeof(header));
            if (status != STATUS_SUCCESS)
                return status;

            // Zero the alignment padding at the record tail.
            const ULONG used = sizeof(header) + PayloadSize_();
            RtlZeroMemory((BYTE*)Buffer + used, total - used);
            return STATUS_SUCCESS;
        }

        ULONG SerializedSize() const
        {
            return Wire::Align8(sizeof(Wire::Header) + PayloadSize_());
        }

    protected:
        // Body + strings only; the base writes the header and the tail padding.
        virtual NTSTATUS Serialize_(_Inout_ PVOID Buffer, _In_ ULONG BufferSize) const = 0;
        virtual ULONG    PayloadSize_() const = 0;

        static BYTE* WriteString(_Inout_ BYTE* ptr, _In_ const String& s)
        {
            *(UINT16*)ptr = s.Length;
            ptr += sizeof(UINT16);
            RtlCopyMemory(ptr, s.Buffer, s.Length);
            return ptr + s.Length;
        }

        static constexpr ULONG StringSize(_In_ const String& s)
        {
            return sizeof(UINT16) + s.Length;
        }
    };
}

// File related events
namespace Event
{
    /* FileOpen record: Wire::Header (identity = opener) ++ FileName string. */
    struct FileOpenEvent : public Event
    {
        String FileName;

        FileOpenEvent() noexcept { Type = Types::FileOpen; }

        virtual ~FileOpenEvent() {}

        virtual NTSTATUS Serialize_(
            _Inout_ PVOID Buffer,
            _In_ ULONG BufferSize) const override
        {
            if (BufferSize < PayloadSize_())
                return STATUS_BUFFER_TOO_SMALL;

            WriteString((BYTE*)Buffer, FileName);
            return STATUS_SUCCESS;
        }

        virtual ULONG PayloadSize_() const override
        {
            return StringSize(FileName);
        }
    };

    /* FileWrite record: Wire::Header (identity = the writing process) ++ FileName.
       Emitted once per handle on the first write (see MiniFilter Pre_Write). Same
       layout as FileOpen; a distinct Type so the engine maps it to Op::Write. */
    struct FileWriteEvent : public Event
    {
        String FileName;

        FileWriteEvent() noexcept { Type = Types::FileWrite; }

        virtual ~FileWriteEvent() {}

        virtual NTSTATUS Serialize_(
            _Inout_ PVOID Buffer,
            _In_ ULONG BufferSize) const override
        {
            if (BufferSize < PayloadSize_())
                return STATUS_BUFFER_TOO_SMALL;

            WriteString((BYTE*)Buffer, FileName);
            return STATUS_SUCCESS;
        }

        virtual ULONG PayloadSize_() const override
        {
            return StringSize(FileName);
        }
    };
}


// Process related events
namespace Event
{
    /* ProcessCreate record: Wire::Header (identity = PARENT process) ++
       Wire::ProcessCreateBody (child identity) ++ ImageName ++ CommandLine. */
    struct ProcessCreateEvent : public Event
    {
        ULONG ChildProcessId = 0;
        LARGE_INTEGER ChildCreateTime;
        String ImageName;
        String CommandLine;

        ProcessCreateEvent() noexcept { Type = Types::ProcessCreate; }

        virtual ~ProcessCreateEvent() {}

        virtual NTSTATUS Serialize_(
            _Inout_ PVOID Buffer,
            _In_ ULONG BufferSize) const override
        {
            if (BufferSize < PayloadSize_())
                return STATUS_BUFFER_TOO_SMALL;

            Wire::ProcessCreateBody body{};
            body.ChildProcessId = ChildProcessId;
            body.ChildCreateTime = ChildCreateTime.QuadPart;
            RtlCopyMemory(Buffer, &body, sizeof(body));

            BYTE* ptr = (BYTE*)Buffer + sizeof(body);
            ptr = WriteString(ptr, ImageName);
            WriteString(ptr, CommandLine);
            return STATUS_SUCCESS;
        }

        virtual ULONG PayloadSize_() const override
        {
            return sizeof(Wire::ProcessCreateBody) + StringSize(ImageName) + StringSize(CommandLine);
        }

    };


    /* ProcessExit record: Wire::Header only (identity = the exiting process,
       ProcessCreateTime carries its creation time). */
    struct ProcessExitEvent : public Event
    {
        ProcessExitEvent() noexcept { Type = Types::ProcessExit; }

        virtual ~ProcessExitEvent() {}

        virtual NTSTATUS Serialize_(
            _Inout_ PVOID Buffer,
            _In_ ULONG BufferSize) const override
        {
            UNREFERENCED_PARAMETER(Buffer);
            UNREFERENCED_PARAMETER(BufferSize);
            return STATUS_SUCCESS;
        }
        virtual ULONG PayloadSize_() const override
        {
            return 0;
        }
    };

    /* ProcessOpen record: Wire::Header (identity = opener) ++
       Wire::ProcessOpenBody (target identity + access) ++ TargetImage. */
    struct ProcessOpenEvent : public Event
    {
        ULONG TargetProcessId = 0;
        ULONG DesiredAccess = 0;
        LARGE_INTEGER TargetCreateTime;
        String TargetImage;

        ProcessOpenEvent() noexcept { Type = Types::ProcessOpen; }

        virtual ~ProcessOpenEvent() {}

        virtual NTSTATUS Serialize_(
            _Inout_ PVOID Buffer,
            _In_ ULONG BufferSize) const override
        {
            if (BufferSize < PayloadSize_())
                return STATUS_BUFFER_TOO_SMALL;

            Wire::ProcessOpenBody body{};
            body.TargetProcessId = TargetProcessId;
            body.DesiredAccess = DesiredAccess;
            body.TargetCreateTime = TargetCreateTime.QuadPart;
            RtlCopyMemory(Buffer, &body, sizeof(body));

            WriteString((BYTE*)Buffer + sizeof(body), TargetImage);
            return STATUS_SUCCESS;
        }

        virtual ULONG PayloadSize_() const override
        {
            return sizeof(Wire::ProcessOpenBody) + StringSize(TargetImage);
        }
    };

    /* RemoteThreadCreate record: Wire::Header (identity = injector) ++
       Wire::RemoteThreadBody (target identity + thread id). */
    struct RemoteThreadCreateEvent : public Event
    {
        ULONG TargetProcessId = 0;
        ULONG ThreadId = 0;
        LARGE_INTEGER TargetCreateTime;

        RemoteThreadCreateEvent() noexcept { Type = Types::RemoteThreadCreate; }

        virtual ~RemoteThreadCreateEvent() {}

        virtual NTSTATUS Serialize_(
            _Inout_ PVOID Buffer,
            _In_ ULONG BufferSize) const override
        {
            if (BufferSize < PayloadSize_())
                return STATUS_BUFFER_TOO_SMALL;

            Wire::RemoteThreadBody body{};
            body.TargetProcessId = TargetProcessId;
            body.ThreadId = ThreadId;
            body.TargetCreateTime = TargetCreateTime.QuadPart;
            RtlCopyMemory(Buffer, &body, sizeof(body));
            return STATUS_SUCCESS;
        }

        virtual ULONG PayloadSize_() const override
        {
            return sizeof(Wire::RemoteThreadBody);
        }
    };

}
