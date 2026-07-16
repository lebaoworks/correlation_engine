/********************
*     Includes      *
********************/

#include "Ring.hpp"

// Logging via tracing
#include "trace.h"
#include "Ring.tmh"

/*********************
*    Declarations    *
*********************/

namespace
{
    // Frame header, as `endpoint_service/src/sensor.rs` decodes it. TotalSize sits
    // first, which is what lets it double as the ring's commit flag.
    constexpr ULONG FRAME_HEADER = 8;
    constexpr ULONG O_FRAME_TOTAL_SIZE = 0;
    constexpr ULONG O_FRAME_VERSION = 4;
    constexpr ULONG O_FRAME_COUNT = 6;
    // High bit of Count: the service must answer this frame with a C_VERDICT.
    constexpr UINT16 FRAME_REPLY_EXPECTED = 0x8000;
    // Version 0 is invalid on the wire, so it marks the pad frame we insert at a
    // wrap for the consumer to skip.
    constexpr UINT16 PAD_VERSION = 0;
    // ReqId within a record header (Event::Wire::Header::ReqId).
    constexpr ULONG O_RECORD_REQ_ID = 20;

    //
    // Memory ordering helpers.
    //
    // KeMemoryBarrier() is a full barrier. It is heavier than the release/acquire
    // these two need on x86, but publish already pays a locked CAS, and the alone
    // -x86 assumption is exactly the kind of thing that rots on an ARM64 build.
    //
    FORCEINLINE void StoreRelease32(_Inout_ volatile UINT32* p, _In_ UINT32 v)
    {
        KeMemoryBarrier();
        *p = v;
    }
    FORCEINLINE UINT32 LoadAcquire32(_In_ const volatile UINT32* p)
    {
        UINT32 v = *p;
        KeMemoryBarrier();
        return v;
    }
    FORCEINLINE UINT64 LoadAcquire64(_In_ const volatile UINT64* p)
    {
        UINT64 v = *p;
        KeMemoryBarrier();
        return v;
    }

    /// Publish a monotonically increasing value. Two producers can reach this out of
    /// reservation order, and a mirror that went backwards would hide committed
    /// frames from the consumer — hence max, not store.
    FORCEINLINE void PublishMax64(_Inout_ volatile LONG64* p, _In_ LONG64 v)
    {
        LONG64 cur = *p;
        while (cur < v)
        {
            LONG64 prev = InterlockedCompareExchange64(p, v, cur);
            if (prev == cur)
                break;
            cur = prev;
        }
    }

    FORCEINLINE bool IsPowerOfTwo(_In_ ULONG n)
    {
        return n != 0 && (n & (n - 1)) == 0;
    }

    // MmMapLockedPagesSpecifyCache *raises* on failure rather than returning NULL.
    // Isolated in its own function: SEH cannot coexist with the C++ unwinding
    // objects (`defer`) used by the caller.
    #pragma warning(push)
    #pragma warning(disable : 6320)
    PVOID SafeMapToUser(_In_ PMDL Mdl)
    {
        __try
        {
            return MmMapLockedPagesSpecifyCache(
                Mdl, UserMode, MmCached, NULL, FALSE, NormalPagePriority | MdlMappingNoExecute);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return NULL;
        }
    }
    #pragma warning(pop)
}

/*********************
*   Implementations  *
*********************/

namespace Ring
{
    void PendingVerdicts::Initialize() noexcept
    {
        KeInitializeSpinLock(&_lock);
        RtlZeroMemory(_slots, sizeof(_slots));
    }

    _IRQL_requires_max_(DISPATCH_LEVEL)
    bool PendingVerdicts::Add(_In_ UINT32 ReqId, _In_ PKEVENT Event) noexcept
    {
        KLOCK_QUEUE_HANDLE lh;
        KeAcquireInStackQueuedSpinLock(&_lock, &lh);
        bool ok = false;
        for (ULONG i = 0; i < CAP; i++)
        {
            if (!_slots[i].Used)
            {
                _slots[i].ReqId = ReqId;
                _slots[i].Event = Event;
                _slots[i].Deny = false;
                _slots[i].Used = true;
                ok = true;
                break;
            }
        }
        KeReleaseInStackQueuedSpinLock(&lh);
        return ok;
    }

    _IRQL_requires_max_(DISPATCH_LEVEL)
    bool PendingVerdicts::Complete(_In_ UINT32 ReqId, _In_ bool Deny) noexcept
    {
        KLOCK_QUEUE_HANDLE lh;
        KeAcquireInStackQueuedSpinLock(&_lock, &lh);
        bool found = false;
        for (ULONG i = 0; i < CAP; i++)
        {
            if (_slots[i].Used && _slots[i].ReqId == ReqId)
            {
                _slots[i].Deny = Deny;
                // Signal while still holding the lock. `Take` cannot run until we
                // release it, so the waiter's stack KEVENT is guaranteed live here.
                KeSetEvent(_slots[i].Event, IO_NO_INCREMENT, FALSE);
                found = true;
                break;
            }
        }
        KeReleaseInStackQueuedSpinLock(&lh);
        return found;
    }

    _IRQL_requires_max_(DISPATCH_LEVEL)
    bool PendingVerdicts::Take(_In_ UINT32 ReqId, _Out_ bool* Deny) noexcept
    {
        // Set unconditionally: an unknown ReqId must read as allow, which is the
        // fail-open default the whole enforcement path is built on.
        *Deny = false;

        KLOCK_QUEUE_HANDLE lh;
        KeAcquireInStackQueuedSpinLock(&_lock, &lh);
        bool got = false;
        for (ULONG i = 0; i < CAP; i++)
        {
            if (_slots[i].Used && _slots[i].ReqId == ReqId)
            {
                // The slot exists whether or not a verdict landed; the event being
                // signalled is what distinguishes them, and the caller already knows
                // that from its wait. Report the recorded value either way — it is
                // false unless Complete set it, which is the fail-open default.
                *Deny = _slots[i].Deny;
                _slots[i].Used = false;
                _slots[i].Event = nullptr;
                got = true;
                break;
            }
        }
        KeReleaseInStackQueuedSpinLock(&lh);
        return got;
    }
}

namespace Ring
{
    _IRQL_requires_(PASSIVE_LEVEL)
    Buffer::Buffer() noexcept
    {
        // Nothing here can fail, and no memory is taken until the service asks for a
        // ring: `failable::_status` is already STATUS_SUCCESS.
        ExInitializeRundownProtection(&_rundown);
        _verdicts.Initialize();
    }

    _IRQL_requires_(PASSIVE_LEVEL)
    Buffer::~Buffer()
    {
        Unregister();
    }

    _IRQL_requires_(PASSIVE_LEVEL)
    NTSTATUS Buffer::Register(
        _In_ ULONG DataBytes,
        _In_ HANDLE Doorbell,
        _Outptr_ PVOID* MappedVa) noexcept
    {
        *MappedVa = nullptr;

        if (!IsPowerOfTwo(DataBytes) || DataBytes < MIN_DATA_BYTES || DataBytes > MAX_DATA_BYTES)
        {
            TraceEvents(TRACE_LEVEL_ERROR, TRACE_DRIVER, "Ring: rejected DataBytes=%lu (want a power of two in [%lu,%lu])",
                DataBytes, MIN_DATA_BYTES, MAX_DATA_BYTES);
            return STATUS_INVALID_PARAMETER;
        }
        if (_base != nullptr)
        {
            TraceEvents(TRACE_LEVEL_ERROR, TRACE_DRIVER, "Ring: already registered");
            return STATUS_ALREADY_REGISTERED;
        }

        NTSTATUS status = STATUS_SUCCESS;
        const SIZE_T total = DATA_OFFSET + (SIZE_T)DataBytes;

        // ExAllocatePool2 zeroes by default, which the commit protocol depends on:
        // every slot must start with TotalSize == 0 ("reserved but not committed"),
        // or the consumer would read a stale frame out of fresh memory.
        PVOID pool = ExAllocatePool2(POOL_FLAG_NON_PAGED, total, 'RNG0');
        if (pool == nullptr)
        {
            TraceEvents(TRACE_LEVEL_ERROR, TRACE_DRIVER, "Ring: ExAllocatePool2(%llu) failed", (ULONG64)total);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        defer{ if (status != STATUS_SUCCESS) ExFreePool(pool); };

        PMDL mdl = IoAllocateMdl(pool, (ULONG)total, FALSE, FALSE, NULL);
        if (mdl == nullptr)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            TraceEvents(TRACE_LEVEL_ERROR, TRACE_DRIVER, "Ring: IoAllocateMdl failed");
            return status;
        }
        defer{ if (status != STATUS_SUCCESS) IoFreeMdl(mdl); };
        MmBuildMdlForNonPagedPool(mdl);

        // Runs in the service's context (port message callback), so this maps into
        // the service. It is also why we must remember the process: the matching
        // unmap has to run in this same context.
        PVOID user = SafeMapToUser(mdl);
        if (user == nullptr)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            TraceEvents(TRACE_LEVEL_ERROR, TRACE_DRIVER, "Ring: MmMapLockedPagesSpecifyCache failed");
            return status;
        }
        defer{ if (status != STATUS_SUCCESS) MmUnmapLockedPages(user, mdl); };

        PKEVENT doorbell = nullptr;
        status = ObReferenceObjectByHandle(
            Doorbell, EVENT_MODIFY_STATE | SYNCHRONIZE, *ExEventObjectType, UserMode, (PVOID*)&doorbell, NULL);
        if (status != STATUS_SUCCESS)
        {
            TraceEvents(TRACE_LEVEL_ERROR, TRACE_DRIVER, "Ring: ObReferenceObjectByHandle(doorbell) -> %!STATUS!", status);
            return status;
        }
        defer{ if (status != STATUS_SUCCESS) ObDereferenceObject(doorbell); };

        PEPROCESS process = PsGetCurrentProcess();
        ObReferenceObject(process);

        // Control block. The consumer validates magic + abi, so write those last:
        // until the magic lands the block is not claimed to be valid.
        BYTE* b = (BYTE*)pool;
        *(UINT32*)(b + O_DATA_SIZE) = DataBytes;
        StoreRelease32((volatile UINT32*)(b + O_ABI), ABI);
        StoreRelease32((volatile UINT32*)(b + O_MAGIC), MAGIC);

        _head = 0;
        _mask = (UINT64)DataBytes - 1;
        _data_size = DataBytes;
        _user = user;
        _mdl = mdl;
        _process = process;
        _doorbell = doorbell;

        // Last, with a barrier: this is the gate producers test. Everything above
        // must be visible to them before they can see a non-NULL base.
        KeMemoryBarrier();
        _base = pool;

        *MappedVa = user;
        TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "Ring: registered %lu KiB, kernel=%p user=%p", DataBytes / 1024, pool, user);
        return STATUS_SUCCESS;
    }

    _IRQL_requires_(PASSIVE_LEVEL)
    void Buffer::Unregister() noexcept
    {
        PVOID pool = InterlockedExchangePointer((PVOID volatile*)&_base, nullptr);
        if (pool == nullptr)
            return; // never registered, or already torn down

        // `_base` is now NULL so no new producer can start, but some may already be
        // inside with a cached pointer. This waits them out; after it returns the
        // region is ours alone. Enforcement waiters do *not* hold rundown across
        // their wait (see EnforceSync), so this cannot stall for the verdict timeout.
        ExWaitForRundownProtectionRelease(&_rundown);

        // MmUnmapLockedPages must run in the process the mapping belongs to, and
        // disconnect notify gives no such guarantee — hence the attach.
        //
        // Unless the process is already gone: ObReferenceObject keeps the PEPROCESS
        // alive but NOT its address space, which the kernel tears down on exit —
        // taking the user mapping with it. Unmapping then would be operating on an
        // address space that no longer exists. The normal path never hits this (the
        // port handle closes early in process rundown, so disconnect notify fires
        // while the address space is intact); this covers driver unload with a dead
        // client, and is cheap next to a bugcheck.
        if (PsGetProcessExitStatus(_process) == STATUS_PENDING)
        {
            KAPC_STATE apc;
            KeStackAttachProcess(_process, &apc);
            MmUnmapLockedPages(_user, _mdl);
            KeUnstackDetachProcess(&apc);
        }
        else
        {
            TraceEvents(TRACE_LEVEL_WARNING, TRACE_DRIVER, "Ring: client already exited; its mapping went with its address space");
        }

        IoFreeMdl(_mdl);
        ExFreePool(pool);
        ObDereferenceObject(_process);
        ObDereferenceObject(_doorbell);

        _user = nullptr;
        _mdl = nullptr;
        _process = nullptr;
        _doorbell = nullptr;
        _data_size = 0;
        _mask = 0;

        // Re-arm for a future connection. Only valid *after* the rundown wait above,
        // which is why it lives here and not in Register. Between now and the next
        // Register, a publish can take rundown again but finds `_base` NULL and bails.
        ExReInitializeRundownProtection(&_rundown);

        TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "Ring: unregistered");
    }

    _IRQL_requires_max_(APC_LEVEL)
    ULONG Buffer::Reserve(_In_ BYTE* Base, _In_ ULONG FrameSize, _In_ bool Enforce) noexcept
    {
        BYTE* b = Base; // never re-read _base here — see the header
        volatile UINT64* tail_p = (volatile UINT64*)(b + O_TAIL);
        volatile LONG64* dropped_p = (volatile LONG64*)(b + O_DROPPED);

        const UINT64 budget = Enforce
            ? (UINT64)_data_size
            : (UINT64)_data_size * TELEMETRY_BUDGET_NUM / TELEMETRY_BUDGET_DEN;

        for (;;)
        {
            const LONG64 head = _head;

            // `tail` is service-written and untrusted; see the header's invariant.
            // It only decides whether there is room. An impossible `used` means the
            // service corrupted its own tail, so we treat the ring as full and drop
            // rather than trusting it — nothing here can move a write out of bounds.
            const UINT64 tail = LoadAcquire64(tail_p);
            const UINT64 used = (UINT64)head - tail;
            if (used > (UINT64)_data_size)
            {
                InterlockedIncrement64(dropped_p);
                return RESERVE_FAILED;
            }
            const UINT64 avail = (budget > used) ? (budget - used) : 0;

            const ULONG off = (ULONG)((UINT64)head & _mask);
            const ULONG remainder = _data_size - off;
            // A frame that would straddle the end takes the remainder too, so the
            // real frame lands contiguously at 0 and the remainder becomes a pad.
            const bool wraps = remainder < FrameSize;
            const ULONG need = wraps ? remainder + FrameSize : FrameSize;
            if ((UINT64)need > avail)
            {
                InterlockedIncrement64(dropped_p);
                return RESERVE_FAILED;
            }

            const LONG64 next = head + need;
            if (InterlockedCompareExchange64(&_head, next, head) != head)
                continue; // lost the race to another producer; re-read and retry

            // Publish the reservation before filling it: the consumer sees head move,
            // reads TotalSize == 0 and waits, rather than reading a torn frame.
            PublishMax64((volatile LONG64*)(b + O_HEAD_MIRROR), next);

            if (wraps)
            {
                // Pad frame: Version 0 is invalid on the wire, so the consumer skips
                // it. Committed like any other frame — TotalSize last.
                BYTE* p = b + DATA_OFFSET + off;
                *(UINT16*)(p + O_FRAME_VERSION) = PAD_VERSION;
                *(UINT16*)(p + O_FRAME_COUNT) = 0;
                StoreRelease32((volatile UINT32*)(p + O_FRAME_TOTAL_SIZE), remainder);
                return 0;
            }
            return off;
        }
    }

    _IRQL_requires_max_(APC_LEVEL)
    NTSTATUS Buffer::Publish(_In_ const Event::Event& evt, _In_ UINT32 ReqId) noexcept
    {
        if (!ExAcquireRundownProtection(&_rundown))
            return STATUS_PORT_DISCONNECTED; // service gone → caller fails open
        defer{ ExReleaseRundownProtection(&_rundown); };

        BYTE* b = (BYTE*)_base;
        if (b == nullptr)
            return STATUS_PORT_DISCONNECTED; // not registered yet
        // Acquire, pairing with Register's release of `_base`: _mask, _data_size and
        // the control block were all written before it, and we are about to read
        // them. MSVC gives volatile loads acquire semantics on x64 but not under
        // /volatile:iso (the ARM64 default), so state the requirement rather than
        // inherit it from the target.
        KeMemoryBarrier();

        const ULONG rec_size = evt.SerializedSize();          // already 8-aligned
        const ULONG frame_size = FRAME_HEADER + rec_size;     // therefore so is this
        if (frame_size > _data_size)
        {
            TraceEvents(TRACE_LEVEL_WARNING, TRACE_DRIVER, "Ring: dropping oversized event (%lu bytes)", frame_size);
            InterlockedIncrement64((volatile LONG64*)(b + O_DROPPED));
            return STATUS_BUFFER_OVERFLOW;
        }

        const ULONG off = Reserve(b, frame_size, ReqId != 0);
        if (off == RESERVE_FAILED)
            return STATUS_INSUFFICIENT_RESOURCES; // ring full; counted as a drop

        BYTE* p = b + DATA_OFFSET + off;
        UINT16 count = 1;
        if (ReqId != 0)
            count |= FRAME_REPLY_EXPECTED;
        *(UINT16*)(p + O_FRAME_VERSION) = Event::Wire::Version;
        *(UINT16*)(p + O_FRAME_COUNT) = count;

        NTSTATUS status = evt.Serialize(p + FRAME_HEADER, rec_size);
        if (status != STATUS_SUCCESS)
        {
            // The slot is reserved and cannot be reclaimed, so commit it as a pad the
            // consumer will skip. Leaving TotalSize at 0 would wedge the consumer
            // forever waiting for a commit that is never coming.
            *(UINT16*)(p + O_FRAME_VERSION) = PAD_VERSION;
            StoreRelease32((volatile UINT32*)(p + O_FRAME_TOTAL_SIZE), frame_size);
            InterlockedIncrement64((volatile LONG64*)(b + O_DROPPED));
            return status;
        }
        // Serialize zero-fills the record header, so patch ReqId after it.
        if (ReqId != 0)
            *(UINT32*)(p + FRAME_HEADER + O_RECORD_REQ_ID) = ReqId;

        // The release store that makes the frame visible: everything written above is
        // ordered ahead of it, so a consumer that reads a non-zero TotalSize is
        // guaranteed a complete frame.
        StoreRelease32((volatile UINT32*)(p + O_FRAME_TOTAL_SIZE), frame_size);

        // Producer half of the Dekker pattern (see ringbuf.rs `should_sleep`): the
        // full barrier between publishing and reading ConsumerState is what keeps a
        // consumer that is going to sleep from being missed. Release/acquire would
        // not do — x86 reorders store-then-load, and this is exactly that shape.
        KeMemoryBarrier();
        if (LoadAcquire32((volatile UINT32*)(b + O_CONSUMER_STATE)) == CONSUMER_SLEEPING)
            KeSetEvent(_doorbell, IO_NO_INCREMENT, FALSE);

        return STATUS_SUCCESS;
    }

    _IRQL_requires_max_(APC_LEVEL)
    NTSTATUS Buffer::PublishTelemetry(_In_ const Event::Event& evt) noexcept
    {
        return Publish(evt, 0);
    }

    _IRQL_requires_max_(APC_LEVEL)
    NTSTATUS Buffer::EnforceSync(_In_ const Event::Event& evt, _Out_ bool* Deny) noexcept
    {
        *Deny = false;

        // ReqId 0 means "no verdict wanted", so never hand it out.
        UINT32 req_id = (UINT32)InterlockedIncrement(&_next_req_id);
        if (req_id == 0)
            req_id = (UINT32)InterlockedIncrement(&_next_req_id);

        KEVENT done;
        KeInitializeEvent(&done, NotificationEvent, FALSE);
        if (!_verdicts.Add(req_id, &done))
        {
            TraceEvents(TRACE_LEVEL_WARNING, TRACE_DRIVER, "Ring: verdict table full; failing open");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        NTSTATUS status = Publish(evt, req_id);
        if (status != STATUS_SUCCESS)
        {
            bool ignored = false;
            _verdicts.Take(req_id, &ignored);
            return status; // no service / full ring → fail open
        }

        // Note the rundown protection taken by Publish is already released: a
        // disconnect must not have to wait out this timeout. The KEVENT is on our
        // stack and the verdict table outlives any connection, so nothing here
        // depends on the mapping still existing.
        LARGE_INTEGER timeout;
        timeout.QuadPart = VERDICT_TIMEOUT_100NS;
        status = KeWaitForSingleObject(&done, Executive, KernelMode, FALSE, &timeout);

        bool verdict = false;
        _verdicts.Take(req_id, &verdict); // after this, `done` is unreachable
        if (status == STATUS_SUCCESS)
        {
            *Deny = verdict;
            return STATUS_SUCCESS;
        }

        // Timed out: the service is wedged or gone. Fail open — a detection we
        // cannot make in time must not become a machine we cannot use.
        TraceEvents(TRACE_LEVEL_WARNING, TRACE_DRIVER, "Ring: verdict %lu timed out; failing open", req_id);
        return STATUS_TIMEOUT;
    }

    _IRQL_requires_max_(APC_LEVEL)
    NTSTATUS Buffer::CompleteVerdict(_In_ UINT32 ReqId, _In_ bool Deny) noexcept
    {
        if (!_verdicts.Complete(ReqId, Deny))
        {
            // Stale (the waiter already timed out) or bogus. Not fatal: the service
            // is not trusted to send only well-formed ReqIds.
            TraceEvents(TRACE_LEVEL_WARNING, TRACE_DRIVER, "Ring: verdict for unknown req %lu", ReqId);
            return STATUS_NOT_FOUND;
        }
        return STATUS_SUCCESS;
    }
}
