#pragma once

/********************
*     Includes      *
********************/

#include <krn.hpp>

#include "Event.hpp"

/*********************
*    Declarations    *
*********************/

//
// Shared-memory telemetry ring — the transport that replaced one FltSendMessage
// per event (see readme.md "Transport").
//
// The driver owns the memory: it allocates the region from non-paged pool, maps it
// into the service on C_REGISTER_RING, and hands back the mapped address. Callbacks
// serialize straight into a reserved slot and are done — no pool allocation, no
// queue, no worker thread, and no kernel transition at all in the steady state.
//
// The service half, the byte layout and the commit protocol are specified (and
// unit-tested) in `endpoint_service/src/ringbuf.rs`. **The two must agree byte for
// byte**; the offsets below are asserted against that spec's constants.
//
//   +--------+---------------------------------------------------------------+
//   | 0      | Magic:u32 ++ Abi:u16 ++ pad ++ DataSize:u32 ++ pad             |
//   | 64     | HeadMirror:u64 ++ Dropped:u64          <- we write             |
//   | 128    | Tail:u64 ++ ConsumerState:u32          <- service writes       |
//   | 4096   | Data[DataSize]  (DataSize is a power of two)                   |
//   +--------+---------------------------------------------------------------+
//
// Safety invariant — this is what separates a ring from a kernel write primitive.
// The region is mapped into the service, so the service can write anywhere in it.
// Therefore the authoritative head and mask live in `Buffer` (driver-private
// non-paged pool, NOT in the mapped region); only a mirror of head is published for
// the consumer to read. Every write offset is `_head & _mask`, both driver-private,
// so a write can never leave the data region however the service scribbles. `Tail`
// is service-written and thus untrusted: it feeds only the free-space check, and an
// impossible `head - tail` is clamped to "full" (drop).
//
namespace Ring
{
    // Layout — must equal `ringbuf.rs`.
    constexpr UINT32 MAGIC = 0x474E5253;   // "SRNG"
    constexpr UINT16 ABI = 1;
    constexpr ULONG  O_MAGIC = 0;
    constexpr ULONG  O_ABI = 4;
    constexpr ULONG  O_DATA_SIZE = 8;
    constexpr ULONG  O_HEAD_MIRROR = 64;   // own cacheline: written on every event
    constexpr ULONG  O_DROPPED = 72;
    constexpr ULONG  O_TAIL = 128;         // own cacheline: written by the consumer
    constexpr ULONG  O_CONSUMER_STATE = 136;
    constexpr ULONG  DATA_OFFSET = 4096;

    // ConsumerState values.
    constexpr UINT32 CONSUMER_RUNNING = 0;
    constexpr UINT32 CONSUMER_SLEEPING = 1;

    // Accepted data-region sizes. Non-paged pool is a finite machine-wide resource,
    // so a service asking for more than this is refused rather than trusted.
    constexpr ULONG  MIN_DATA_BYTES = 64 * 1024;
    constexpr ULONG  MAX_DATA_BYTES = 4 * 1024 * 1024;

    // Telemetry may fill 7/8 of the ring; enforcement may use all of it. A dropped
    // telemetry record costs visibility, but a dropped enforce record strands a
    // thread that is blocked in the kernel waiting for a verdict.
    constexpr ULONG  TELEMETRY_BUDGET_NUM = 7;
    constexpr ULONG  TELEMETRY_BUDGET_DEN = 8;

    // How long an enforcing callback will hold the operation waiting for a verdict
    // before failing open. The service normally answers in well under a
    // millisecond; this only bounds the damage when it is wedged or gone.
    constexpr LONG64 VERDICT_TIMEOUT_100NS = -1000LL * 1000 * 10; // 1 s

    /// Outstanding synchronous-enforcement requests, keyed by ReqId.
    ///
    /// The waiter's KEVENT lives on its own stack, so the window where the service
    /// could signal a request the waiter has already abandoned must be closed: the
    /// spinlock is what makes "complete it" and "abandon it" mutually exclusive.
    /// Concurrent armed operations are few (that is the whole point of the arm
    /// table), so a small linear table is ample and allocates nothing.
    class PendingVerdicts
    {
    private:
        struct Slot
        {
            UINT32  ReqId;
            PKEVENT Event;
            bool    Deny;
            bool    Used;
        };
        static constexpr ULONG CAP = 64;

        KSPIN_LOCK _lock;
        Slot       _slots[CAP] = {};

    public:
        void Initialize() noexcept;

        /// Claim a slot for `ReqId`. False if the table is full → fail open.
        _IRQL_requires_max_(DISPATCH_LEVEL)
        bool Add(_In_ UINT32 ReqId, _In_ PKEVENT Event) noexcept;

        /// Record the service's verdict and wake the waiter. False if the request is
        /// unknown (already timed out, or a bogus ReqId from the service).
        _IRQL_requires_max_(DISPATCH_LEVEL)
        bool Complete(_In_ UINT32 ReqId, _In_ bool Deny) noexcept;

        /// Release the slot and read the verdict. `*Deny` is always written — false
        /// if no verdict arrived, which is the fail-open default. Returns whether the
        /// slot existed. After this returns, the caller's KEVENT is unreachable from
        /// `Complete`.
        _IRQL_requires_max_(DISPATCH_LEVEL)
        bool Take(_In_ UINT32 ReqId, _Out_ bool* Deny) noexcept;
    };

    /// The ring itself. One instance for the driver's lifetime; `Register` /
    /// `Unregister` bracket a service connection.
    class Buffer : public krn::failable, public krn::tag<'RNG0'>
    {
    private:
        // --- driver-private, deliberately NOT in the mapped region ---
        volatile LONG64 _head = 0;   // authoritative write cursor
        UINT64          _mask = 0;
        ULONG           _data_size = 0;
        volatile LONG   _next_req_id = 0;

        // --- the mapping ---
        // `_base` is the publish gate: it is set last on Register (release) and
        // cleared first on Unregister, so a producer that reads it non-NULL (under
        // rundown protection) sees a fully initialized ring. volatile because both
        // sides race on it by design and it must never be cached across the check.
        PVOID volatile _base = nullptr; // kernel VA (pool); valid at any IRQL/context
        PVOID     _user = nullptr;   // service VA; only valid in _process
        PMDL      _mdl = nullptr;
        PEPROCESS _process = nullptr; // referenced: MmUnmapLockedPages needs its context
        PKEVENT   _doorbell = nullptr;

        EX_RUNDOWN_REF  _rundown;
        PendingVerdicts _verdicts;

        /// Reserve `FrameSize` bytes. Returns the data offset to write at, or
        /// `RESERVE_FAILED` if it does not fit within the caller's budget.
        /// @param Base The caller's already-validated `_base`. Passed in, never
        ///        re-read: `Unregister` clears `_base` *before* waiting for rundown,
        ///        so a producer holding rundown must use the pointer it checked. The
        ///        memory stays alive until that wait returns, which is the point.
        _IRQL_requires_max_(APC_LEVEL)
        ULONG Reserve(_In_ BYTE* Base, _In_ ULONG FrameSize, _In_ bool Enforce) noexcept;

        /// Publish `evt` as one frame. `ReqId` != 0 marks it reply-expected.
        _IRQL_requires_max_(APC_LEVEL)
        NTSTATUS Publish(_In_ const Event::Event& evt, _In_ UINT32 ReqId) noexcept;

    public:
        static constexpr ULONG RESERVE_FAILED = 0xFFFFFFFF;

        _IRQL_requires_(PASSIVE_LEVEL)
        Buffer() noexcept;

        _IRQL_requires_(PASSIVE_LEVEL)
        ~Buffer();

        /// Allocate the ring, map it into the **calling** process and reference
        /// `Doorbell` from it. Must run in the service's context — it does, being
        /// called from the port's message callback.
        /// @param DataBytes Requested data region; power of two within [MIN,MAX].
        /// @param Doorbell  Service event handle, signalled when a sleeping consumer
        ///                  must be woken.
        /// @param MappedVa  Out: the service-side address of the region. Non-NULL
        ///                  only on success; NULL on every failure path — hence
        ///                  `_Success_`, without which `_Outptr_` would promise a
        ///                  non-NULL result even when we return an error.
        _IRQL_requires_(PASSIVE_LEVEL)
        _Success_(return == STATUS_SUCCESS)
        NTSTATUS Register(
            _In_ ULONG DataBytes,
            _In_ HANDLE Doorbell,
            _Outptr_ PVOID* MappedVa) noexcept;

        /// Tear the mapping down. Safe to call when not registered.
        _IRQL_requires_(PASSIVE_LEVEL)
        void Unregister() noexcept;

        /// Async telemetry: publish and return. Never blocks; drops (and counts) if
        /// the ring is over the telemetry budget.
        _IRQL_requires_max_(APC_LEVEL)
        NTSTATUS PublishTelemetry(_In_ const Event::Event& evt) noexcept;

        /// Synchronous enforcement: publish reply-expected and block until the
        /// service answers or the timeout lapses. Fails open (`*Deny = false`) if
        /// there is no service, the ring is full, or the answer is late — a wedged
        /// service must never be able to break the machine.
        ///
        /// Ordering: because the request travels the *same* ring as telemetry, the
        /// service necessarily sees every event that preceded it before it decides.
        /// The old split (telemetry via the worker thread, enforce direct from the
        /// callback) had no such guarantee.
        _IRQL_requires_max_(APC_LEVEL)
        NTSTATUS EnforceSync(_In_ const Event::Event& evt, _Out_ bool* Deny) noexcept;

        /// Deliver a C_VERDICT from the service. Called on the control path.
        _IRQL_requires_max_(APC_LEVEL)
        NTSTATUS CompleteVerdict(_In_ UINT32 ReqId, _In_ bool Deny) noexcept;
    };
}
