#pragma once

/********************
*     Includes      *
********************/

#include <krn.hpp>

//
// Arm table — the kernel half of the §9 pushdown (see EnforcementPlane.md).
//
// The engine arms only the exact (process identity, op) that is one step from a
// chokepoint; the service serializes those as control records (service/src/
// control.rs) and pushes them here. A monitor callback whose (pid, op) is armed
// takes the *synchronous* enforcement path; everything else stays async. This is
// what keeps enforcement latency off the hot path — only armed identities pay it.
//
// Identity is (pid, start_ms) where start_ms = PsGetProcessCreateTimeQuadPart /
// 10000, matching the engine's NodeKey::Process and service/src/translate.rs. A
// reused pid never inherits a stale arm (collision only within the same ms).
//
namespace Arm
{
    // Op codes — must match service/src/control.rs::op_code. Kernel-native types
    // (UCHAR/ULONG/LONGLONG) so this header is self-contained (no Win32 aliases).
    constexpr UCHAR OP_EXEC = 1;
    constexpr UCHAR OP_READ = 2;
    constexpr UCHAR OP_WRITE = 3;
    constexpr UCHAR OP_INJECT = 4;

    class Table : public krn::failable, public krn::tag<'EVT0'>
    {
    private:
        struct Entry
        {
            ULONG    Pid;
            LONGLONG StartMs;
            UCHAR    Op;
            bool     Used;
        };

        // Live chokepoints are few; a small linear table scanned under a lock is
        // ample and avoids allocation on the hot path.
        static constexpr ULONG CAP = 512;

        ERESOURCE _lock;
        Entry     _entries[CAP] = {};
        volatile LONG _service_pid = -1; // exempt from enforcement (avoids self-deadlock)

    public:
        /// @brief Initializes the arm table lock.
        /// @remarks On success status() == STATUS_SUCCESS.
        _IRQL_requires_(PASSIVE_LEVEL)
        _IRQL_requires_same_
        Table() noexcept;

        _IRQL_requires_(PASSIVE_LEVEL)
        _IRQL_requires_same_
        ~Table();

        /// @brief Hot path: is (pid, start_ms, op) currently armed? Shared lock.
        _IRQL_requires_max_(APC_LEVEL)
        bool IsArmed(_In_ ULONG pid, _In_ LONGLONG start_ms, _In_ UCHAR op) noexcept;

        /// @brief Insert an arm (idempotent). Exclusive lock.
        _IRQL_requires_max_(APC_LEVEL)
        void Arm(_In_ ULONG pid, _In_ LONGLONG start_ms, _In_ UCHAR op) noexcept;

        /// @brief Remove every arm for this identity (all ops). Exclusive lock.
        _IRQL_requires_max_(APC_LEVEL)
        void Disarm(_In_ ULONG pid, _In_ LONGLONG start_ms) noexcept;

        /// @brief Record the service pid so callbacks in its context skip enforcement.
        void SetServicePid(_In_ ULONG pid) noexcept { InterlockedExchange(&_service_pid, (LONG)pid); }

        /// @brief Is `pid` the service itself?
        bool IsServicePid(_In_ ULONG pid) noexcept { return (LONG)pid == InterlockedCompareExchange(&_service_pid, -1, -1); }
    };
}
