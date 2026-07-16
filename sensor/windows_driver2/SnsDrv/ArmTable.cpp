/********************
*     Includes      *
********************/

#include "ArmTable.hpp"

/*********************
*   Implementations  *
*********************/

namespace Arm
{
    _IRQL_requires_(PASSIVE_LEVEL)
    _IRQL_requires_same_
    Table::Table() noexcept
    {
        auto& status = krn::failable::_status;
        status = ExInitializeResourceLite(&_lock);
        if (status != STATUS_SUCCESS)
            return;
        RtlZeroMemory(_entries, sizeof(_entries));
    }

    _IRQL_requires_(PASSIVE_LEVEL)
    _IRQL_requires_same_
    Table::~Table()
    {
        if (status() != STATUS_SUCCESS)
            return;
        ExDeleteResourceLite(&_lock);
    }

    _IRQL_requires_max_(APC_LEVEL)
    bool Table::IsArmed(_In_ ULONG pid, _In_ LONGLONG start_ms, _In_ UCHAR op) noexcept
    {
        ExAcquireResourceSharedLite(&_lock, TRUE);
        defer{ ExReleaseResourceLite(&_lock); };

        for (ULONG i = 0; i < CAP; ++i)
        {
            const Entry& e = _entries[i];
            if (e.Used && e.Pid == pid && e.StartMs == start_ms && e.Op == op)
                return true;
        }
        return false;
    }

    _IRQL_requires_max_(APC_LEVEL)
    void Table::Arm(_In_ ULONG pid, _In_ LONGLONG start_ms, _In_ UCHAR op) noexcept
    {
        ExAcquireResourceExclusiveLite(&_lock, TRUE);
        defer{ ExReleaseResourceLite(&_lock); };

        LONG free_slot = -1;
        for (ULONG i = 0; i < CAP; ++i)
        {
            const Entry& e = _entries[i];
            if (e.Used && e.Pid == pid && e.StartMs == start_ms && e.Op == op)
                return; // already armed (idempotent)
            if (!e.Used && free_slot < 0)
                free_slot = (LONG)i;
        }
        if (free_slot < 0)
            return; // table full — drop the arm (bounded by CAP; extremely unlikely)

        Entry& e = _entries[free_slot];
        e.Pid = pid;
        e.StartMs = start_ms;
        e.Op = op;
        e.Used = true;
    }

    _IRQL_requires_max_(APC_LEVEL)
    void Table::Disarm(_In_ ULONG pid, _In_ LONGLONG start_ms) noexcept
    {
        ExAcquireResourceExclusiveLite(&_lock, TRUE);
        defer{ ExReleaseResourceLite(&_lock); };

        for (ULONG i = 0; i < CAP; ++i)
        {
            Entry& e = _entries[i];
            if (e.Used && e.Pid == pid && e.StartMs == start_ms)
                e.Used = false; // clear every op for this identity
        }
    }
}
