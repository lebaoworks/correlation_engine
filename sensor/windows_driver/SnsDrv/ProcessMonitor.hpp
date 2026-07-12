#pragma once

/********************
*     Includes      *
********************/

#include <krn.hpp>

// Events
#include "Event.hpp"
#include "ArmTable.hpp"

namespace Process
{
    class Monitor : public krn::failable, public krn::tag<'EVT0'>
    {
    private:
        // Handle for ObReristerCallbacks registration
        PVOID _handle = NULL;

    public:
        /// @brief Sets up the filter and starts filtering.
        /// @param Callback The async telemetry sink for captured events.
        /// @param Arms The arm table consulted before enforcing (§9).
        /// @param Enforce The synchronous enforcement path for armed / chokepoint events.
        /// @remarks On success, status() will be STATUS_SUCCESS.
        /// @remarks On failure, status() will be set to the error code, rewind any partial initialization.
        _IRQL_requires_(PASSIVE_LEVEL)
        _IRQL_requires_same_
        Monitor(
            _In_ Event::EventNotifyCallback Callback,
            _In_ Arm::Table& Arms,
            _In_ Event::SyncEnforceCallback Enforce
        ) noexcept;

        _IRQL_requires_(PASSIVE_LEVEL)
        _IRQL_requires_same_
        ~Monitor();
    };
}