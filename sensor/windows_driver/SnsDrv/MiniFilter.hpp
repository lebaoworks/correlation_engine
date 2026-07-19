#pragma once

/********************
*     Includes      *
********************/

#include <krn.hpp>

// Events
#include "Event.hpp"
#include "ArmTable.hpp"
#include "Ring.hpp"

/*********************
*    Declarations    *
*********************/

namespace MiniFilter
{
    class Filter;
    class Port;
}

namespace MiniFilter
{
    class Filter : public krn::failable, public krn::tag<'EVT0'>
    {
        friend class MiniFilter::Port;
    public:

    private:
        PFLT_FILTER _filter = NULL;
        

    public:

        /// @brief Sets up the filter and starts filtering.
        /// @param DriverObject
        /// @param Callback The async telemetry sink for captured events.
        /// @param Arms The arm table consulted before enforcing a first-write (§9).
        /// @param Enforce The synchronous enforcement path for armed writes.
        /// @remarks On success, status() will be STATUS_SUCCESS.
        /// @remarks On failure, status() will be set to the error code, rewind any partial initialization.
        _IRQL_requires_(PASSIVE_LEVEL)
        _IRQL_requires_same_
        Filter(
            _In_ DRIVER_OBJECT* DriverObject,
            _In_ Event::EventNotifyCallback Callback,
            _In_ Arm::Table& Arms,
            _In_ Event::SyncEnforceCallback Enforce
        );
        
        _IRQL_requires_(PASSIVE_LEVEL)
        _IRQL_requires_same_
        ~Filter();
    };
}

namespace MiniFilter
{
    /// The control port. It carries *only* the control plane now — arm/disarm, ring
    /// registration and verdicts — because telemetry moved to the shared ring
    /// (`Ring::Buffer`). Nothing is ever sent kernel→user through it, so there is no
    /// connection object to keep and no `FltSendMessage` anywhere in the driver.
    class Port : public krn::failable, public krn::tag<'EVT0'>
    {
    private:
        PFLT_PORT _port = NULL;
        PVOID     _cookie = nullptr;

    public:
        /// @brief Creates a communication port for the filter.
        /// @param Filter The filter to which the port will be attached.
        /// @param PortName The name of the port, which will be used by user-mode applications to connect to it.
        /// @param ArmTable The arm table the control plane pushes into.
        /// @param RingBuffer The ring registered on C_REGISTER_RING and torn down on disconnect.
        /// @remarks On success, status will be STATUS_SUCCESS.
        /// @remarks On failure, status will be set to the error code, rewind any partial initialization.
        _IRQL_requires_(PASSIVE_LEVEL)
        _IRQL_requires_same_
        Port(
            _In_ const Filter&   Filter,
            _In_ UNICODE_STRING* PortName,
            _In_ Arm::Table&     ArmTable,
            _In_ Ring::Buffer&   RingBuffer
        ) noexcept;

        _IRQL_requires_(PASSIVE_LEVEL)
        _IRQL_requires_same_
        ~Port();
    };
}
