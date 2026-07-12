#pragma once

/********************
*     Includes      *
********************/

#include <krn.hpp>

// Events
#include "Event.hpp"
#include "ArmTable.hpp"

/*********************
*    Declarations    *
*********************/

namespace MiniFilter
{
    class Filter;
    class Port;
    class Connection;
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
    class Port : public krn::failable, public krn::tag<'EVT0'>
    {
    public:
        using ConnectNotifyCallback = NTSTATUS(*)(krn::unique_ptr<Connection>&);

    private:
        PFLT_PORT _port = NULL;
        PVOID     _cookie = nullptr;

    public:
        /// @brief Creates a communication port for the filter.
        /// @param Filter The filter to which the port will be attached.
        /// @param PortName The name of the port, which will be used by user-mode applications to connect to it.
        /// @remarks On success, status will be STATUS_SUCCESS.
        /// @remarks On failure, status will be set to the error code, rewind any partial initialization.
        _IRQL_requires_(PASSIVE_LEVEL)
        _IRQL_requires_same_
        Port(
            _In_ const Filter&          Filter,
            _In_ UNICODE_STRING*        PortName,
            _In_ ConnectNotifyCallback  ConnectNotifyCallback,
            _In_ Arm::Table&            ArmTable
        ) noexcept;

        _IRQL_requires_(PASSIVE_LEVEL)
        _IRQL_requires_same_
        ~Port();
    };

    class Connection : public krn::tag<'EVT0'>
    {
    private:
        PFLT_FILTER _filter = NULL;
        PFLT_PORT   _port   = NULL;

    public:
        /// @brief Wraps a MiniPort connection
        /// @param Filter The filter to which the port is attached.
        /// @param ClientPort The port representing the connection to the user-mode application.
        Connection(
            _In_ PFLT_FILTER Filter,
            _In_ PFLT_PORT ClientPort
        ) noexcept;
        ~Connection();

        /// @brief Send data to the connected user-mode application (fire-and-forget).
        /// @param Buffer The buffer containing the data to send.
        /// @param BufferSize The size of the buffer in bytes.
        /// @return [TODO]
        NTSTATUS Send(
            _In_reads_bytes_(BufferSize) PVOID Buffer,
            _In_ ULONG BufferSize
        ) noexcept;

        /// @brief Send synchronously and wait for the service's 1-byte verdict.
        ///        Used on the enforcement path: the calling callback blocks here
        ///        (bounded by a short timeout) so it can allow/deny inline.
        /// @param Buffer The frame to send (reply-expected flag set).
        /// @param BufferSize Size of the frame in bytes.
        /// @param Deny Out: TRUE if the service denied; FALSE on allow/timeout/error
        ///        (fail-open: a slow service must not break the operation).
        /// @return The FltSendMessage status (STATUS_TIMEOUT if the service was too slow).
        _IRQL_requires_max_(APC_LEVEL)
        NTSTATUS SendWithReply(
            _In_reads_bytes_(BufferSize) PVOID Buffer,
            _In_ ULONG BufferSize,
            _Out_ bool* Deny
        ) noexcept;
    };
}
