#pragma once

/********************
*     Includes      *
********************/

#include <krn.hpp>
#include <queue.hpp>

#include "Event.hpp"
#include "MiniFilter.hpp"
#include "ArmTable.hpp"

/*********************
*    Declarations    *
*********************/

namespace Worker
{
    class Worker;
    class Queue;
}

namespace Worker
{
    class Queue : public krn::failable, public krn::tag<'EVT0'>
    {
        friend class Worker;

    private:
        krn::queue<krn::unique_ptr<Event::Event>, krn::tag<'EVT0'>> _events;
        ERESOURCE _lock;
        KEVENT _push_event;

    public:

        /// @brief Initializes the event queue.
        /// @remarks On success, status() will be STATUS_SUCCESS.
        /// @remarks On failure, status() will be set to the error code, rewind any partial initialization.
        _IRQL_requires_(PASSIVE_LEVEL)
        _IRQL_requires_same_
        Queue() noexcept;
            
        _IRQL_requires_(PASSIVE_LEVEL)
        _IRQL_requires_same_
        ~Queue();

        /// @brief Push an event to the queue.
        /// @param event The event to push.
        /// @return STATUS_SUCCESS if the event was successfully pushed, otherwise an error code.
        _IRQL_requires_(PASSIVE_LEVEL)
        _IRQL_requires_same_
        NTSTATUS Push(_Inout_ krn::unique_ptr<Event::Event>& event) noexcept;
    };
}

namespace Worker
{
    class Worker : public krn::failable, public krn::tag<'EVT0'>
    {
    private:
        // Buffer for serializing events before sending to user-mode
        PVOID _serialized_buffer;

        // Current active connection to the filter (if any)
        krn::unique_ptr<MiniFilter::Connection> _connection;
        ERESOURCE _lock;
        KEVENT _connect_event;

        // Handle for the worker thread
        PETHREAD _worker_object = NULL;
        KEVENT   _stop_event;

        // Reference to the event queue shared between the driver and worker
        Queue& _queue;

        // Non-owning pointer to the live connection, published by the worker thread
        // so enforcement callbacks can send synchronously. Guarded by _conn_lock:
        // shared while a callback is mid-Send, exclusive to (un)publish. The owning
        // unique_ptr lives on the worker thread's stack and is unpublished before
        // it is destroyed, so the raw pointer never dangles.
        MiniFilter::Connection* _active_conn = nullptr;
        ERESOURCE _conn_lock;

        // Arm table (owned by the Driver) consulted on the enforcement path.
        Arm::Table& _arm_table;

    public:

        /// @brief Initializes the worker.
        /// @remarks On success, status() will be STATUS_SUCCESS.
        /// @remarks On failure, status() will be set to the error code, rewind any partial initialization.
        _IRQL_requires_(PASSIVE_LEVEL)
        _IRQL_requires_same_
        Worker(Queue& queue, Arm::Table& arm_table) noexcept;

        /// @brief The arm table, for callbacks to consult before enforcing.
        Arm::Table& Arms() noexcept { return _arm_table; }

        /// @brief Enforcement path: serialize `evt`, send it synchronously, and
        ///        return the service's verdict. Fails open (Deny=false) if no
        ///        connection or the service does not reply in time.
        /// @remarks Runs in the acting callback's context (PASSIVE/APC).
        _IRQL_requires_max_(APC_LEVEL)
        NTSTATUS EnforceSync(_In_ const Event::Event& evt, _Out_ bool* Deny) noexcept;
        
        _IRQL_requires_(PASSIVE_LEVEL)
        _IRQL_requires_same_
        ~Worker();
        
        /// @brief Notifies the worker of a new connection.
        /// @param connection The connection to notify the worker about.
        /// @return STATUS_SUCCESS if the notification was successful, otherwise an error code.
        _IRQL_requires_(PASSIVE_LEVEL)
        _IRQL_requires_same_
        NTSTATUS ConnectNotify(_Inout_ krn::unique_ptr<MiniFilter::Connection>& connection) noexcept;


        _IRQL_requires_same_
        _Function_class_(KSTART_ROUTINE)
        static VOID Routine(_In_ PVOID Context);
    };
}