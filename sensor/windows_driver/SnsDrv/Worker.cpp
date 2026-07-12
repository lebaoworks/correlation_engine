/********************
*     Includes      *
********************/
#include "Worker.hpp"

// Logging via tracing
#include "trace.h"
#include "Worker.tmh"

/*********************
*    Declarations    *
*********************/

#define MAX_EVENT_QUEUE_SIZE 1000
#define SERIALIZED_BUFFER_SIZE (512 * 1024) // 512 KB

#pragma warning(disable : 4200)
namespace
{
    // Frame header (8 bytes). Events are sent immediately as they occur (no
    // batching, minimal latency): one message = one record, Count = 1. The
    // format still allows several records per frame (replay files use that).
    // Data starts 8-aligned; every record is a multiple of 8 bytes (Event::Wire).
    struct Header
    {
        UINT32 TotalSize = sizeof(Header);
        UINT16 Version = Event::Wire::Version;
        UINT16 Count = 0; // number of records in the frame
        BYTE Data[0]; // Flexible array member for serialized event data
    };
    static_assert(sizeof(Header) == 8, "frame header must be 8 bytes");
    static_assert(sizeof(Header) < SERIALIZED_BUFFER_SIZE, "Header size must be less than the total serialized buffer size");
}

/*********************
*   Implementations  *
*********************/

namespace Worker
{
    _IRQL_requires_(PASSIVE_LEVEL)
    _IRQL_requires_same_
    Queue::Queue() noexcept
    {
        auto& status = krn::failable::_status;
        
        status = ExInitializeResourceLite(&_lock);
        if (status != STATUS_SUCCESS)
        {
            TraceEvents(TRACE_LEVEL_ERROR, TRACE_DRIVER, "Worker: Failed to initialize queue lock -> status: %!STATUS!", status);
            return;
        }
        KeInitializeEvent(&_push_event, NotificationEvent, FALSE);
    }

    _IRQL_requires_(PASSIVE_LEVEL)
    _IRQL_requires_same_
    Queue::~Queue()
    {
        if (status() != STATUS_SUCCESS)
            return; // If constructor failed, we may be in a partially initialized state, only clean up what was initialized

        ExDeleteResourceLite(&_lock);
    }

    _IRQL_requires_(PASSIVE_LEVEL)
    _IRQL_requires_same_
    NTSTATUS Queue::Push(_Inout_ krn::unique_ptr<Event::Event>& event) noexcept
    {
        ExAcquireResourceExclusiveLite(&_lock, TRUE);
        defer{ ExReleaseResourceLite(&_lock); };

        if (_events.size() >= MAX_EVENT_QUEUE_SIZE)
        {
            //TraceEvents(TRACE_LEVEL_WARNING, TRACE_DRIVER, "Worker: Event queue is full");
            return STATUS_TOO_MANY_NODES;
        }

        auto old_size = _events.size();
        _events.push(std::move(event));
        if (_events.size() == old_size)
            return STATUS_NO_MEMORY;

        // Signal worker there is data to process
        KeSetEvent(&_push_event, 0, FALSE);

        return STATUS_SUCCESS;
    }
}

namespace Worker
{
    _IRQL_requires_(PASSIVE_LEVEL)
    _IRQL_requires_same_
    Worker::Worker(Queue& queue, Arm::Table& arm_table) noexcept
        : _queue(queue), _arm_table(arm_table)
    {
        auto& status = krn::failable::_status;

        // Initialize serialized buffer
        _serialized_buffer = Worker::operator new(SERIALIZED_BUFFER_SIZE);
        if (_serialized_buffer == NULL)
        {
            status = STATUS_NO_MEMORY;
            TraceEvents(TRACE_LEVEL_ERROR, TRACE_DRIVER, "Worker: Failed to allocate serialized buffer -> status: %!STATUS!", status);
            return;
        }
        defer{ if (status != STATUS_SUCCESS) { Worker::operator delete(_serialized_buffer); _serialized_buffer = NULL; } };

        // Initialize connection management
        status = ExInitializeResourceLite(&_lock);
        if (status != STATUS_SUCCESS)
        {
            TraceEvents(TRACE_LEVEL_ERROR, TRACE_DRIVER, "Worker: Failed to initialize connection lock -> status: %!STATUS!", status);
            return;
        }
        defer{ if (status != STATUS_SUCCESS) ExDeleteResourceLite(&_lock); };

        // Lock guarding the published active-connection pointer (enforcement path).
        status = ExInitializeResourceLite(&_conn_lock);
        if (status != STATUS_SUCCESS)
        {
            TraceEvents(TRACE_LEVEL_ERROR, TRACE_DRIVER, "Worker: Failed to initialize enforcement lock -> status: %!STATUS!", status);
            return;
        }
        defer{ if (status != STATUS_SUCCESS) ExDeleteResourceLite(&_conn_lock); };
        KeInitializeEvent(&_connect_event, SynchronizationEvent, FALSE);
        
        // Create worker system thread
        KeInitializeEvent(&_stop_event, NotificationEvent, FALSE);
        HANDLE hThread;
        status = PsCreateSystemThread(
            &hThread,               // ThreadHandle
            THREAD_ALL_ACCESS,      // DesiredAccess
            NULL,                   // ObjectAttributes
            NULL,                   // ProcessHandle
            NULL,                   // ClientId
            Routine,                // StartRoutine
            this);                  // StartContext  
        if (status != STATUS_SUCCESS)
        {
            TraceEvents(TRACE_LEVEL_ERROR, TRACE_DRIVER, "Worker: Failed to create system thread -> status: %!STATUS!", status);
            return;
        }
        defer{ if (status != STATUS_SUCCESS) { KeSetEvent(&_stop_event, 0, FALSE); ZwWaitForSingleObject(hThread, FALSE, NULL); ZwClose(hThread); } };

        // Get thread object from handle for later synchronization when stopping the worker
        status = ObReferenceObjectByHandle(
            hThread,                        // Handle
            THREAD_ALL_ACCESS,              // DesiredAccess
            *PsThreadType,                  // ObjectType
            KernelMode,                     // AccessMode
            (PVOID*)&_worker_object,        // Object
            NULL);                          // HandleInformation
        if (status != STATUS_SUCCESS)
        {
            TraceEvents(TRACE_LEVEL_ERROR, TRACE_DRIVER, "Worker: Failed to reference thread object -> status: %!STATUS!", status);
            return;
        };
        // We have the thread object, close the handle
        ZwClose(hThread);
    }

    _IRQL_requires_(PASSIVE_LEVEL)
    _IRQL_requires_same_
    Worker::~Worker()
    {
        if (status() != STATUS_SUCCESS)
            return; // If constructor failed, we may be in a partially initialized state, only clean up what was initialized

        // Signal worker to stop
        KeSetEvent(&_stop_event, 0, FALSE);

        // Wait for thread to exit
        KeWaitForSingleObject(_worker_object, Executive, KernelMode, FALSE, NULL);
        ObDereferenceObject(_worker_object);

        ExDeleteResourceLite(&_lock);
        ExDeleteResourceLite(&_conn_lock);

        Worker::operator delete(_serialized_buffer);
    }

    _IRQL_requires_(PASSIVE_LEVEL)
    _IRQL_requires_same_
    NTSTATUS Worker::ConnectNotify(_Inout_ krn::unique_ptr<MiniFilter::Connection>& connection) noexcept
    {
        ExAcquireResourceExclusiveLite(&_lock, TRUE);
        defer{ ExReleaseResourceLite(&_lock); };

        _connection = std::move(connection);
        KeSetEvent(&_connect_event, 0, FALSE); // Signal worker of new connection
        return STATUS_SUCCESS;
    }

    _IRQL_requires_max_(APC_LEVEL)
    NTSTATUS Worker::EnforceSync(_In_ const Event::Event& evt, _Out_ bool* Deny) noexcept
    {
        *Deny = false;

        // Frame = 8-byte batch header (Count=1, reply-expected) ++ one record.
        const ULONG rec_size = evt.SerializedSize();
        const ULONG frame_size = sizeof(UINT32) + sizeof(UINT16) * 2 + rec_size;

        PVOID frame = ExAllocatePool2(POOL_FLAG_NON_PAGED, frame_size, 'EVT1');
        if (frame == NULL)
            return STATUS_NO_MEMORY;
        defer{ ExFreePool(frame); };

        BYTE* p = (BYTE*)frame;
        *(UINT32*)(p + 0) = frame_size;                  // TotalSize
        *(UINT16*)(p + 4) = Event::Wire::Version;        // Version = 2
        *(UINT16*)(p + 6) = (UINT16)(1 | 0x8000);        // Count=1 | FRAME_REPLY_EXPECTED
        NTSTATUS status = evt.Serialize(p + 8, rec_size);
        if (status != STATUS_SUCCESS)
            return status;

        // Send under a shared lock so an unpublish (disconnect) waits for us.
        ExAcquireResourceSharedLite(&_conn_lock, TRUE);
        defer{ ExReleaseResourceLite(&_conn_lock); };

        if (_active_conn == nullptr)
            return STATUS_PORT_DISCONNECTED; // no service → fail open (Deny stays false)

        return _active_conn->SendWithReply(frame, frame_size, Deny);
    }

    _IRQL_requires_same_
    _Function_class_(KSTART_ROUTINE)
    VOID Worker::Routine(_In_ PVOID Context)
    {
        auto& worker = *reinterpret_cast<Worker*>(Context);
        auto& queue = worker._queue;
        defer{ PsTerminateSystemThread(STATUS_SUCCESS); };

        Header* header = (Header*)worker._serialized_buffer;

        while (true)
        {
            PVOID events[] = { &worker._stop_event, &worker._connect_event };
            auto status = KeWaitForMultipleObjects(
                2,          // Count
                events,     // Objects to wait on
                WaitAny,    // Wait type
                Executive,  // Wait reason
                KernelMode, // Wait mode
                FALSE,      // Alertable
                NULL,       // Timeout
                NULL        // Wait block array
            );

            if (status == STATUS_WAIT_0) // WorkerStopEvent signaled
            {
                TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "Worker: Stop event signaled, exiting worker thread");
                return;
            }
            if (status == STATUS_WAIT_0 + 1) // _connect_event signaled
            {
                ExAcquireResourceExclusiveLite(&worker._lock, TRUE);
                krn::unique_ptr<MiniFilter::Connection> connection(std::move(worker._connection));
                ExReleaseResourceLite(&worker._lock);

                TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "Worker: Connect event signaled, processing connection");

                // Publish the connection so enforcement callbacks can send
                // synchronously. Unpublished (under the lock, so in-flight enforcers
                // drain first) before `connection` is destroyed at scope exit.
                ExAcquireResourceExclusiveLite(&worker._conn_lock, TRUE);
                worker._active_conn = connection.get();
                ExReleaseResourceLite(&worker._conn_lock);
                defer{
                    ExAcquireResourceExclusiveLite(&worker._conn_lock, TRUE);
                    worker._active_conn = nullptr;
                    ExReleaseResourceLite(&worker._conn_lock);
                };

                bool connected = true;
                while (connected)
                {
                    PVOID events2[] = { &worker._stop_event, &queue._push_event };
                    auto status2 = KeWaitForMultipleObjects(
                        2,          // Count
                        events2,    // Objects to wait on
                        WaitAny,    // Wait type
                        Executive,  // Wait reason
                        KernelMode, // Wait mode
                        FALSE,      // Alertable
                        NULL,       // Timeout — nothing is staged, wait for events
                        NULL        // Wait block array
                    );

                    if (status2 == STATUS_WAIT_0) // WorkerStopEvent signaled
                    {
                        TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "Worker: Stop event signaled, exiting worker thread");
                        return;
                    }

                    // PushEvent signaled: ship each queued event immediately —
                    // no staging/batching, so detection latency is one queue hop.
                    KeResetEvent(&queue._push_event);

                    while (connected)
                    {
                        // Pop one event; do not hold the queue lock across Send.
                        krn::unique_ptr<Event::Event> event;
                        ExAcquireResourceExclusiveLite(&queue._lock, TRUE);
                        if (!queue._events.empty())
                        {
                            event = std::move(queue._events.front());
                            queue._events.pop();
                        }
                        ExReleaseResourceLite(&queue._lock);

                        if (!event)
                            break; // Queue drained, go back to waiting

                        if (sizeof(Header) + event->SerializedSize() > SERIALIZED_BUFFER_SIZE)
                        {
                            TraceEvents(TRACE_LEVEL_WARNING, TRACE_DRIVER, "Worker: Dropping oversized event (%lu bytes)", event->SerializedSize());
                            continue;
                        }

                        *header = Header();
                        event->Serialize(header->Data, SERIALIZED_BUFFER_SIZE - sizeof(Header));
                        header->TotalSize += event->SerializedSize();
                        header->Count = 1;

                        TraceEvents(TRACE_LEVEL_VERBOSE, TRACE_DRIVER, "Worker: Sending event (%lu bytes) to client", header->TotalSize);

                        auto send_status = connection->Send(worker._serialized_buffer, header->TotalSize);
                        if (send_status == STATUS_TIMEOUT)
                        {
                            // Service was momentarily slow to drain (FilterGetMessage),
                            // NOT gone. Dropping the client port here would make its
                            // next FilterGetMessage fail and the service exit. Drop
                            // just this telemetry event and keep the connection.
                            TraceEvents(TRACE_LEVEL_WARNING, TRACE_DRIVER, "Worker: Send timed out, dropping event, keeping connection");
                        }
                        else if (send_status != STATUS_SUCCESS)
                        {
                            TraceEvents(TRACE_LEVEL_ERROR, TRACE_DRIVER, "Worker: Failed to send message to client -> status: %!STATUS!", send_status);
                            connected = false; // Connection genuinely gone, wait for the next connection
                        }
                    }
                }
            }
        }

    }
}