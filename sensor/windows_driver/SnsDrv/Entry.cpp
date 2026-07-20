/********************
*     Includes      *
********************/

#include "krn.hpp"

// Logging via tracing
#include "trace.h"
#include "Entry.tmh"

// Functional
#include "MiniFilter.hpp"
#include "Ring.hpp"
#include "Callbacks.hpp"
#include "WPF.hpp"
#include "ArmTable.hpp"
#include "Engine.hpp"

/*********************
*    Declarations    *
*********************/
#ifndef ALLOC_PRAGMA
#error "ALLOC_PRAGMA must be defined to compile this driver."
#endif

#ifdef __cplusplus
extern "C" { DRIVER_INITIALIZE DriverEntry; }
#endif

static DRIVER_UNLOAD DriverUnload;

struct Driver;

// Free up the memory taken by DriverEntry after initialization
#pragma alloc_text (INIT, DriverEntry)

/*********************
*     Global Vars    *
*********************/

#pragma data_seg("NONPAGED")
static Driver* GlobalDriver = nullptr;
static Ring::Buffer* GlobalRingBuffer = nullptr;
static Arm::Table* GlobalArmTable = nullptr;
static Engine::Instance* GlobalEngine = nullptr;
#pragma data_seg()

// Telemetry sink handed to the monitors: serialize straight into the shared ring.
// No queue, no worker thread, no allocation — the callback returns as soon as the
// bytes are in the slot. Capture-less lambda → function pointer.
static NTSTATUS TelemetryThunk(const Event::Event& evt)
{
    if (GlobalRingBuffer == nullptr)
        return STATUS_PORT_DISCONNECTED;
    return GlobalRingBuffer->PublishTelemetry(evt);
}

// In-kernel enforcement: feed the event to engine_core inline and take its verdict
// directly — no round-trip to the service. Fails open if the engine is gone.
// engine_core keeps DISARMED internally, so a later event carrying a disarmed op
// returns BLOCK on its own; the driver needs no arm-table mirroring for that.
static NTSTATUS EngineEnforceThunk(const Event::Event& evt, bool* deny)
{
    if (GlobalEngine == nullptr)
    {
        *deny = false;
        return STATUS_PORT_DISCONNECTED;
    }
    return GlobalEngine->Feed(evt, deny);
}

/*********************
*   Implementations  *
*********************/

struct Driver : public krn::failable, public krn::tag<'EVT0'>
{
private:
    MiniFilter::Filter* _filter = nullptr;
    MiniFilter::Port*   _port   = nullptr;
    Ring::Buffer*       _ring   = nullptr;
    Process::Monitor*   _monitor = nullptr;
    WPF::Monitor*       _netmon = nullptr;
    Arm::Table*         _armtable = nullptr;
    Engine::Instance*   _engine = nullptr;

public:
    Driver(DRIVER_OBJECT* DriverObject) noexcept
    {
        NTSTATUS& status = krn::failable::_status;

        // Initialize Arm table (consulted by callbacks; must outlive Worker/monitors)
        {
            auto result = krn::make<Arm::Table>();
            status = result.status();
            if (status != STATUS_SUCCESS)
            {
                TraceEvents(TRACE_LEVEL_ERROR, TRACE_DRIVER, "Initialized ArmTable -> status: %!STATUS!", status);
                return;
            }
            _armtable = result.release();
        }
        defer{ if (status != STATUS_SUCCESS) { delete _armtable; _armtable = nullptr; } };
        GlobalArmTable = _armtable;

        // Initialize the in-kernel detection engine (engine_core). Created empty;
        // endpoint_service pushes a compiled ruleset down later (Engine::Load).
        // Must exist before Filter/Monitor register callbacks that feed it.
        {
            auto result = krn::make<Engine::Instance>();
            status = result.status();
            if (status != STATUS_SUCCESS)
            {
                TraceEvents(TRACE_LEVEL_ERROR, TRACE_DRIVER, "Initialized Engine -> status: %!STATUS!", status);
                return;
            }
            _engine = result.release();
        }
        defer{ if (status != STATUS_SUCCESS) { delete _engine; _engine = nullptr; } };
        GlobalEngine = _engine;

        // Initialize the shared telemetry ring. It holds no memory until the service
        // connects and asks for it (C_REGISTER_RING); until then every publish is a
        // cheap no-op and enforcement fails open.
        {
            auto result = krn::make<Ring::Buffer>();
            status = result.status();
            if (status != STATUS_SUCCESS)
            {
                TraceEvents(TRACE_LEVEL_ERROR, TRACE_DRIVER, "Initialized Ring -> status: %!STATUS!", status);
                return;
            }
            _ring = result.release();
        }
        defer{ if (status != STATUS_SUCCESS) { delete _ring; _ring = nullptr; } };
        GlobalRingBuffer = _ring; // Store in global for callback access

        // Initialize MiniFilter
        {
            auto result = krn::make<MiniFilter::Filter>(DriverObject, TelemetryThunk, *_armtable, EngineEnforceThunk);
            status = result.status();
            if (status != STATUS_SUCCESS)
            {
                TraceEvents(TRACE_LEVEL_ERROR, TRACE_DRIVER, "Initialized MiniFilter -> status: %!STATUS!", status);
                return;
            }
            _filter = result.release();
        }
        defer{ if (status != STATUS_SUCCESS) { delete _filter; _filter = nullptr; } };

        // Create MiniPort object — the control plane only (arm/disarm, ring
        // registration, verdicts). Telemetry never goes through it.
        {
   	        UNICODE_STRING port_name = RTL_CONSTANT_STRING(L"\\SnsDrvPort");
   	        auto result = krn::make<MiniFilter::Port>(*_filter, &port_name, *_armtable, *_ring, *_engine);
   	        status = result.status();
            if (status != STATUS_SUCCESS)
            {
                TraceEvents(TRACE_LEVEL_ERROR, TRACE_DRIVER, "Initialized MiniPort -> status: %!STATUS!", status);
                return;
            };
            _port = result.release();
        }
        defer{ if (status != STATUS_SUCCESS) { delete _port; _port = nullptr; } };

        // Initialize Process Monitor
        {
            auto result = krn::make<Process::Monitor>(TelemetryThunk, *_armtable, EngineEnforceThunk);
            status = result.status();
            if (status != STATUS_SUCCESS)
            {
                TraceEvents(TRACE_LEVEL_ERROR, TRACE_DRIVER, "Initialized Process Monitor -> status: %!STATUS!", status);
                return;
            }
            _monitor = result.release();
        }
        defer{ if (status != STATUS_SUCCESS) { delete _monitor; _monitor = nullptr; } };

        // Network Monitor — DISABLED. Its WFP ALE_AUTH_CONNECT callout currently
        // emits NO events (only PERMIT + verbose trace), so it is pure dead weight,
        // and a loaded WFP callout is the prime suspect for the loopback TCP resets
        // (os 10053/10054) seen on the endpoint↔backend link — the transport is stable
        // on a clean host (see `--stress`). Re-enable only once the callout actually
        // ships events AND exempts loopback / handles classify rights correctly.
#if 0
        {
            auto result = krn::make<WPF::Monitor>(DriverObject, TelemetryThunk);
            status = result.status();
            if (status != STATUS_SUCCESS)
            {
                TraceEvents(TRACE_LEVEL_ERROR, TRACE_DRIVER, "Initialized Network Monitor -> status: %!STATUS!", status);
                return;
            }
            _netmon = result.release();
        }
        defer{ if (status != STATUS_SUCCESS) { delete _netmon; _netmon = nullptr; } };
#endif
    }

    ~Driver()
    {
        if (failable::status() != STATUS_SUCCESS)
            return;

        delete _port;   // Stop accepting new connections (also stops control pushdown)
        delete _monitor; // Stop process callbacks (they consult the arm table / enforce)
        delete _netmon; // Stop monitoring network events
        delete _filter; // Close the filter => stop accepting new events
        // Callbacks that fed the engine are stopped above; safe to drop it now.
        GlobalEngine = nullptr; // EngineEnforceThunk tests this; never leave it dangling
        delete _engine;
        // Only now can the ring go: its destructor unregisters, which waits out any
        // producer still mid-publish. Every source of publishes is stopped above.
        GlobalRingBuffer = nullptr; // the thunks test this; never leave it dangling
        delete _ring;
        delete _armtable; // Last: everything that referenced it is now gone
    }
};

_Function_class_(DRIVER_INITIALIZE)
_IRQL_requires_(PASSIVE_LEVEL)
_IRQL_requires_same_
NTSTATUS DriverEntry(
    _In_ DRIVER_OBJECT* DriverObject,
    _In_ UNICODE_STRING* RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);

    // Declare status variable for the initialization process
    NTSTATUS status = STATUS_SUCCESS;

    //
	// Initialize essential driver components
    //

    // Initialize WPP Tracing
    WPP_INIT_TRACING(DriverObject, RegistryPath);
    defer{ if (status != STATUS_SUCCESS) { WPP_CLEANUP(DriverObject); } };

    // Allow driver unload
    DriverObject->DriverUnload = DriverUnload;

    //
	// Initialize functional components
    //

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "Initializing");

    auto result = krn::make<Driver>(DriverObject);
    if (result.status() != STATUS_SUCCESS)
    {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_DRIVER, "Initialized Driver -> status: %!STATUS!", result.status());
        return result.status();
    }
    GlobalDriver = result.release();

    return STATUS_SUCCESS;
}

_Function_class_(DRIVER_UNLOAD)
_IRQL_requires_(PASSIVE_LEVEL)
_IRQL_requires_same_
VOID DriverUnload(_In_ DRIVER_OBJECT* DriverObject)
{
    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "Unloading");

    // Clean up functional components
    delete GlobalDriver;

	// Clean up WPP Tracing
    WPP_CLEANUP(DriverObject);
}