# Two-plane transport — driver spec (§9 kernel-arm pushdown)

Goal: **enforcement latency falls only on events that can actually block.** Almost
everything is fire-and-forget telemetry; a tiny, dynamically-chosen set of
`(process identity, op)` pairs is enforced synchronously, inline.

**Status.** Both sides are implemented. The Rust side is tested
(`engine/src/endpoint.rs` `ArmCmd`/`reconcile_arms`, `endpoint_service/src/control.rs`,
`endpoint_service/src/sensor.rs` reply-expected flag + `req_id`,
`endpoint_service/src/ringbuf.rs` for the ring protocol itself). The C++ side
(`ArmTable.*`, `Ring::EnforceSync`, `Ring::PendingVerdicts`, the control
`MessageNotifyCallback`, enforcement in `ProcessMonitor`) is built with the WDK
(toolset `WindowsKernelModeDriver10.0`, WDK 10.0.26100) via MSBuild invoked from WSL:

```
MSBuild.exe SnsDrv.vcxproj /t:Build /p:Configuration=Debug /p:Platform=x64
```

(The build also reports an `InfVerif.dll` load failure — an environment quirk of
the INF-verification step in this WDK install, unrelated to the source or the
`.inf`; the `.sys` is produced regardless.)

Compiling is not running: the runtime behavior (the MDL map/unmap and its process
context, rundown ordering on disconnect, and the doorbell fences) still needs a real
load test on a Windows target / VM, under Driver Verifier. This document is the
design reference; the transport itself is specified in `readme.md` and
`endpoint_service/src/ringbuf.rs`.

## The three planes

```
Telemetry (async, majority)   callback → serialize into ring slot (Event.hpp v2) → service → engine
Control   (service → driver)  ARM/DISARM/REGISTER_RING/VERDICT records (control.rs, 16 B each)
Enforce   (sync, rare)        callback: (pid,op) ∈ arm table OR ∈ static predicate
                              → publish to the ring tagged reply-expected + ReqId
                              → wait on a stack KEVENT → allow/deny inline
```

## Arm table (new driver state)

A small concurrent set, keyed by identity + op:

```
key   = { UINT32 Pid; INT64 PidStartMs; BYTE Op; }   // PidStartMs = FILETIME/10000
value = (presence)
```

- **Lookup on the hot path must be lock-free-ish.** Expected size is tiny (a
  handful of live chokepoints), so a small open-addressed array scanned under a
  push-lock held *shared*, or an RCU-style pointer swap, is fine. Do **not** take
  a global exclusive lock per callback.
- Match rule in a callback: compute `startMs = PsGetProcessCreateTimeQuadPart(...) / 10000`
  for the acting process, then test `{Pid, startMs, Op}` against the table. The
  `/10000` truncation mirrors `translate.rs::ms()`, so identities line up with the
  engine's `NodeKey::Process { pid, start_ts }`. (Pid + ms-start collides only if a
  pid is recreated within the same millisecond — negligible.)

## Control port

*(This section originally proposed a second, dedicated control port. It was not
needed: telemetry left the port entirely for the ring, so the one port at
`\SnsDrvPort` carries nothing but control and is not on any hot path.)*

`ControlMessageNotify` in `MiniFilter.cpp` takes `control.rs` frames (concatenated
16-byte records — every kind is exactly 16 bytes, so the parse stays a flat loop).
On each record:

```
Kind==1 (Arm)           → insert {Pid, PidStartMs, Op(rec[1])} into the arm table
Kind==2 (Disarm)        → remove every entry with this {Pid, PidStartMs} (any op)
Kind==3 (SetSelf)       → record the service pid (exempt from enforcement, see below)
Kind==4 (RegisterRing)  → allocate + map the ring; reply with the mapped address
Kind==5 (Verdict)       → complete the enforce request ReqId and wake its waiter
```

Op codes: see `control.rs::op_code` (exec=1, read=2, write=3, inject=4, …).

## Callback routing (the actual latency win)

Each monitor callback (ProcessMonitor / MiniFilter / Network) decides per event:

```
must_enforce = arm_table.contains(actor_pid, actor_startMs, op)
            || static_predicate(op, event)        // see below
if must_enforce:
    Ring::EnforceSync(event, &deny)                 // publish reply-expected + ReqId,
                                                    // wait on a stack KEVENT (1 s)
    if timed out: deny = false                      // fail open
    enforce verdict in this callback (block the operation) and RETURN
else:
    Ring::PublishTelemetry(event)                   // serialize into a slot, return
```

Both build the event **on the stack**: each sink serializes it into the ring before
returning, so it never outlives the callback frame. That is one pool allocation per
event that the old queue-based path could not avoid.

### `static_predicate` — why the arm table is not enough alone

Arming predicts a block **one step ahead**, so it only covers *multi-step*
patterns (dropper, ransomware — the engine arms the encrypting-write before it
happens). A **single-step chokepoint** (e.g. the LSASS read: the first matching
event both crosses the threshold *and is* the chokepoint) can never be pre-armed.

For those, the driver must send that one narrow event class synchronously by
default. The set is derivable from the loaded rules (ops/conditions that appear
in a `block` step of a single-step pattern) and is already what the kernel
pre-filters — e.g. ProcessMonitor only emits an lsass open with sensitive access.
So the static-sync volume stays tiny. Push this predicate down once at rule load
(same control port, a third record kind) or hardcode the current single case
(lsass read + VM_READ) if you prefer to ship sooner.

## Mandatory: exempt the service process

Any callback for the service's own pid must **skip enforcement** (send async or
nothing). Otherwise: the service opens a file while handling a sync enforce →
that open is itself enforce-pending → waits on the service → **deadlock**. Record
the service pid at control-port connect time and short-circuit it everywhere.

## Removing Queue/Worker — done

`Worker`/`Queue` are gone, along with `Connection` and every `FltSendMessage` in the
driver. Callbacks publish straight into the ring, which removed per event: a pool
allocation for the `Event`, an `ExAcquireResourceExclusiveLite`, a thread wake, and
a kernel↔user round trip. Events emitted before the service attaches are simply
dropped (there is no ring to hold them) — a pre-connection buffer was considered and
rejected: it would be state to age out and reconcile for telemetry nobody is
listening to yet.

## Ordering / correlation — now structural, not a caveat

This was a live hazard in the old design and is worth recording as resolved. A block
decision depends on prior events the engine must already have ingested. Previously
telemetry went through the worker thread while enforcement went **straight from the
callback** to the port — two independent senders, no ordering guarantee, so the
engine could be asked to rule on an event whose predecessors were still queued.

Enforcement now travels the *same ring* as telemetry, and the service drains it from
a single ordered consumer. A request therefore cannot reach the engine before the
events published ahead of it. The ordering is a property of the transport; neither
side has to do anything to preserve it.
```
