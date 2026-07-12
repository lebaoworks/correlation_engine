# Two-plane transport — driver spec (§9 kernel-arm pushdown)

Goal: **enforcement latency falls only on events that can actually block.** Almost
everything is fire-and-forget telemetry; a tiny, dynamically-chosen set of
`(process identity, op)` pairs is enforced synchronously, inline.

**Status.** Both sides are implemented. The Rust side is tested
(`engine/src/endpoint.rs` `ArmCmd`/`reconcile_arms`, `service/src/control.rs`,
`service/src/sensor.rs` reply-expected flag). The C++ side (`ArmTable.*`,
`Connection::SendWithReply`, `Worker::EnforceSync`, the control
`MessageNotifyCallback`, enforcement in `ProcessMonitor`) **compiles and links
cleanly** with the WDK (toolset `WindowsKernelModeDriver10.0`, WDK 10.0.26100) —
`SnsDrv.sys` builds and signs with 0 warnings. Built via MSBuild invoked from WSL:

```
MSBuild.exe SnsDrv.vcxproj /t:Build /p:Configuration=Debug /p:Platform=x64
```

(The build also reports an `InfVerif.dll` load failure — an environment quirk of
the INF-verification step in this WDK install, unrelated to the source or the
`.inf`; the `.sys` is produced regardless.)

Compiling is not running: the runtime behavior (IRQL on the sync send, the
control-buffer probe, and the connection-lifetime lock ordering) still needs a
real load test on a Windows target / VM. This document is the design reference.

## The three planes

```
Telemetry (async, majority)   callback → serialize (Event.hpp v2) → ring/port → service → engine
Control   (service → driver)  ARM/DISARM records (control.rs, 16 B each) → driver arm table
Enforce   (sync, rare)        callback: (pid,op) ∈ arm table OR ∈ static predicate
                              → FltSendMessage WITH reply → wait verdict → allow/deny inline
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

## Control port (new, second communication port)

Add a second `FltCreateCommunicationPort` (e.g. `\SnsDrvControlPort`) with a
`MessageNotifyCallback`. The service sends `control.rs` frames (concatenated
16-byte records). On each record:

```
Kind==1 (Arm)    → insert {Pid, PidStartMs, Op(rec[1])} into the arm table
Kind==2 (Disarm) → remove every entry with this {Pid, PidStartMs} (any op)
```

Op codes: see `control.rs::op_code` (exec=1, read=2, write=3, inject=4, …).

## Callback routing (the actual latency win)

Each monitor callback (ProcessMonitor / MiniFilter / Network) decides per event:

```
must_enforce = arm_table.contains(actor_pid, actor_startMs, op)
            || static_predicate(op, event)        // see below
if must_enforce:
    serialize event → FltSendMessage(..., replyBuffer=1 byte, timeout=T)
    verdict = replyBuffer[0]                        // 1 = deny
    if timed out: verdict = policy_default          // fail-open or fail-closed
    enforce verdict in this callback (block the operation) and RETURN
else:
    serialize event → send async (no reply)         // current path
```

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

## Removing Queue/Worker

With enforce-events sent inline from the callback and telemetry going to the ring,
the staging `Worker`/`Queue` is no longer the latency path. Keep a queue only as a
pre-connection buffer if you want to retain events emitted before the service
attaches; otherwise delete it. `FltSendMessage` is internally synchronized, so
concurrent callbacks sending on one port is supported.

## Ordering / correlation caveat (must handle in the service, already noted)

A block decision depends on prior events the engine must have already ingested.
The service feeds the engine from a single ordered consumer, and on a sync enforce
it must **drain pending telemetry into the engine first**, then feed the enforce
event, then reply — so the storyline context is never missing when the verdict is
computed. (Service-side work; the driver just needs to preserve per-event order on
each plane.)
```
