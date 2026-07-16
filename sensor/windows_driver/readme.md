# SnsDrv (Rust) — kernel-mode EDR sensor minifilter

Rust port of the C++ sensor in [`../windows_driver2/SnsDrv`](../windows_driver2/SnsDrv),
built on [windows-drivers-rs](https://github.com/microsoft/windows-drivers-rs)
(`wdk-sys` bindings) and modelled on the build/toolchain setup of
[0xflux/sanctum](https://github.com/0xflux/sanctum). The long-term goal is for this
crate to **replace** `windows_driver2`; until it reaches parity the C++ driver stays
as the reference.

## What it does

The sensor observes file/process activity in the kernel and feeds each observation to
the **in-kernel detection engine** through a single seam, `engine::submit`. The
engine is being moved into the kernel; until it lands, `submit` is a stub that traces
and counts. There is **no user-mode transport** — the earlier shared-memory ring is
gone, precisely because the engine no longer lives in user space.

The `\SnsDrvPort` minifilter communication port is kept open as a reserved
connect/disconnect endpoint, but it defines no commands today.

## Bindings

Base NT bindings come from **`wdk-sys`**: functions from `wdk_sys::ntddk`, types from
`wdk_sys::types`, constants from `wdk_sys::constants`. The runtime — a pool-backed
global allocator and a panic handler — comes from `wdk-alloc` / `wdk-panic`.

`wdk-sys` 0.5 has **no filesystem-minifilter surface** (no `fltKernel.h`, no `fltmgr`
feature), so the `Flt*` API and its structs are declared in a small, self-contained
shim, [`src/fltmgr.rs`](src/fltmgr.rs), reusing `wdk-sys` base types. It links against
`fltMgr.lib` (see `build.rs`). This is the only hand-rolled FFI in the crate.

## Status

### Done (this crate)

- WDK-Rust build system: `Cargo.toml`, `build.rs`, `makefile.toml`, `rust-toolchain.toml`,
  `.cargo/config.toml`, `SnsDrv.inx`.
- `DriverEntry` + minifilter unload teardown; `Driver` singleton (`src/lib.rs`).
- Minifilter: pre-`IRP_MJ_WRITE`, first-write-per-handle `FileWrite` (`src/minifilter.rs`).
- Event domain model handed to the engine (`src/event.rs`).
- Engine seam / stub sink (`src/engine.rs`).
- Reserved (empty) control port `\SnsDrvPort` (`src/port.rs`).

### TODO

- The **in-kernel detection engine** behind `engine::submit` (the reason the ring was
  removed). Everything upstream is already routed to that one function.
- More sources feeding `engine::submit`: `PsSetCreateProcessNotifyRoutineEx`
  (ProcessCreate/Exit), `ObRegisterCallbacks` (ProcessOpen),
  `PsSetCreateThreadNotifyRoutine` (RemoteThreadCreate). The `event::Body` variants
  for these already exist.
- Inline enforcement once the engine can render a verdict in-kernel (no user-mode
  round-trip needed anymore).

## Module map (vs `windows_driver2/SnsDrv`)

| Rust (`src/`)   | C++ counterpart               |
| --------------- | ----------------------------- |
| `lib.rs`        | `Entry.cpp`                   |
| `event.rs`      | `Event.hpp` (types only)      |
| `engine.rs`     | *(new: in-kernel engine seam)* |
| `minifilter.rs` | `MiniFilter.cpp` (filter)     |
| `port.rs`       | `MiniFilter.cpp` (port)       |
| `fltmgr.rs`     | *(FltMgr FFI shim — wdk-sys gap)* |
| `log.rs`        | `trace.h` / WPP               |

Removed relative to the first draft: `ring.rs`, `arm_table.rs`, `wire.rs` (byte
serialization) and the hand-rolled `ffi.rs` — all obsoleted by moving the engine
in-kernel and switching to `wdk-sys`.

## Building (Windows only)

Requires: Windows, the WDK + matching SDK, Visual Studio Build Tools (MSVC), a nightly
Rust toolchain (pinned in `rust-toolchain.toml`), `cargo-make`, and LLVM. This crate
is intentionally **excluded from the workspace** at the repo root (it is `no_std`,
nightly, and targets `x86_64-pc-windows-msvc`).

```powershell
cd sensor\windows_driver
$env:LIBCLANG_PATH = "C:\Program Files\LLVM\bin"
cargo build           # -> target\x86_64-pc-windows-msvc\debug\snsdrv.dll (the driver image)
```

For a signed `.sys/.inf/.cat` package see **Packaging** below. It does **not** build
on Linux (no WDK / kernel target).

### Verified build (2026-07)

`cargo build` on the Windows host produces `snsdrv.dll` — a native-subsystem kernel
image with `DriverEntry` as its entry point (rename to `.sys` + sign for loading;
`cargo make` automates that). What the build needs, learned the hard way:

- **VS2022 + WDK 10.0.26100** (MSVC linker, `ntoskrnl.lib`/`fltMgr.lib`, headers).
- **Rust nightly** with `rust-src`, target `x86_64-pc-windows-msvc`.
- **LLVM** for `libclang` (wdk-sys runs `bindgen`); set `LIBCLANG_PATH=C:\Program
  Files\LLVM\bin`.
- **`+crt-static`** in `.cargo/config.toml` — wdk-build errors `StaticCrtNotEnabled`
  otherwise.
- `build.rs` calls `wdk_build::configure_wdk_binary_build()` (name differs across
  wdk-build versions).
- **`fma`/`fmaf` stubs** in `lib.rs` — `compiler_builtins`' libm references them and
  the kernel image (`/NODEFAULTLIB`) has no C math lib; the driver uses no FP, so the
  stubs only satisfy the linker.

The unused-`event` dead-code warnings are expected until the Phase-2 callbacks land.

## Packaging (test-signed .sys/.inf/.cat)

Two ways to produce the signed driver package:

- **`cargo make`** — the intended flow, but its wdk-build makefile bootstrap
  symlinks `rust-driver-makefile.toml` into `target/` (its `path = "."` dep only
  resolves through that link). Creating the symlink needs **Developer Mode**, an
  elevated shell, or an **eWDK developer prompt**. Without one it fails at
  `wdk-build-init`.

- **`package.ps1`** — a no-elevation alternative that drives the WDK tools directly
  (verified on 2026-07): `stampinf` → `Inf2Cat` → self-signed cert → `signtool`.

  ```powershell
  $env:LIBCLANG_PATH = "C:\Program Files\LLVM\bin"
  .\package.ps1            # or .\package.ps1 -Release
  ```

  Output in `target/package/`: `SnsDrv.sys` (signed), `snsdrv.cat` (signed),
  `SnsDrv.inf` (stampinf'd), `WDRLocalTestCert.cer`. `signtool verify` reporting an
  untrusted root is expected for a self-signed cert — install the `.cer` (below) or
  enable test signing to make the chain trust.

Gotchas that bit us: the `ActivityMonitor` `ClassGuid` in `SnsDrv.inx` must be the
real `{b86dff51-a31e-4bac-b3cf-e8cfe75c9fc2}`; `Inf2Cat.exe` ships **x86-only** under
`bin\<ver>\x86`; the crate's `wdk-build` build-dep must match the version `wdk-sys`
pulls (else `MultipleWdkBuildCratesDetected`).

## Verifying end-to-end (test-signed VM)

1. Enable test signing (`bcdedit /set testsigning on`) and reboot.
2. Install + load: `sc create SnsDrv type= filesystem binPath= C:\...\SnsDrv.sys`,
   then `fltmc load SnsDrv`.
3. Write to a file → the pre-write callback fires `engine::submit`; confirm the
   `engine::submit #N FileWrite pid=...` line in a kernel debugger / DebugView.
4. `fltmc unload SnsDrv` → the filter unregisters cleanly.

## Notes for maintainers

- The FltMgr struct layouts in `fltmgr.rs` are the documented x64 WDK layouts. If a
  future WDK changes them, `FltRegisterFilter` will reject the registration — validate
  against `fltKernel.h` there.
- All callbacks/entry use `extern "C"` (identical to the kernel ABI on x64).
