# EDR engine + sensor

Lõi phát hiện (**detection engine**) và **sensor** endpoint. Engine được viết từ đầu theo lộ trình
tăng dần (`engine_base → v0.0.1 → v0.0.2 → bounded`), `no_std + alloc`, zero-dep — chạy được cả
usermode lẫn **inline trong kernel driver Windows**.

- Thiết kế thuật toán: [`docs/`](docs/) — `engine_base.md`, `engine_v0.0.1.md`, `engine_v0.0.2.md`,
  `todo.md` (lộ trình), `replay.md` (dataset).
- Kiến trúc sensor: [`sensor/windows_driver/SnsDrv/readme.md`](sensor/windows_driver/SnsDrv/readme.md).

## Kiến trúc

```
rule text ──engine_rules──▶ wire "ERD1" ──C_SET_RULES──▶ ┌─────────────── kernel ───────────────┐
(endpoint_service, usermode)                              │ SnsDrv (C++ WDK)  +  engine_core.lib  │
                                                          │ callback → tag TTP → engine_on_event  │
event (exec/write/open/read) ─────────────────────────────▶ verdict → deny inline (ArmTable)     │
                                                          └───────────────────────────────────────┘
```

Engine **chạy trong kernel**: driver bắt event → tag TTP (theo op) → gọi `engine_core` → verdict →
chặn tại chỗ. `endpoint_service` co lại thành bộ **compile rule + ship xuống** driver.

## Cấu trúc workspace

| Crate / thư mục | Vai trò |
|---|---|
| [`engine_core/`](engine_core/) | Lõi phát hiện `no_std`. Bản `v0_0_2` (usermode) + `v0_0_2_bounded` (kernel, fixed-capacity, không cấp phát hot-path). C-ABI ở `src/ffi.rs` (feature `kernel`), header [`include/engine.h`](engine_core/include/engine.h). |
| [`engine_rules/`](engine_rules/) | Compile rule text → `RuleSet`/`DagRuleSet` hoặc wire bytes (`ERL1`/`ERD1`). |
| [`engine_replay/`](engine_replay/) | Regression: dataset `docs/replay.md` chạy qua các bản engine. |
| [`endpoint_service/`](endpoint_service/) | Service usermode: compile rule DAG rồi ship xuống sensor qua control port. |
| [`sensor/windows_driver/`](sensor/windows_driver/) | Driver kernel C++ (WDK) `SnsDrv` — link `engine_core.lib`, chạy engine inline. |
| `engine/`, `proto/`, `backend_service/` | Thành phần cũ (v1) — không thuộc dòng engine mới. |

## Yêu cầu

- **Rust** stable (host) + target bare-metal để kiểm `no_std`:
  ```
  rustup target add x86_64-unknown-none
  ```
- **Build kernel (Windows only):** Visual Studio 2022 + **WDK 10** (đã cài, toolset
  `WindowsKernelModeDriver10.0`), và một Rust toolchain Windows (target `x86_64-pc-windows-msvc`)
  cho `engine_core.lib`.

---

## Build

### 1. Engine (Rust, host) — nhanh, kiểm logic
```
cargo build                                          # cả workspace
cargo check -p engine_core --target x86_64-unknown-none   # xác nhận no_std
```

### 2. `engine_core.lib` cho kernel (Windows)
Static lib để driver link. Dùng script sẵn (dựng vcvars + cargo với feature `kernel`, `panic=abort`):
```
build-engine-kernel-lib.cmd
```
→ `target/x86_64-pc-windows-msvc/release/engine_core.lib`.

> Script tham chiếu đường dẫn VS/cargo cụ thể — sửa `build-engine-kernel-lib.cmd` cho máy bạn nếu
> khác. Feature `kernel` bật global-allocator/panic-handler chuyển tiếp xuống driver
> (`SnsDrv/EngineRt.cpp`), và chọn engine bản `v0_0_2_bounded` (không panic OOM trên hot-path).

### 3. Driver `SnsDrv` (Windows, cần `engine_core.lib` ở bước 2)
```
msbuild sensor\windows_driver\Sensor.sln /p:Configuration=Debug /p:Platform=x64 /m
```
→ `sensor\windows_driver\x64\Debug\SnsDrv.sys` (+ `snsdrv.cat`, test-signed).

> Đường dẫn `msbuild.exe` tuỳ máy, ví dụ:
> `"C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe"`.
> Cảnh báo `InfVerif.dll` khi build dưới WSL là **không chặn** — `.sys`/`.cat` vẫn được tạo và ký.

### 4. `endpoint_service` (usermode)
```
cargo build -p edr-endpoint-service --release
```

---

## Load (nạp driver + rule)

> Cần **Administrator** và **test-signing mode** (driver ký test): `bcdedit /set testsigning on`
> rồi reboot. Chỉ chạy trên máy/VM thử nghiệm.

1. Cài + chạy driver:
   ```
   sc create SnsDrv type= kernel binPath= C:\path\SnsDrv.sys
   sc start  SnsDrv
   ```
2. Chạy service — nó kết nối `\SnsDrvPort`, đăng ký pid của mình, và **push ruleset DAG** xuống
   engine trong kernel (`C_SET_RULES`); từ đó driver bắt đầu phát hiện:
   ```
   edr-endpoint-service            # (thêm --help để xem cờ)
   ```
   Rule mặc định: [`endpoint_service/rules/dag.rules`](endpoint_service/rules/dag.rules).
3. Gỡ:
   ```
   sc stop SnsDrv && sc delete SnsDrv
   ```

> **Chưa nạp rule thì engine trả `IGNORE` hết** — service phải chạy và push rule để có phát hiện.

---

## Test

```
# toàn bộ engine (unit + regression + FFI + vi sai bounded↔v0.0.2)
cargo test -p engine_core -p engine_rules -p engine_replay

# service (gồm test compile dag.rules → wire)
cargo test -p edr-endpoint-service

# in bảng replay (dataset docs/replay.md qua bản engine hiện hành)
cargo run -p engine_replay
```

Điểm đáng chú ý được test tự động hoá:
- **Vi sai các bản engine**: `base ↔ v0.0.1` cho verdict giống hệt; `v0_0_2_bounded` không bao giờ
  enforce mạnh hơn `v0.0.2` (`vb ≤ va`), bằng khít khi chưa chạm trần.
- **FFI roundtrip**: `engine_create/on_event/destroy` qua C-ABI khớp verdict (kịch bản đảo thứ tự).
- **Chuỗi đảo thứ tự**: `v0.0.1` (tuyến tính) bỏ lọt, `v0.0.2` (DAG) bắt trọn — chứng minh giá trị
  của partial-order (`engine_replay/tests/replay.rs`).
