# edr-endpoint-service — cầu nối sensor(kernel) ↔ engine

Console app userland: nhận **batch event** từ sensor (minifilter `SnsDrv`), giải mã, chuẩn hoá
thành event của engine, đưa vào **detection engine** (load như library, crate `../engine`), in
quyết định ALLOW/DENY từng event + **chuỗi backend dựng lại** khi chặn, và **trả quyết định chặn
về sensor**.

## Chạy

Args parse bằng `clap`. **Mặc định**: nguồn = sensor live `--com-port \SnsDrvPort`,
ship lên backend `--remote-addr 127.0.0.1:7171`.

```bash
cargo run --bin edr-endpoint-service                          # (Windows) live sensor + ship backend (mặc định)
cargo run --bin edr-endpoint-service -- --com-port \SnsDrvPort --remote-addr 127.0.0.1:7171  # (đầy đủ, = mặc định)
cargo run --bin edr-endpoint-service -- --demo --in-process   # kịch bản LSASS-dump dựng sẵn, backend in-process (mọi nền tảng)
cargo run --bin edr-endpoint-service -- --file dump.bin       # replay batch nhị phân bắt từ driver
cargo run --bin edr-endpoint-service -- --stdin               # đọc batch từ stdin
cargo run --bin edr-endpoint-service -- --rules r.rules       # nạp rule khác
cargo run --bin edr-endpoint-service -- --help                # liệt kê đầy đủ cờ + default
cargo test
```

- **Nguồn** (loại trừ nhau): mặc định `--com-port` (live, chỉ Windows); override bằng
  `--file` / `--stdin` / `--demo`.
- **Backend**: mặc định ship qua TCP tới `--remote-addr` (`edr-backend-service`, crate
  `../backend_service`) trên **thread shipper riêng** — graph đầy đủ + STORYLINE hiển thị
  **trên console backend**. Dùng `--in-process` để chạy backend trong tiến trình (in tại chỗ),
  không mở TCP.

## Logging (`log` + `env_logger`)

Mức log theo quan hệ event ↔ automaton phát hiện:

| Trường hợp | Mức |
|---|---|
| Event **không khớp** automaton nào | `debug` |
| Event **khớp/tiến triển** một automaton (chưa xong chuỗi) | `info` |
| Event **hoàn thành chuỗi** (pattern accept / block) | `warn` |

Lọc bằng biến môi trường `RUST_LOG` (mặc định `info`, nên `debug` — các event không khớp
— ẩn cho tới khi cần):

```bash
RUST_LOG=info  edr-endpoint-service ...   # info + warn (mặc định)
RUST_LOG=debug edr-endpoint-service ...   # thấy cả event không khớp + mốc [winport]
RUST_LOG=warn  edr-endpoint-service ...   # chỉ chuỗi hoàn thành + lỗi
```

Format: `[HH:MM:SS.mmm LEVEL] <msg>` — cùng timestamp với backend để đối chiếu.

Demo in ra (đầu-cuối, chạy được trên mọi nền tảng):
```
[batch 2] 2 event → engine:
  ts=2000  exec  100.0    -> 800.2000   [exec] ALLOW
  ts=2100  read  800.2000 -> 50.900     [→lsass? T1003] DENY  [Block lsass_credential_dump 7.4]
=== STORYLINE (blocked)  pattern=lsass_credential_dump ... ***BLOCKED*** ...
  ⇒ quyết định gửi sensor: BLOCK
```

## Giao thức với sensor (khớp `sensor/windows_driver/SnsDrv`)

- **Kết nối**: communication port `\SnsDrvPort` (`FilterConnectCommunicationPort`).
- **Batch** (`Worker.cpp` Header): `TotalSize:u32le` (gồm cả chính nó) ++ các event nối tiếp.
- **Event** (`Event.hpp`): `Type:u8 ++ TimeStamp:i64le(100ns từ 1601)` ++ phần riêng; chuỗi là
  `Length:u16le(byte) ++ UTF-16LE`. Bộ mã hoá/giải mã ở `src/sensor.rs` khớp byte-for-byte.

## Ánh xạ event sensor → engine (`src/translate.rs`)

| Sensor event | Engine op | Ghi chú |
|---|---|---|
| `ProcessCreate` | `exec` | actor=parent, object=child, `image`+`cmd`; ghi bảng pid→{start,image} |
| `ProcessOpen` (VM_READ) | `read` | object=target; `target_image` (tra bảng) + `vm_read` → tagger T1003 |
| `FileOpen` | `open` | object=file (token = path — sensor chưa cấp FileId thật) |
| `RemoteThreadCreate` | `inject` | actor→target (causal) |
| `ProcessExist` / `ProcessExit` | — | chỉ cập nhật/khởi tạo bảng process (identity/target-image) |

Engine cần identity `(pid, start_ts)` chống pid-reuse; sensor `ProcessCreate` không cấp thời điểm
tạo nên service dùng timestamp event làm start của tiến trình con và **học bảng `pid → {start,
image}`** từ `ProcessCreate`/`ProcessExist` (đúng như một agent thật phải làm). Đó cũng là cách suy
ra *target image* của `ProcessOpen` (chỉ có target pid) để biết đó là LSASS.

## Trả quyết định chặn về sensor

Service tính quyết định **theo batch** (DENY nếu có event bị chặn) và gọi `source.reply(deny)`.
Trên Windows, `WinPortSource::reply` gửi 1 byte quyết định qua `FilterReplyMessage`.

> ⚠️ Driver hiện tại gửi **notify-only** (`FltSendMessage(..., NULL, 0, ...)`) và pre-op trả
> `FLT_PREOP_SUCCESS_NO_CALLBACK` → **chưa** chặn đồng bộ. Để chặn thật, driver cần: (a) gửi kèm
> reply buffer và cho pre-op *chờ* quyết định, hoặc (b) nhận **bảng arm theo identity** đẩy xuống
> rồi tự deny trong kernel (đúng mô hình `engine.md` §9). Đường reply đã hiện thực sẵn ở
> `src/winport.rs` để bật được ngay khi driver hỗ trợ.

## Phạm vi / giới hạn

- Sensor hiện chỉ phát process + file-open + process-open + remote-thread (chưa có **file write +
  entropy**), nên pattern ransomware (T1486) chưa dựng được từ sensor này; ca demo đầu-cuối là
  **LSASS credential dump (T1003)** — khớp đúng các event-type sensor có.
- `--com-port` (live sensor) chỉ build/chạy trên Windows (`#[cfg(windows)]`, FFI thô tới `fltlib`);
  trên nền khác dùng `--demo/--file/--stdin`. Lõi giải mã + ánh xạ + engine là cross-platform và có test
  (`tests/integration.rs`).
