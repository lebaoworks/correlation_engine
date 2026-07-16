# SDD — `edr-endpoint-service` (dịch vụ userland: sensor → engine → backend)

**Software Design Document** · crate `edr_endpoint_service` (v0.1.0)

> Tài liệu này mô tả *thiết kế phần mềm* của **dịch vụ endpoint** phía userland: cầu
> nối giữa **sensor** kernel (minifilter) và **lõi phát hiện** [`edr-engine`], cộng
> đường **uplink** ship telemetry/alert lên backend. Nó bổ trợ — không thay thế —
> [`SDD_engine.md`](SDD_engine.md) (lõi phát hiện) và tài liệu enforcement của sensor
> [`sensor/windows_driver/SnsDrv/EnforcementPlane.md`](../sensor/windows_driver/SnsDrv/EnforcementPlane.md).
> Nguồn sự thật là code trong [endpoint_service/src/](../endpoint_service/src/).

---

## 1. Giới thiệu

### 1.1 Mục đích
`edr-endpoint-service` là **console app** chạy ở userland trên endpoint. Trách nhiệm:

- **Nhận** sự kiện từ sensor kernel qua **shared-memory ring** (driver cấp phát non-paged
  pool rồi map vào service); cổng minifilter (`\SnsDrvPort`) chỉ còn mang control-plane.
- **Giải mã** wire format v2 nhị phân → `SensorEvent`, **chuẩn hoá** → engine `Event`.
- **Nạp** từng event vào lõi phát hiện inline ([`edr_engine::Endpoint`]) và **trả verdict**
  ALLOW/DENY về sensor trên đường enforcement đồng bộ.
- **Đẩy** control-plane arm/disarm xuống sensor (chỉ `(identity, op)` sát chokepoint mới
  enforce đồng bộ).
- **Ship** mọi event + alert lên **backend service** (ship-and-forget) qua TCP/protobuf,
  trên một thread riêng để backend chậm/mất không bao giờ chặn hot path.

### 1.2 Phạm vi
Crate là **lớp vận chuyển + điều phối**, không chứa logic phát hiện (nằm ở `edr-engine`)
và không định nghĩa serialization backend (nằm ở [`proto/`](../proto/)). Nó sở hữu:
giải mã wire sensor, ánh xạ sang model engine, đóng/mở cổng minifilter, mô hình luồng, và
uplink có tự-nối-lại. Enforcement thực thi nằm trong **sensor** kernel; engine core nằm ở
crate `edr-engine`.

### 1.3 Thuộc tính chất lượng (design drivers)
| Thuộc tính | Cách đạt được |
|---|---|
| **Latency enforcement thấp** | Verdict tính inline trên thread sự kiện; **reply sensor TRƯỚC** khi ship backend — §6.2 |
| **Backend không bao giờ chặn hot path** | Uplink chạy thread 2; thread 1 chỉ enqueue non-blocking, đầy thì drop — §6 |
| **Hot path gần zero-alloc** | Giải mã cấp phát string **một lần**, *move* xuyên suốt decode→Event→Wire; serialize ở thread 2 — §7 |
| **Chống pid-reuse xuyên biên** | Mọi record mang `(pid, create_time)`; control record khớp arm theo identity — §3, §5 |
| **Chạy được không cần driver** | Nguồn thay thế `--file/--stdin/--demo/--stress`; backend `--in-process` — §8 |
| **Fail fast & rõ** | Kết nối backend có timeout; lỗi I/O in kèm mã OS (10053/10054…) — §6.4 |

### 1.4 Thuật ngữ
- **Batch / frame** — một port message = một khung `TotalSize`-prefixed chứa ≥1 record.
- **Record** — một sự kiện sensor đã serialize (header 32B + body + strings).
- **Enforcement path (sync)** — frame có cờ `FRAME_REPLY_EXPECTED`: driver **chặn** thao
  tác đợi verdict; service phải `reply()`.
- **Telemetry (async)** — frame không cờ: fire-and-forget, không cần reply.
- **Arm** — control record đẩy xuống sensor để `(identity, op)` đi đường enforce đồng bộ.
- **Shipper** — thread 2, drain hàng đợi → ghi TCP backend, tự nối lại.

---

## 2. Tổng quan kiến trúc

### 2.1 Sơ đồ thành phần

```
   SENSOR (kernel minifilter)                    ENDPOINT SERVICE (userland)                 BACKEND
   ┌──────────────────────┐   wire v2 frame     ┌───────────────────────────────┐          ┌─────────┐
   │  SnsDrv               │ ══ SHARED RING ═══► │  Thread 1: vòng lặp sự kiện    │          │  edr-   │
   │  (Ring/ArmTable)      │   (không syscall)   │   ring → sensor::decode        │          │ backend │
   │                       │ ──doorbell KEVENT─► │   → translate → engine.on_event│  Wire    │ service │
   │                       │   (chỉ khi ngủ)     │   → reply sensor               │ (protobuf│         │
   │                       │                     │   → enqueue Wire (non-block)   │  /TCP)   │         │
   │  \SnsDrvPort          │ ◄─FilterSendMsg──── │                                │ ───────► │         │
   │  (control only)       │   ArmCmd/Register/  │  Thread 2: shipper_loop        │          └─────────┘
   └──────────────────────┘   Verdict           │   drain → encode_frame → ship  │
                                                 │   tự reconnect                 │
                                                 └───────────────────────────────┘
                                                   bounded channel (cap 8192, đầy⇒drop)
```

Telemetry đi qua ring nên **không có kernel transition nào** ở steady state: producer chỉ
ghi vào slot, và chỉ rung doorbell khi consumer đã ngủ. Cổng minifilter chỉ còn chiều
user→kernel (arm/disarm, đăng ký ring, verdict) — vài record/giây so với hàng triệu
event/giây đi ngược lại. Xem `sensor/windows_driver/SnsDrv/readme.md` cho lý do không
dùng inverted call và không làm ring chiều xuống.

### 2.2 Bản đồ module ↔ trách nhiệm

| Module | File | Trách nhiệm |
|---|---|---|
| `main` | [main.rs](../endpoint_service/src/main.rs) | CLI, vòng lặp sự kiện (thread 1), shipper (thread 2), `Uplink` tự-nối-lại |
| `lib` | [lib.rs](../endpoint_service/src/lib.rs) | `Service` + `process_batch`; `BatchOutcome`; rule set mặc định |
| `sensor` | [sensor.rs](../endpoint_service/src/sensor.rs) | Wire v2: **decode** frame→`SensorEvent`, **encode** (demo/test) |
| `translate` | [translate.rs](../endpoint_service/src/translate.rs) | `SensorEvent` → engine `Event` (consume by-value, move string) |
| `control` | [control.rs](../endpoint_service/src/control.rs) | Control-plane: encode `ArmCmd`/`SetSelf`/`RegisterRing`/`Verdict` xuống sensor (16B/record) |
| `source` | [source.rs](../endpoint_service/src/source.rs) | Trait `EventSource`; `ReaderSource` (file/stdin), `VecSource` (demo) |
| `ringbuf` | [ringbuf.rs](../endpoint_service/src/ringbuf.rs) | **Đặc tả** layout + giao thức commit của ring; thuần Rust nên test được mọi nền tảng |
| `ring` | [ring.rs](../endpoint_service/src/ring.rs) | *Windows-only*: transport mặc định — ring + doorbell; port cho control/verdict |
| `winport` | [winport.rs](../endpoint_service/src/winport.rs) | *Windows-only*: transport cũ (1 `FltSendMessage`/event), giữ làm fallback `--transport=port` |

### 2.3 Luồng xử lý một batch (end-to-end)
Qua [`Service::process_batch`](../endpoint_service/src/lib.rs):
1. `sensor::parse_batch(payload)` → `Vec<SensorEvent>` (bỏ qua record type lạ).
2. Với mỗi record: `translate::to_engine_event(se)` (consume) → `Option<Event>`
   (`None` cho `ProcessExist`/`ProcessExit` — engine không có op tương ứng).
3. `endpoint.on_event(ev)` (consume) → `(Decision, Verdict)`; nội bộ engine ship mọi event
   vào outbox, chặn thì ship thêm `BlockReport`.
4. `drain_outbox()` → nếu `remote` thì dồn vào `BatchOutcome.wire`; nếu không thì nạp backend
   in-process (dựng chain).
5. `drain_arm_cmds()` → `BatchOutcome.arms` để caller đẩy xuống sensor.
6. Caller ([main.rs](../endpoint_service/src/main.rs) vòng lặp): **reply sensor** (nếu frame
   sync) → **push control** (arm deltas) → **enqueue** wire cho shipper (non-blocking).

---

## 3. Mô hình dữ liệu: wire sensor→service (v2)

Nguồn sự thật kép: [`Event.hpp` (`Event::Wire`)](../sensor/windows_driver/SnsDrv/Event.hpp)
phía driver và [sensor.rs](../endpoint_service/src/sensor.rs) phía service. Tất cả
little-endian; string là UTF-16LE ở đuôi record.

### 3.1 Frame (batch) header — 8 byte
```
TotalSize : u32   (gồm cả header 8B)
Version   : u16   (= 2, WIRE_VERSION)
Count     : u16   (15 bit thấp = số record; bit 0x8000 = FRAME_REPLY_EXPECTED)
```
Driver ship mỗi event ngay khi xảy ra ⇒ `Count = 1`; format vẫn cho nhiều record/frame
(replay dump gói nhiều). Bit `FRAME_REPLY_EXPECTED` bật ⇔ frame đi đường enforcement đồng
bộ, driver đang **chặn** đợi verdict (khớp bằng `ReqId`, xem §3.2).

Frame header sống sót nguyên vẹn qua việc đổi transport nhờ một trùng hợp có chủ đích:
`TotalSize` nằm ở offset 0 nên **kiêm luôn cờ commit của ring** (0 = đã reserve nhưng chưa
commit). Nhờ vậy `parse_batch` đọc thẳng slot ring, và file replay không hỏng.

### 3.2 Record header — 32 byte (mọi field căn chỉnh tự nhiên)
| Offset | Size | Field | Mô tả |
|---|---|---|---|
| 0 | 4 | `Size` u32 | tổng byte record, **bội số 8** (để skip record lạ, giữ 8-align) |
| 4 | 1 | `Type` u8 | `Event::Types` |
| 5 | 3 | *Reserved* | zero |
| 8 | 8 | `TimeStamp` i64 | FILETIME (100-ns từ 1601) |
| 16 | 4 | `ProcessId` u32 | pid tiến trình đang hành động |
| 20 | 4 | `ReqId` u32 | id yêu cầu enforce — chỉ có nghĩa khi frame bật `FRAME_REPLY_EXPECTED`; 0 với mọi telemetry. Trước đây là *Reserved* zero-fill nên replay dump cũ vẫn decode nguyên vẹn |
| 24 | 8 | `ProcessCreateTime` i64 | create time (identity, chống pid-reuse) |

> Các đoạn *Reserved* là **đệm căn chỉnh tự nhiên**: giữ field 8-byte ở offset bội số 8, và
> biến padding ngầm của compiler thành hợp đồng tường minh nên C++ (`RtlCopyMemory` nguyên
> struct) và Rust (đọc tại offset cố định) khớp byte-for-byte.

String ở đuôi: `Length:u16 (byte) ++ UTF-16LE`.

### 3.3 Body theo `Type` (tại offset 32) — [sensor.rs](../endpoint_service/src/sensor.rs)
| `Type` | Code | Body (16B nếu có) | Strings | → `SensorEvent` |
|---|---|---|---|---|
| `FileOpen` | 1 | — | FileName | `FileOpen` (capture đang tắt) |
| `FileWrite` | 2 | — | FileName | `FileWrite` (write đầu/handle) |
| `ProcessCreate` | 100 | ChildPid:u32, pad, ChildCreateTime:i64 | Image, CommandLine | `ProcessCreate` (header = **parent**) |
| `ProcessExit` | 101 | — | — | `ProcessExit` |
| `ProcessOpen` | 102 | TargetPid:u32, DesiredAccess:u32, TargetCreateTime:i64 | TargetImage | `ProcessOpen` |
| `ProcessExist` | 103 | — | Image | `ProcessExist` (driver không phát) |
| `RemoteThreadCreate` | 104 | TargetPid:u32, ThreadId:u32, TargetCreateTime:i64 | — | `RemoteThreadCreate` |

`SensorEvent` giữ **thời gian raw FILETIME**; mọi record mang đủ identity `(pid, start)` cho
cả actor lẫn target ⇒ service **không cần bảng pid→start-time**.

### 3.4 Bất biến giải mã — [`parse_batch`](../endpoint_service/src/sensor.rs)
- `Version` phải `= 2`; `TotalSize` ∈ `[8, payload.len()]`.
- Mỗi record: `Size ≥ 32`, `Size % 8 == 0`, không vượt `TotalSize`.
- Record **type lạ** → skip nhờ `Size` (forward-compat), không fatal.
- String: `Length` chẵn, không vượt biên record.

---

## 4. Thành phần: giải mã & chuẩn hoá

### 4.1 `sensor` — decode/encode wire v2
- [`parse_batch`](../endpoint_service/src/sensor.rs): duyệt frame → `Vec<SensorEvent>`; field
  số đọc tại **offset cố định** (không byte-cursor), chỉ string mới walk
  ([`wstr_at`](../endpoint_service/src/sensor.rs)).
- [`expects_reply`](../endpoint_service/src/sensor.rs): đọc cờ `FRAME_REPLY_EXPECTED`.
- Hàm `enc_*` + `build_batch`/`build_frame`: **encode** ngược — dùng bởi `--demo`, `--stress`
  và test; đồng thời là tài liệu sống của layout byte.

### 4.2 `translate` — sensor → engine — [translate.rs](../endpoint_service/src/translate.rs)
Ánh xạ 1:1 (wire v2 đã mang đủ identity nên **không tra bảng, không state**):

| `SensorEvent` | engine `Op` | actor → object | attrs |
|---|---|---|---|
| `ProcessCreate` | `Exec` | parent → child | `image`, `cmd` |
| `FileOpen` | `Open` | proc → `File{name}` | — |
| `FileWrite` | `Write` | proc → `File{name}` | — |
| `ProcessOpen` | `Read` | proc → target proc | `target_image`, `vm_read` (nếu `PROCESS_VM_READ`) |
| `RemoteThreadCreate` | `Inject` | proc → target proc | — |
| `ProcessExist` / `ProcessExit` | — (`None`) | | |

- Chuyển FILETIME→ms qua [`ms()`](../endpoint_service/src/translate.rs) (`/10_000`).
- `to_engine_event` **consume `SensorEvent` by value**: string decode được **move thẳng** vào
  `Event`, không copy lần hai (§7).
- File identity hiện dùng **tên** làm token thay cho FileId thật (engine.md §2 muốn FileId);
  entropy/PE-ness của write là enrichment tương lai (chưa set `entropy`/`pe`).

---

## 5. Thành phần: control-plane (service → sensor) — [control.rs](../endpoint_service/src/control.rs)

Ngược chiều telemetry: service đẩy lệnh arm/disarm **xuống** cổng của driver để chỉ
`(process identity, op)` sát chokepoint mới đi đường enforce đồng bộ. Đây là **toàn bộ**
kênh user→kernel — nó vẫn là message chứ không phải ring thứ hai, vì kernel không có thread
nào ngồi chờ ring: làm vậy sẽ phải dựng lại đúng worker thread vừa xoá, và chèn thêm một
thread hop vào đúng đường verdict (nơi đang có thread bị block trong kernel).

### 5.1 Control record — 16 byte, cố định (mọi kind)
```
Kind:u8 (1=Arm, 2=Disarm, 3=SetSelf) ++ Op:u8 ++ pad[2]
  ++ Pid:u32le ++ PidStartMs:u64le

Kind=4 RegisterRing : ++ pad[3] ++ RingBytes:u32le ++ DoorbellHandle:u64le
Kind=5 Verdict      : ++ Deny:u8 ++ pad[2] ++ ReqId:u32le ++ pad[8]
```
Mọi kind đều **đúng 16 byte** nên driver giữ được vòng parse phẳng (`len % 16 == 0`) —
service không bao giờ gửi địa chỉ xuống, nên không cần record dài thay đổi.
- `PidStartMs` = create time cùng **engine-millisecond** với telemetry (FILETIME/10_000);
  driver khớp arm theo `pid` + create time (ms) ⇒ pid tái dùng không thừa hưởng arm cũ.
- Chỉ **process identity** enforce được trong kernel; `encode()` trả `None` cho identity khác.
- Op code ổn định phải khớp driver: [`op_code`/`op_from_code`](../endpoint_service/src/control.rs)
  (Exec=1, Read=2, Write=3, Inject=4, …).

### 5.2 `SetSelf` — [`encode_set_self`](../endpoint_service/src/control.rs)
Lúc kết nối, service **đăng ký pid của chính nó** để driver **miễn trừ** enforcement — một
sync-enforce tự kích sẽ deadlock (xem EnforcementPlane.md). Gửi ngay trong
[`RingSource::connect`](../endpoint_service/src/ring.rs), **trước** khi xin ring.

### 5.3 `RegisterRing` / `Verdict` — [ring.rs](../endpoint_service/src/ring.rs)
- `RegisterRing`: service xin ring `RING_BYTES` (1 MiB, power-of-two) và đưa handle doorbell;
  **driver** cấp non-paged pool, map vào service, trả **user VA qua `lpOutBuffer`** của
  `FilterSendMessage`. Service không bao giờ gửi địa chỉ xuống — driver nắm cả hai đầu mapping
  là điều giữ cho một service bị chiếm quyền không lái được ghi kernel (xem `ringbuf.rs`).
- `Verdict`: trả lời một record ring có `FRAME_REPLY_EXPECTED`, khớp bằng `ReqId`. Đây là
  **toàn bộ** chi phí syscall của đường enforcement, và nó hiếm.

---

## 6. Mô hình luồng & vận chuyển

### 6.1 Hai thread, tách trách nhiệm — [main.rs](../endpoint_service/src/main.rs)
- **Thread 1 (vòng lặp sự kiện)**: `next_batch` → `process_batch` (engine) → reply sensor →
  push control → **enqueue** `Wire` vào `sync_channel` (cap `SHIP_QUEUE_CAP = 8192`).
- **Thread 2 (`shipper_loop`)**: `recv` → `edr_proto::encode_frame(&w)` → `Uplink::ship` (TCP)
  → tự reconnect. Hoàn toàn **decoupled** khỏi thread 1.

### 6.2 Thứ tự bắt buộc: reply TRƯỚC ship
Trên frame enforcement, driver chặn thao tác dưới **timeout ngắn** đợi verdict. Nên thread 1
**reply sensor trước** rồi mới enqueue backend — verdict không được nằm sau một vòng TCP tới
backend (quá timeout ⇒ "send timeout" ở sensor ⇒ fail-open). Frame async không cần reply.

### 6.3 Backpressure = drop (best-effort)
Enqueue là `try_send` **non-blocking**. Hàng đợi đầy ⇒ backend đang chậm/mất ⇒ **drop** record
(đếm + `warn!`), **không** block hay back-pressure vòng sự kiện. Enforcement độc lập hoàn toàn
với ống ship (verdict đã reply trước handoff).

### 6.4 `Uplink` — uplink tự-nối-lại — [main.rs](../endpoint_service/src/main.rs)
- Kết nối ban đầu có **timeout 5s** (`connect_backend`) + `write_timeout` 10s.
- Lỗi ghi (reset/timeout) ⇒ **bỏ socket, tự reconnect** (throttle 500ms); telemetry sinh ra
  khi mất kết nối bị drop (bounded). In lỗi kèm **mã OS** để đối chiếu với backend.

### 6.5 Transport Windows — [ring.rs](../endpoint_service/src/ring.rs) (`#[cfg(windows)]`, mặc định)

Chọn bằng `--transport=ring|port` (mặc định `ring`).

| API | Dùng cho |
|---|---|
| `FilterConnectCommunicationPort` | mở `\SnsDrvPort` (control-plane) |
| `CreateEventW` | doorbell — **auto-reset**: nếu driver rung chuông đúng khe giữa lúc recheck và lúc `Wait`, trạng thái signaled phải *dính lại* |
| `FilterSendMessage` | control: `SetSelf`, `RegisterRing` (nhận user VA về qua `lpOutBuffer`), `Verdict` |
| `WaitForSingleObject` | ngủ trên doorbell sau khi spin `SPINS_BEFORE_SLEEP` vòng |

Vòng consumer: spin → `should_sleep()` (công bố `SLEEPING`, **full fence**, kiểm tra lại) →
`Wait`. `Empty::Uncommitted` (producer đang ghi dở) **không bao giờ** ngủ, chỉ spin/yield.
Timeout `DOORBELL_WAIT_MS` **không** phải lưới an toàn cho wakeup lỡ — nó chỉ để nổi lên
kiểm tra khi driver unload lúc ta đang ngủ.

> **Mẫu Dekker.** `should_sleep()` và phía producer đọc `ConsumerState` tạo thành cặp
> store-X-rồi-load-Y bắt chéo. x86-TSO cho phép đúng một đảo thứ tự này (store còn trong
> store buffer), và release/acquire **không đủ** — trên x86 cả hai chỉ là `MOV` trần. Thiếu
> full fence ở **cả hai phía** ⇒ mất wakeup ⇒ treo ngẫu nhiên. Chi tiết + chứng minh:
> [ringbuf.rs](../endpoint_service/src/ringbuf.rs).

### 6.6 Transport cũ — [winport.rs](../endpoint_service/src/winport.rs) (`--transport=port`)
Một `FltSendMessage`/event. Giữ lại làm fallback cho driver chưa có ring.
| API fltlib | Dùng cho |
|---|---|
| `FilterGetMessage` | nhận batch (đồng bộ, `OVERLAPPED=NULL`) vào `buf` dùng lại |
| `FilterReplyMessage` | trả verdict 1 byte (0/1) kèm `MessageId` |

`FILTER_MESSAGE_HEADER` 16B (`ReplyLength` + `MessageId`); payload bắt đầu ngay sau, mở đầu
bằng `TotalSize`.

---

## 7. Thiết kế hot-path gần zero-alloc (thread 1)

Mục tiêu: xử lý/tag **inline gần zero-alloc**, đẩy serialize + gửi mạng sang thread khác. Đạt
được bằng **materialize một lần rồi move xuyên suốt**, không phải bằng buffer pool.

### 7.1 Vì sao không cần buffer pool / transcoder
Protobuf serialize (`encode_frame`, cấp phát output, convert UTF-16→UTF-8) **đã** nằm trên
**thread 2** (`shipper_loop`). Raw sensor buffer **không rời thread 1** (engine tiêu thụ nó tại
chỗ; cái ship lên backend là `Wire` chứa engine `Event` + `ttps` — output của engine, không
phải raw). Do đó "hand raw buffer sang thread 2 + pool" là **thừa**; việc còn lại chỉ là khử
copy trên thread 1.

### 7.2 Ba lần khử alloc (đã hiện thực)
| Chỗ | Trước | Sau |
|---|---|---|
| `Event.attrs` | `HashMap<String,String>` (+ key-string mỗi event) | struct `Attrs` typed — [event.rs](../engine/src/event.rs); accessor `attr/attr_bool/attr_f64` giữ API tagger |
| `SensorEvent→Event` | decode alloc string **rồi clone** | `to_engine_event` **consume**, move string ([translate.rs](../endpoint_service/src/translate.rs)) |
| `Event→outbox Wire` | `event.clone()` + `ttps.clone()` mỗi event | `on_event` **consume `Event`**, **move** vào `WireEvent` ([endpoint.rs](../engine/src/endpoint.rs)) |

`Attrs` giữ **wire tương thích**: proto flatten typed→`map<string,string>` khi serialize, nên
backend không đổi (golden-byte test vẫn xanh). Tập attr là **đóng** theo vocabulary tagger
(`image, cmd, target_image, dir, entropy, pe, vm_read, enum`); thêm `attr_true=<key>` mới cần
thêm field — đúng triết lý "tagger là tầng code" của [rules.rs](../engine/src/rules.rs).

### 7.3 Sàn còn lại của kiến trúc
| Loại event | Alloc trên thread 1 |
|---|---|
| process→process, không string (exec/open/inject) | **0** — đọc số, move; graph retain là `Copy` |
| có string (image/cmd/file) | **1** (trong decode) — rồi move suốt tới thread 2 |
| DENY (block) | +1 clone event (hiếm — event cần cho cả telemetry lẫn `BlockReport`) |

Một copy string còn lại là **bắt buộc**: ship-and-forget cần dữ liệu owned để trao sang thread
2; nó nằm ở decode và **move** đi, không nhân đôi. `feed()` (đường replay/test, không production)
giữ API `&Event` và clone nội bộ.

### 7.4 Alloc còn lại ngoài detect/ship
Lớp **logging** vẫn `format!` một dòng outcome + `key_short` mỗi event
([lib.rs](../endpoint_service/src/lib.rs)); có thể gate theo log level nếu cần tối ưu thêm —
độc lập với đường phát hiện/ship.

---

## 8. Giao diện & chế độ chạy

### 8.1 API thư viện — [lib.rs](../endpoint_service/src/lib.rs)
```rust
Service::new() / with_rules(&str) -> Result<Service, String>
Service::process_batch(&mut self, payload: &[u8]) -> Result<BatchOutcome, String>
Service { pipe: Pipeline, remote: bool, events_seen: u64, denies: u64 }

BatchOutcome { outcomes: Vec<EventOutcome>, chains: Vec<Chain>,
               deny: bool, state_only: usize, arms: Vec<ArmCmd>, wire: Vec<Wire> }
```
`process_batch` phải gọi **tuần tự** (state engine không thread-safe). `deny` = OR mọi event
trong batch = quyết định chặn của batch. `wire` chỉ được điền khi `remote` (ngược lại backend
in-process đã tiêu thụ, `chains` mang bản dựng lại).

### 8.2 `EventSource` — [source.rs](../endpoint_service/src/source.rs)
Trait: `next_batch` / `reply(deny)` / `push_control(frame)` / `name`. Hiện thực:
`WinPortSource` (live), `ReaderSource` (file/stdin, batch tự-đóng-khung), `VecSource` (demo).
`reply`/`push_control` mặc định no-op cho nguồn chỉ-đọc.

### 8.3 CLI — [main.rs](../endpoint_service/src/main.rs)
| Flag | Ý nghĩa |
|---|---|
| `--com-port <name>` | cổng minifilter (mặc định `\SnsDrvPort`) — nguồn live |
| `--remote-addr <ip:port>` | backend (mặc định `127.0.0.1:7171`) |
| `--in-process` | chạy backend ngay trong tiến trình (dựng chain ở console) |
| `--rules <file>` | thay rule set (mặc định: builtin + lsass) |
| `--file/--stdin/--demo` | nguồn thay thế (không cần driver) |
| `--stress <N>` | sinh N event write giả — cô lập lỗi transport khỏi sensor |

Rule mặc định `SERVICE_RULES` = builtin engine + **chỉ pattern** LSASS (không lặp ttp/tagger).

---

## 9. Ràng buộc & hạn chế đã biết

- **Không thread-safe ở engine**: `process_batch`/`on_event` đơn luồng, tuần tự (đó là lý do
  không tách receive khỏi engine — sẽ tăng latency enforcement).
- **`winport` chỉ Windows** (`#![cfg(windows)]`); không build/test trên host khác — dùng
  `--file/--stdin/--demo` để thử nghiệm nền tảng khác.
- **Telemetry best-effort**: hàng đợi đầy hoặc backend mất ⇒ **drop** (có đếm), không lưu vô
  hạn, không back-pressure. Chỉ enforcement là không mất (reply inline).
- **File identity = tên**, chưa phải FileId thật; `entropy`/`pe` của write chưa được sensor
  điền (enrichment tương lai) — tagger tương ứng vì thế chưa kích hoạt trên đường live.
- **`FilterGetMessage` đồng bộ, một `buf`**: đủ vì raw không cross thread; overlapped/nhiều
  buffer chỉ đáng nếu kernel-delivery thành bottleneck (hiện không).
- **Arm ngược backend→endpoint** và stitch xuyên host **chưa** hiện thực (xem
  [SDD_engine.md §11](SDD_engine.md) và [docs/todo.md](todo.md)).

---

## 10. Tham chiếu
- Lõi phát hiện: [SDD_engine.md](SDD_engine.md) · thuật toán [engine.md](engine.md)
- Wire sensor: [Event.hpp](../sensor/windows_driver/SnsDrv/Event.hpp) · enforcement
  [EnforcementPlane.md](../sensor/windows_driver/SnsDrv/EnforcementPlane.md) ·
  [ProcessMonitor.md](../sensor/windows_driver/SnsDrv/ProcessMonitor.md)
- Contract backend: [proto/wire.proto](../proto/wire.proto) · codec
  [proto/src/lib.rs](../proto/src/lib.rs) · backend [backend_service/](../backend_service/)
- Yêu cầu: [SRS.md](SRS.md) · [BRD.md](BRD.md) · roadmap [todo.md](todo.md)
