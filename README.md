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

## Behavior

Engine nhận event thô `(actor, op, object)` — `op` là một trong 8 [`Op`](engine_core/src/event.rs#L20).
Ngoài việc khớp bước rule (`Step.match.ops`), mỗi op còn quyết định **có ghép storyline hay không**:
cạnh **nhân-quả** (`IS_CAUSAL`) thì `object` trở thành *sản phẩm/thuộc quyền* của storyline `actor` →
**merge** hai storyline; cạnh **truy cập** thì chỉ **ship cạnh**, giữ nguyên hai storyline riêng
(docs/engine.md §4). Phân loại này là nền của `scope=same_storyline` và của việc phân biệt
"ghi X rồi chạy X" với "A đọc file người khác ghi".

| Op | bit | Actor | Object | Ngữ nghĩa (actor → object) | Ghép storyline? | Vì sao |
|---|---|---|---|---|---|---|
| `Exec`    | `1<<0` | Process | File (ảnh thực thi) | chạy/ánh xạ image thành process | ✅ merge | sản sinh — object là sản phẩm actor tạo ra |
| `Create`  | `1<<1` | Process | File \| Process \| Registry* | tạo object (file/process/khoá) | ✅ merge | sản sinh — object do actor đẻ ra |
| `Write`   | `1<<2` | Process | File \| Registry* | ghi nội dung vào object | ✅ merge | sản phẩm — nội dung object do actor định đoạt |
| `Inject`  | `1<<6` | Process | Process | tiêm code/thread vào object | ✅ merge | điều khiển — actor chiếm quyền thực thi object |
| `Dup`     | `1<<7` | Process | Process | nhân bản/chuyển handle sang object | ✅ merge | chuyển quyền — object thừa hưởng năng lực actor |
| `Read`    | `1<<3` | Process | File \| Process | đọc nội dung object | ❌ ship cạnh | tiêu thụ, không sở hữu — đọc file người khác ghi ≠ cùng lineage |
| `Open`    | `1<<4` | Process | Process \| File \| Registry* | mở handle tới object | ❌ ship cạnh | chỉ truy cập — mở handle LSASS không biến actor thành con LSASS |
| `Connect` | `1<<5` | Process | Socket | kết nối tới socket/đầu xa | ❌ ship cạnh | truy cập ngoài — không sản sinh thực thể mới trong storyline |

`Actor` luôn là **Process** — chỉ tiến trình mới hành động trong mô hình event này; cột object mới
là trục biến thiên thật sự.

> **\*Registry chưa có chỗ đứng trong `Kind`.** [`Kind`](engine_core/src/event.rs#L10) hiện chỉ có
> `Process | File | Socket | Other` — không có biến thể Registry, dù chính bảng trên gọi tên nó
> ("khoá" ở dòng `Create`). Một `Create/Write/Open` nhắm vào registry key hiện phải rơi vào
> `Kind::Other`, mất khả năng lọc theo `obj=…` trong rule (mục [Rules](#rules)). Cần quyết định:
> thêm biến thể `Kind::Registry` (nếu registry là bề mặt cần rule lọc riêng) hay giữ `Other` (nếu
> registry chỉ cần phân biệt qua `ttp`, không qua `obj`).

> **Hệ quả cho rule:** ở pattern mà mọi bước đều là op **merge** trên **cùng** entity đã `bind`
> (vd `write X → exec X`), `same_storyline` gần như tự thoả — binding đã ép đúng file, mà chạm-file
> bằng op merge thì kéo theo cùng storyline. `scope` chỉ thành ràng buộc *thực sự* khi có bước dùng
> op **ship cạnh** (`Open`/`Read`/`Connect` — LSASS dump, C2, đọc file lạ) hoặc khi cần chặn việc
> khâu nhầm các lineage độc lập.

## Rules

Một **rule** mô tả một mẫu tấn công là **thứ tự bộ phận (DAG) các bước**, không phải chuỗi tuyến
tính. Engine theo tiến độ bằng **bitmask các bước đã xong** (`completed_mask`), nên các bước tự do
thứ tự đến xen kẽ vẫn khớp (docs/engine.md §6).

### Tagger — ranh giới giữa event thô và rule

[`Event`](engine_core/src/event.rs#L68) chỉ mang **6 trường**: `ts, op, actor, actor_kind, object,
object_kind` — không path, không chữ ký, không entropy, không cmdline. Mọi thứ "ngữ nghĩa" khác
(technique, công cụ, độ tin cậy nguồn gốc…) được lớp **tagger** (platform-specific, docs/engine.md
§6.0) diễn giải **trước khi** event chạm tới DAG matcher, rồi gói lại thành tập `ttps` đi kèm event.

Hệ quả cho rule: chỉ có **hai kênh** để mô tả một event —
- **cấu trúc** (đọc thẳng từ `Event`): `op`, `obj` (từ `Kind`).
- **ngữ nghĩa** (do tagger gán): `ttp`.

Không có kênh thứ ba. Muốn khớp theo "đã ký bởi nhà phát hành tin cậy", "entropy cao", "hash nằm
trong threat-intel" — **không thể** viết thẳng biểu thức đó vào rule (không có trường nào để đọc);
phải để tagger tự kiểm tra rồi phát ra một `Ttp` đại diện (vd `T_SIGNED_TRUSTED`), rule chỉ khớp
TTP đó như mọi TTP khác. Ràng buộc này áp dụng cho **mọi** clause dùng thuộc tính, kể cả `unless`
bên dưới.

### Grammar

```
ruleset := pattern+
pattern := "pattern" NAME
             [ "scope" SCOPE ]                       # mặc định same_storyline
             step+
           "end"
step    := "step" NAME "=" match [ "after" prereq ] [ "unless" names ] [ "->" action ]
match   := clause ( "&" clause )*
clause  := op | "ttp" ttpsel | "obj" kind | bind
op      := exec | create | write | read | open | connect | inject | dup | any
ttpsel  := T<id> | any( T<id>, … ) | all( T<id>, … )
kind    := process | file | socket
bind    := field "=" NAME ":" field                  # <field-này> phải == <step>:<field-kia>
field   := actor | object
prereq  := NAME ( "&" NAME )*                         # AND: mọi step phải xong (mốc hội tụ)
         | NAME ( "|" NAME )*                         # OR : một step bất kỳ xong (hợp lưu)
                                                      # thuần & HOẶC thuần | — KHÔNG trộn
names   := NAME ( "," NAME )*
action  := block | disarm oplist                     # bỏ trống = chỉ inspect (báo hiệu)
SCOPE   := same_storyline | same_actor | free
```

### Một `step` gồm 6 trục độc lập

`step <name> = <op> [& ttp …] [& obj …] [& <bind>] … [after …] [unless …] [-> <action>]`

| Trục | Từ khoá | Ý nghĩa | Bắt buộc? |
|---|---|---|---|
| **op** | `exec/write/open/…/any` | loại syscall — luôn viết trước; là **đơn vị chặn** | có (dùng `any` nếu không quan tâm) |
| **ttp** | `ttp T1003` / `ttp any(…)` / `ttp all(…)` | nhãn ngữ nghĩa tagger gán; `any`=OR biến thể, `all`=phải đủ | không |
| **obj** | `obj process/file/socket` | loại object của event | không |
| **bind** | `object=drop:object` | identity: trường này phải **trùng thực thể** với `<step>:<field>` | không |
| **after** | `after recon & kill_shadow` / `after a \| b` | các step phải **xong trước**; `&`=mọi, `\|`=bất kỳ | không (rỗng = bước gốc/seed) |
| **unless** | `unless trusted_msi` | bỏ qua bước này nếu step liệt kê **đã** commit (whitelist) | không |
| **action** | `-> block` / `-> disarm write,exec` | cưỡng chế khi bước commit; bỏ trống = inspect | không |

### Hai loại "và" — đừng lẫn

| | Nghĩa | Phạm vi |
|---|---|---|
| `&` (trong `match`) | các điều kiện **cùng đúng** | **một** event |
| `after` (prereq) | bước kia **đã xong trước** | **qua nhiều** event (cạnh DAG) |

`write & ttp T1486` = *một* event vừa là `write` vừa mang tag T1486. `encrypt after recon` = *hai*
event khác nhau, cái sau đến sau. Không có `OR` ở tầng clause — muốn "một trong nhiều" thì dùng
`ttp any(…)` bên trong trục ttp.

### `after` nhiều bước — `&` (mọi) và `|` (bất kỳ)

`after` gộp nhiều tiền đề bằng **một** toán tử, **thuần `&` hoặc thuần `|`, không trộn**:

| | Nghĩa | Kiểm (O(1)) | Commit khi |
|---|---|---|---|
| `after a & b` | **hội tụ** — chờ mọi nhánh | `(prereq_mask & done) == prereq_mask` | cả `a` lẫn `b` xong |
| `after a \| b` | **hợp lưu** — đạt qua đường bất kỳ | `(prereq_mask & done) != 0` | `a` *hoặc* `b` xong (cái nào trước) |

Cùng một `prereq_mask` (= OR bit các cha); step chỉ thêm **một bit mode** chọn `==` hay `!=0`. Thứ
tự *giữa* các nhánh luôn **tự do** — đó là điểm của DAG; prereq chỉ hỏi "đủ chưa", không hỏi "chiều nào".

**`&` — mốc hội tụ** (ví dụ `ransomware_dag`):
```
pattern ransomware_dag
    scope same_storyline
    step exec_cmd    = exec  & ttp T1059                              # bước gốc (seed)
    step recon       = read  & ttp T1083   after exec_cmd             # nhánh do thám
    step kill_shadow = exec  & ttp T1490   after exec_cmd             # nhánh xoá Shadow Copy
    step encrypt     = write & ttp T1486   after recon & kill_shadow  # MỐC: đòi CẢ hai nhánh
                       -> disarm write,exec,create,inject,connect
end
```
```
            exec_cmd                     # gốc: prereq rỗng → seed automaton
           /        \
        recon    kill_shadow             # hai nhánh song song, thứ tự tự do
           \        /
           encrypt                        # after recon & kill_shadow → chỉ commit khi CẢ hai xong
```

| Luồng event | `encrypt` khớp? |
|---|---|
| exec_cmd → recon → kill_shadow → encrypt | ✅ |
| exec_cmd → kill_shadow → recon → encrypt | ✅ (thứ tự nhánh tự do) |
| exec_cmd → recon → encrypt | ❌ thiếu `kill_shadow` |

**`|` — hợp lưu** (một step gộp nhiều đường thay cho việc nhân đôi step cùng bit):
```
    step stage_http = connect & ttp T1071        # hai đường staging thay thế nhau
    step stage_dns  = connect & ttp T1048
    step exfil      = write   & ttp T1041   after stage_http | stage_dns   # đạt qua BẤT KỲ đường nào
```

**Cấm trộn `& |` trong một `after`** — để mỗi step còn đúng một phép mask (giữ bounded, hợp kernel).
Cần logic trộn (`d after a & (b | c)`) thì tách bằng một step trung gian gộp `|` trước:
```
    step reached = … after b | c
    step d       = … after a & reached      # còn lại thuần &
```

Thứ tự đến của các nhánh chỉ cộng/trừ `order_bonus` khi chấm điểm (§6.3), **không** phải điều kiện accept.


### Identity binding

Event chỉ có hai slot thực thể: `actor` và `object`. Bind = "trường của step này phải là **cùng
thực thể** với trường đã chốt ở một step khác", viết `<field>=<step>:<field>`. Step được trỏ là
**nguồn** (chốt giá trị khi commit), step chứa clause là **bên khớp** (`BINDING_OK`, §6.2). Tham
chiếu `S:field` **tự kéo theo** prereq `after S` (không join được step chưa xong).

```
# dropper — "ghi X rồi chạy ĐÚNG X", phân biệt với "ghi X chạy Y"
pattern dropper
    scope same_storyline
    step drop = write & ttp T1105
    step run  = exec  & ttp T1059 & object=drop:object   -> block   # object trùng drop → mới khớp
end
```

`ghi X chạy Y` ⟹ `run.object = Y ≠ drop:object = X` ⟹ bước `run` không commit ⟹ không match. Rename
vô hiệu vì khoá theo FileId (§7). Bind chéo trường cũng hợp lệ: `actor=run:object` ("kẻ hành động
này chính là image mà `run` vừa chạy ra").

### `unless` — loại trừ (whitelist)

`unless S` (hoặc `unless S1, S2` — **OR**: loại trừ nếu **bất kỳ** cái nào đã commit) = bước này bị
**bỏ qua an toàn** nếu step được liệt kê đã commit trên automaton này. Kiểm chỉ là một bit đã có sẵn
trong `completed_mask` — **không cần giữ lại event nào**: một step, khi commit, đã collapse toàn bộ
event (op/ttp/obj/bind) thành đúng một bit; bit đó là tất cả những gì automaton còn nhớ (docs/engine.md
§0, §2 — "phát hiện inline không đọc cạnh lịch sử").

Vì vậy `unless` **chỉ được trỏ vào tên step khác, không bao giờ trỏ vào biểu thức thuộc tính thô** —
đúng ranh giới ở mục [Tagger](#tagger--ranh-giới-giữa-event-thô-và-rule) phía trên. Muốn whitelist
theo "file có chữ ký hợp lệ", biến điều kiện đó thành **một step khớp TTP mà tagger đã pre-compute**,
không phải một biểu thức attr:

```
# dropper — trừ khi đúng file đó có nguồn gốc tin cậy (tagger đã xác minh chữ ký)
pattern dropper
    scope same_storyline
    step drop        = write & ttp T1105
    step trusted_msi = write & ttp T_SIGNED_TRUSTED & object=drop:object   # tagger đã tag "đã ký"
    step run         = exec  & ttp T1059 & object=drop:object
                       after drop   unless trusted_msi   -> block
end
```

`trusted_msi` bắt buộc `object=drop:object` — chỉ hợp lệ khi là **đúng file** đang bị theo dõi, không
phải write nào khác được ký trong cùng storyline.

**Lưu ý — cùng một event có thể vừa mở khoá vừa thoả whitelist.** Vì `object=drop:object` khiến
`trusted_msi` tự có `after drop`, và `done_mask` cập nhật *live* theo thứ tự khai báo trong cùng một
event ([v0_0_2.rs:149-151](engine_core/src/v0_0_2.rs#L149-L151)): nếu chính event `write` đó được
tagger gắn **cả** `T1105` **lẫn** `T_SIGNED_TRUSTED` (chữ ký là thuộc tính tĩnh, đọc được ngay lúc
ghi), `drop` commit trước → mở khoá `trusted_msi` → `trusted_msi` **cũng** commit ngay trong event
đó. Điều này chỉ đúng nếu **`drop` được khai báo trước `trusted_msi`** trong text — quy ước: step bị
tham chiếu luôn khai báo trước step tham chiếu nó.

**Không hồi tố.** `unless S` chỉ ngăn được nếu `S` đã commit **trước hoặc cùng lúc** với thời điểm
step bị canh được xét — whitelist đến muộn hơn không "gỡ" được hành động đã xảy ra (hệ quả tự nhiên
của §6.3/§7 mục 3, không phải luật riêng của `unless`). Đặt step whitelist càng sớm càng an toàn.

### `scope`

`scope` giới hạn event nào được coi là cùng chuỗi với automaton: `same_storyline` (mặc định — cùng
lineage nhân-quả, xem [Behavior](#behavior)), `same_actor` (đúng một process), `free` (mọi event).
Với pattern mà mọi bước đều là op **merge** trên cùng entity đã bind, `same_storyline` gần như tự
thoả; `scope` chỉ thành ràng buộc thật khi có bước dùng op **ship-cạnh** (`open/read/connect`).

### Nhiều `action` trong một pattern

Mỗi step mang action **độc lập**, bắn khi *chính step đó* commit — cho phép **leo thang**: `disarm`
giữa chuỗi để tước năng lực, `block` tại điểm nghẽn. Nếu nhiều step commit trong cùng một event, mọi
side-effect (`disarm`) đều thi hành, verdict trả về là `max` (`Ignore < Inspect < Block < Disarm`).

```
pattern lsass_dump
    scope same_actor
    step open = open  & ttp T1003 & obj process   -> disarm dup,inject
    step dump = write   after open                 -> block
end
```

### Compile → khớp nhanh

- **label → bit**: tác giả đặt *tên* step; compiler cấp `bit` (slot trong `completed_mask`, ≤64) và
  dựng `prereq_mask` từ `after` + tham chiếu bind. Chèn/xoá step không lệch số.
- **ttp → mask**: mọi TTP được intern về chỉ số dày → mỗi step giữ một `u64` mask; khớp ttp =
  `(ev_ttp & req_ttp) == req_ttp`, thay vòng lặp `Vec<Ttp>`.
- **bind → slot**: mỗi `(step,field)` được trỏ tới nhận một slot; automaton giữ mảng `Key` cố định,
  khớp = so `u128`. Không alloc — hợp `no_std`/kernel.
- match(event) rút về vài phép AND/so-sánh trên machine word; bucket step theo op cho prefilter O(1).

> **Trạng thái:** parser hiện hành ([engine_rules](engine_rules/src/lib.rs)) mới nhận
> `op`/`ttp`/`prereq`/`action` (xem [dag.rules](endpoint_service/rules/dag.rules)). Các trục `obj`,
> `bind`, `unless`, `scope` và cú pháp label ở trên là **đích đang triển khai** — bindings là bước 2
> trong [docs/todo.md](docs/todo.md).

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
