# Tách agent–backend: agent giữ trạng thái phát hiện, backend giữ đồ thị

> Bổ trợ cho `engine.md` (kiến trúc lõi) và `engine_state_optimization.md` (bound bộ nhớ tự chứa).
> Tài liệu này đặc tả kiến trúc khi có thêm một **tiền đề mới**: agent đẩy được **toàn bộ event
> stream** lên backend để truy vết ở đó.
>
> Mục tiêu thiết kế: **tối đa độ chính xác phát hiện tại agent** — không phải tối thiểu bộ nhớ.
> Tiền đề này thay đổi bài toán tận gốc: toàn bộ stack §7 của `engine_state_optimization.md`
> được thiết kế cho một agent phải *tự gánh cả forensic*; khi backend nhận full stream, lý do
> tồn tại của pool COLD trên agent gần như biến mất, và **hai nguồn false negative chủ động**
> (admission, hub-split) không còn bắt buộc phải trả.

---

## 0. Tiền đề & nguyên lý đảo vai

**Tiền đề:**
1. Agent gửi được 100% event đã chuẩn hoá (schema §12 `engine.md`) lên backend, với độ trễ
   giây-cấp khi mạng bình thường.
2. Backend có tài nguyên "không giới hạn" so với agent (RAM/disk/CPU) và nhìn được **nhiều host**.
3. Mạng **có thể đứt** — agent phải tự đứng được (xem §5).

**Nguyên lý đảo vai.** Nhìn lại bảng định lượng §1.1 của `engine_state_optimization.md`:

| Thành phần | Kích thước | Ai cần nó? |
|---|---|---|
| `AutomatonInstance` | ~200B–1KB | **detection inline** — chỉ agent dùng được đúng lúc |
| Node + index | ~100–200B/node, số lượng lớn | detection cần *identity + sid*; forensic cần phần còn lại |
| Cạnh (edges) + attrs điều tra | nổ theo hoạt động | **chỉ forensic / SOC** — backend làm tốt hơn |

⟹ Phân vai theo đúng ai-cần-gì:

```
AGENT   = toàn bộ trạng thái PHÁT HIỆN (automata, binding, arm, DSU, identity index)
          — vì nó rẻ, và vì đường verdict inline không được chờ mạng.
BACKEND = toàn bộ trạng thái ĐIỀU TRA (provenance graph đầy đủ, lịch sử dài, cross-host)
          — vì nó nặng, và vì phân tích nặng không có deadline per-event.
```

So với stack §7 tự chứa (HOT/COLD trên cùng agent): **COLD chuyển hẳn lên backend**; HOT ở lại
và được nới hào phóng. Stack §7 không bị vứt — nó tụt xuống làm **chế độ offline** (§5).

Ba quy tắc vàng của kiến trúc này:
1. **Mọi thứ trên đường verdict inline phải cục bộ** — backend nằm sau một đường mạng, mà
   fail-open (§8 `engine.md`) nghĩa là "chờ backend" = "allow".
2. **Không giữ trên agent thứ gì chỉ phục vụ điều tra** — cạnh, attrs hiển thị, lịch sử dài:
   đẩy lên rồi quên.
3. **Backend bù trễ, không bù trần**: những gì agent chủ động cắt (hub-split), backend khâu lại
   và *arm ngược xuống* — FN chuyển thành phát-hiện-trễ-vài-giây, không mất hẳn.

---

## 1. Agent chế độ lean — cắt COLD, nới HOT

### 1.1 Cái giữ / cái bỏ

| Trạng thái | Tự chứa (stack §7) | Lean-agent | Lý do |
|---|---|---|---|
| Automata + `bound_ids` + armed | HOT, sketch khi collapse | **Giữ đầy đủ, nới trần** | đường verdict inline |
| `NODE_INDEX` / DSU (`SID_INDEX`) | COLD, evict theo tier | **Giữ, node lean** (§1.2) | định tuyến event→storyline→automata |
| Cạnh (edges) | COLD, cap cứng | **Bỏ — phù du** (§1.2) | chỉ forensic cần |
| Attrs điều tra (path hiển thị, cmd đầy đủ…) | COLD | **Bỏ sau khi ship** | backend giữ bản gốc |
| `ttp_history` | ring per-storyline | **Ring nhỏ** (chỉ đủ scoring window) | lịch sử đầy đủ ở backend |
| Rate/sketch cho predicate (§4 tối ưu) | HLL/CMS | Giữ nguyên | stateful nhẹ của tagger |
| Admission theo rarity (Hướng 6) | có, `ρ_admit` | **BỎ HẲN** (§1.3) | nguồn FN nặng nhất, hết lý do tồn tại |
| Hub-split (Hướng 3c) | trần thấp | **Nới ~10×** (§1.4) | trần cũ là trần bộ nhớ, không phải CPU |
| Per-root budget (Hướng 3a,b) | bảo vệ COLD | **Giữ dạng nhẹ** (§1.5) | bảo vệ pipeline ship + tín hiệu churn |
| Spill đĩa (Hướng 5) | sketch store | Giữ — phục vụ chế độ offline (§5) | sống qua reboot khi mất mạng |

### 1.2 Node lean & cạnh phù du

```rust
// node trong lean-agent: CHỈ những gì định tuyến + binding cần
struct LeanNode { key: NodeKey /* identity: FileId | (pid,start) | (ip,port) */, sid: usize }
```

Không lưu `first_seen/last_seen` chi tiết, không attrs, **không danh sách cạnh**. Vòng đời một
cạnh trên agent đúng một khoảnh khắc trong `ON_EVENT`:

```
ADD_EDGE(sid, a, o, op, ts)  trở thành:
    (1) cập nhật DSU nếu IS_CAUSAL(op)          # như cũ — §3 engine.md
    (2) cập nhật rate/sketch của tagger          # như cũ — §4
    (3) SHIP(e) vào hàng đợi telemetry (§2)      # thay cho việc lưu cạnh
    # KHÔNG ghi cạnh vào bộ nhớ agent
```

Với node lean ~100–150B và không cạnh, cùng ngân sách RAM agent giữ được số node **gấp cỡ một
bậc** so với tự chứa. Storyline graph mà SOC xem = dựng từ backend, không phải từ agent.

### 1.3 Bỏ admission (Hướng 6) — loại nguồn FN nặng nhất

Admission tồn tại vì "đừng tạo state bền cho tới khi đáng" — hợp lý khi mỗi automaton kéo theo
cả graph. Trong lean-agent, seed một automaton chỉ tốn ~1KB **không kéo theo gì khác**:

- Quay lại ngữ nghĩa seed gốc của `engine.md` §5.3(a): TTP khớp step gốc (`prereq_mask == ∅`)
  là seed, qua `PATTERN_TRIGGER`. `root_gate` dạng cấu trúc (`pe_write`) giữ nguyên — nó là
  điều kiện *đúng-sai của mẫu*, không phải điều kiện tiết kiệm.
- 100k automaton sống đồng thời ≈ vài chục MB — chịu được; trần thật là `MAX_AUTOMATA_PER_SID`
  (trần **CPU** per-event, §1.4).

Hệ quả trực tiếp: chuỗi living-off-the-land toàn-bước-phổ-biến **có instance từ event đầu tiên**;
vấn đề "neo hiếm đến muộn thì mất tiền tố" biến mất vì không còn cổng admission nào cả. (Đây là
nguồn FN duy nhất của stack §7 *không khôi phục được* — vì state chưa bao giờ tồn tại. Loại bỏ
nó là cái lợi chính xác lớn nhất của kiến trúc này.)

### 1.4 Nới hub-split — trần bộ nhớ tách khỏi trần CPU

Hub-split (§11.3c tối ưu) có hai trigger với bản chất khác nhau:

| Trigger | Bản chất | Lean-agent |
|---|---|---|
| `MAX_NODES_PER_SID` | trần **bộ nhớ** của storyline hub | node lean ⟹ **nâng ~10×** (100k → 1M) |
| `MAX_AUTOMATA_PER_SID` | trần **CPU** per-event (§5.3 duyệt automata) | **giữ nguyên** — không liên quan backend |

`stable_hubs` (con của `services.exe`/`explorer.exe` tự làm root) **vẫn giữ** — nó chặn
dependency-explosion ngữ nghĩa (storyline "cả máy"), không phải chỉ bộ nhớ. Nhưng FN do nó
gây ra giờ có lưới đỡ: `link_weak` được **ship lên backend như một loại event**, và backend
khâu lại (§3.2) rồi arm ngược xuống (§4). FN "mất hẳn" → "trễ vài giây".

### 1.5 Ngân sách theo nguồn — đổi mục tiêu bảo vệ

Per-root budget không còn bảo vệ COLD (đã bỏ), nhưng vẫn cần cho hai việc:

1. **Bảo vệ pipeline telemetry**: kẻ tấn công spam event để làm nghẽn hàng đợi ship, trì hoãn
   chính telemetry tố cáo mình. Đối sách ở §2 (ưu tiên theo tier) + rate-limit tạo node per-root.
2. **Tín hiệu churn**: `churn_anomaly(root)` vẫn đưa vào scoring §6 `engine.md` — flooding tự
   tố cáo, giữ nguyên từ Hướng 3.

Trần `MAX_LIVE_NODES_PER_ROOT` vẫn tồn tại nhưng nâng theo tỷ lệ node lean; vượt trần thì evict
node nguội **của chính root đó** (node lean bỏ đi là rẻ — backend còn bản gốc; automaton nào
đang bind identity của node bị bỏ **không bị ảnh hưởng**, vì binding theo identity chứ không
theo uid — refactor §11.0 tối ưu là tiền đề bắt buộc, xem §8).

---

## 2. Pipeline telemetry lên backend

```
ON_EVENT ──▶ SHIP(e) ──▶ hàng đợi ưu tiên theo tier ──▶ batch + nén ──▶ backend
                                │ đầy? drop T0 trước, KHÔNG BAO GIỜ drop T2+
                                ▼
                          disk ring-buffer (offline / backpressure, §5)
```

Quy tắc:

- **Gắn metadata định tuyến trước khi ship**: `{host_id, sid, root_id, tier, seq}`. `seq` đơn
  điệu per-host để backend phát hiện lỗ hổng stream (mất event = tín hiệu, không im lặng).
- **Ưu tiên theo tier của storyline** (tier từ §11.2 tối ưu): event thuộc storyline T2+ (SUSPECT
  trở lên) đi trước; khi backpressure, drop **T0 trước tiên** và đếm số drop (backend thấy
  counter, biết stream không toàn vẹn). Event `link_weak` và mọi thay đổi armed đi ở **hạng
  điều khiển** — không bao giờ xếp sau telemetry thường.
- **Batch + nén ngoài hot path**: `SHIP()` chỉ là push vào ring lock-free; flush là thread riêng.
  Cam kết O(1)/event của §1 `engine.md` giữ nguyên.
- Sự kiện ship là **bản ghi chuẩn hoá đầy đủ** (kể cả attrs agent không giữ lại) — backend là
  nơi duy nhất có bản gốc, nên ship *trước khi* quên.

---

## 3. Backend — làm những gì agent không bao giờ được phép làm inline

### 3.1 Provenance graph đầy đủ, không trần

Backend dựng lại đúng thuật toán §2–§3 `engine.md` (RESOLVE/UNIFY) nhưng **không cap**: giữ
mọi cạnh, mọi attrs, lịch sử không giới hạn thời gian, persistence sẵn có. Storyline graph cho
SOC lấy từ đây — agent không còn nghĩa vụ forensic.

### 3.2 Stitcher — khâu lại những gì agent chủ động cắt

Đầu vào: các event `link_weak(sid_a, sid_b)` + quan hệ cha-con qua hub mà agent đã từ chối merge.
Backend **không có trần merge** nên hợp nhất thoải mái, rồi chạy lại chính matcher §5 trên
storyline đã khâu:

```
STITCH:
    graph_full = UNIFY không hub-split (dùng chính DSU logic, bỏ điều kiện tách)
    for pattern in rules: chạy ADVANCE trên chuỗi đã khâu (offline, không deadline)
    if automaton đạt armed-condition (score ≥ θ_block, còn bước enforceable chưa tới):
        PUSH_ARM(host, identity_scope)            # §4 — vũ trang ngược xuống agent
```

Đây là lưới đỡ cho FN hub-split: kịch bản `powershell → tạo service → services.exe →
payload.exe` (hai sid trên agent) được backend nhìn thành một chuỗi, và `payload.exe` bị arm
**trước khi** nó chạm bước enforceable — nếu vòng phản hồi kịp (§7).

### 3.3 Phân tích nặng — cấm inline, tự do offline

- **Matching đắt**: subgraph alignment kiểu POIROT, window dài tuỳ ý, pattern có binding tổ hợp
  vượt trần agent (§5.8 `engine.md` phải hạ cấp ALERT — backend thì vét cạn được).
- **Low-and-slow**: chuỗi kéo nhiều ngày/qua reboot — backend không có `seg_window` vì không có
  áp lực bộ nhớ; có thể chạy cả hai chế độ (window chặt như agent để so khớp verdict, và window
  nới để hunting).
- **Cross-host**: lateral movement — vá giới hạn "chỉ trên một host" của §13.2 `engine.md`.
  Identity chéo host (remote logon, SMB write từ host A thành file trên host B) chỉ backend nối được.
- **Baseline rarity thật**: đếm tần suất TTP trên toàn fleet (Count-Min + decay như Hướng 4),
  thay bảng `rarity` tĩnh chỉnh tay — vá thêm một giới hạn §13.2, và bảng rarity mới được đẩy
  xuống agent định kỳ qua kênh §4.

### 3.4 Backend KHÔNG làm gì

Không có verdict đồng bộ. Mọi kết luận của backend đi xuống dưới dạng **arm/watchlist/rule** —
tức là thay đổi *trạng thái* của agent, để lần chạm kế tiếp bị chặn **trong kernel** như cơ chế
armed sẵn có (§5.5 `engine.md`). Không bao giờ có đường "event chờ backend trả lời rồi mới allow".

---

## 4. Kênh phản hồi xuống — backend-arm

Mở rộng `PUSH_KERNEL_ARM` (hiện chỉ userland-agent gọi) thành kênh điều khiển có xác thực:

### 4.1 Ngữ nghĩa lệnh

```
ArmDirective = {
    scope,            # theo IDENTITY: (pid,start) | FileId | (root_id) — KHÔNG theo path/tên
    action,           # op bị chặn khi khớp scope: write_high_entropy | exec | connect ...
    ttl,              # bắt buộc — arm không TTL là mìn vĩnh viễn
    reason,           # pattern_id + storyline backend để agent log đối chiếu
    seq               # đơn điệu; agent bỏ directive cũ hơn cái đã áp
}
WatchDirective   = { scope, boost }       # không chặn, chỉ cộng điểm/thăng tier khi chạm
TableUpdate      = { rarity_table | rules | stable_hubs }   # cập nhật knob vận hành
```

- **Arm theo identity, không theo path** — nhất quán với §2/§5.8 `engine.md` (rename vô hiệu).
- **`WatchDirective`** là mức nhẹ cho kết luận chưa đủ chắc: chạm identity trong watchlist →
  storyline thăng thẳng T2/T3 + cộng điểm, để matcher cục bộ tự vượt ngưỡng — backend "mớm"
  chứ không phán.
- Agent áp arm vào đúng bảng kernel-arm sẵn có (hash trong driver, §8.1 `engine.md`) — không
  round-trip khi event enforcing tới.

### 4.2 An toàn của kênh điều khiển (bắt buộc, không phải tuỳ chọn)

Một lệnh arm giả = **DoS chặn nhầm hàng loạt** — self-protection §13.2 `engine.md` giờ mở rộng
ra cả kênh điều khiển:

- mTLS + **ký từng directive** (khoá riêng cho control-plane, không dùng chung khoá telemetry);
  agent từ chối directive không ký/`seq` lùi/hết hạn clock-skew.
- **Trần sanity phía agent**: số arm sống tối đa per-root và toàn cục; vượt trần → từ chối +
  alert (backend bị chiếm không được phép biến agent thành công tắc tắt máy).
- Arm hết TTL tự rơi; backend muốn giữ phải gia hạn (lease) — mất backend thì arm cũ tự tan,
  không để lại trạng thái chặn mồ côi.

---

## 5. Chế độ offline — degrade về stack tự chứa

Mất link không được làm agent mù. Chuyển chế độ theo trạng thái kênh:

| | ONLINE (mặc định) | OFFLINE (degraded) |
|---|---|---|
| Node | lean, không cạnh | như lean (không quay lại giữ cạnh) |
| Admission | tắt | **vẫn tắt** — automaton rẻ trong cả hai chế độ |
| Hub-split | trần nới | **hạ về trần §11.4 tối ưu** (RAM không còn van xả backend) |
| Eviction | chỉ per-root nhẹ | **bật đủ stack §7**: tier + collapse/rehydrate + spill đĩa |
| Telemetry | ship trực tiếp | ghi **disk ring-buffer** (cap dung lượng, drop T0 trước) |
| Arm hiện có | backend lease | giữ đến hết TTL (không gia hạn được) |

Khi nối lại: replay ring-buffer theo `seq` (backend chịu trách nhiệm dedupe theo `(host, seq)`),
backend đối chiếu và có thể phát arm bù. **Điều duy nhất mất khi offline** là lưới đỡ của
backend (stitch, cross-host, LotL dài) — đúng bằng mức của stack §7 tự chứa, không tệ hơn.

---

## 6. Tác động lên hai nguồn FN của stack tự chứa

| | Stack §7 tự chứa | Lean-agent + backend |
|---|---|---|
| **FN admission** (LotL toàn bước phổ biến; neo hiếm đến muộn) | Trung bình, **không khôi phục được** (state chưa từng tồn tại) | **Loại bỏ** — bỏ hẳn admission (§1.3) |
| **FN hub-split** (chuỗi bàn giao qua hub; tự bơm phồng sid) | Mất hẳn với detection; chỉ còn `link_weak` cho SOC | Trần nới ~10× nên hiếm gặp hơn; khi xảy ra: backend stitch + arm xuống, **FN → trễ giây-cấp** (§7) |
| Low-and-slow / xuyên reboot | sketch + spill | backend giữ trọn, không giới hạn thời gian |
| Cross-host | không | có (§3.3) |
| Evict-as-evasion | Hướng 3 triệt | mặt evict gần như hết mục tiêu (COLD không còn); mặt mới là **flood pipeline** — chặn bằng ưu tiên tier + churn signal (§1.5, §2) |

---

## 7. Giới hạn còn lại (trung thực, kiểu §13 `engine.md`)

- **Cửa sổ trễ của vòng phản hồi là giới hạn vật lý.** Chuỗi mà *chỉ backend* nhìn ra (bị
  hub-split, cross-host) chỉ chặn được từ lần chạm **sau khi** arm xuống tới — hành động đầu
  tiên trong cửa sổ đó (vài trăm ms đến vài giây) không cứu được. Với ransomware nghĩa là một
  vài file đầu nếu chuỗi thuộc loại agent-mù. Mọi pattern muốn chặn-hành-động-đầu-tiên **phải**
  khớp được bằng state cục bộ — đây là tiêu chí quyết định pattern nào bắt buộc nằm trong rule
  file của agent chứ không chỉ backend.
- **Phụ thuộc toàn vẹn stream.** Backend đúng bằng dữ liệu nó nhận; drop T0 dưới backpressure là
  chấp nhận mất forensic phần lành tính — nếu phân loại tier sai (chuỗi độc bị coi T0 và drop
  đúng lúc nghẽn) thì backend cũng mù theo. Counter drop + lỗ `seq` phải được giám sát như tín
  hiệu an ninh, không chỉ tín hiệu vận hành.
- **Bề mặt tấn công mới: kênh điều khiển.** §4.2 giảm nhẹ nhưng không triệt — backend bị chiếm
  vẫn nguy hiểm hơn nhiều so với kiến trúc tự chứa (được arm, được sửa rule/rarity). Cần audit
  riêng cho control-plane.
- **Chi phí hạ tầng**: full event stream của fleet lớn là bài toán ingest/storage thật sự
  (ngoài phạm vi tài liệu này); "đẩy được toàn bộ event" là tiền đề phải kiểm chứng bằng số đo
  băng thông thực tế, nhất là event `write` tần suất cao.
- **Kế thừa nguyên các giới hạn mô hình §13.2** không liên quan vị trí trạng thái: tagger theo
  tên file giòn, kênh nhân-quả ngầm (WMI/COM) chưa mô hình hoá — backend nhìn xa hơn nhưng vẫn
  chỉ thấy những cạnh mà sensor phát ra.

---

## 8. Ánh xạ vào prototype (điểm chạm code)

Tiền đề bắt buộc trước mọi thứ: **§11.0 tối ưu (bind theo identity)** — không có nó thì node
lean/evict per-root gãy binding.

| Thay đổi | File / cấu trúc |
|---|---|
| `LeanNode` thay `Node`; bỏ lưu cạnh, `ADD_EDGE` → cập-nhật-rồi-ship | `lib.rs`: `nodes`, `resolve()`, `on_event()` |
| Tắt admission; giữ `root_gate` cấu trúc | `pattern.rs`: bỏ nhánh rarity của `RootGate` (nếu đã thêm) |
| Nâng `MAX_NODES_PER_SID`; giữ `MAX_AUTOMATA_PER_SID`; `stable_hubs` giữ | hằng số + `unify()` |
| `SHIP()` + hàng đợi tier + disk ring-buffer | mới: `telemetry.rs` |
| Kênh directive (arm/watch/table) + verify chữ ký + trần sanity | mới: `control.rs`; nối vào `kernel_arm` |
| Chuyển chế độ ONLINE/OFFLINE (bật/tắt evictor stack §7) | mới: `mode.rs`; tái dùng nguyên §11 tối ưu |
| Backend: RESOLVE/UNIFY không trần + stitcher + rerun matcher | service riêng, ngoài `engine/src` — tái dùng crate lõi làm thư viện |

Thứ tự triển khai đề xuất (mỗi bước xanh test mới bước tiếp, như §11.4 tối ưu):
1. §11.0 tối ưu (identity binding) — dùng chung cho cả hai kiến trúc.
2. `telemetry.rs`: ship + seq + tier queue (chưa cần backend thật — ghi file là đủ test).
3. Node lean + bỏ lưu cạnh (4 test hiện có phải xanh — matcher không đọc cạnh).
4. `control.rs` + backend-arm tối thiểu (mock backend trong test).
5. Chế độ OFFLINE = gắn stack §11 tối ưu vào sau công tắc mode.
6. Backend stitcher (tái dùng crate lõi, chạy offline trên stream đã ship).

---

## 9. Kiểm chứng (nối tiếp §10 tối ưu)

- `lotl_all_common`: chuỗi toàn TTP rarity thấp, giãn thời gian — **phải khớp** trên lean-agent
  (admission đã bỏ). Đây là test hồi quy cho nguồn FN số 2: stack tự chứa được phép fail, lean
  thì không.
- `service_handoff_stitch`: chuỗi đi qua `services.exe` (hub-split trên agent) — agent một mình
  **fail có chủ đích**; với mock-backend stitch + arm, lần chạm enforceable kế tiếp bị DENY. Đo
  **số hành động lọt trong cửa sổ trễ** — đây là metric chính của kiến trúc (§7).
- `flood_pipeline`: nguồn B spam 100k event T0 trong khi nguồn A chạy chuỗi ransomware — event
  T2+ của A phải tới backend (mock) **trước** khối T0 của B; drop counter chỉ đụng T0.
- `arm_forgery`: directive không ký / `seq` lùi / quá trần sanity → agent từ chối + alert.
- `offline_degrade`: cắt link giữa chuỗi low-and-slow → chuyển mode, spill hoạt động, nối lại
  link → replay theo `seq`, backend dedupe, chuỗi hoàn tất.
- **Đo băng thông ship** trên dataset write-nặng: kiểm tiền đề "đẩy được toàn bộ event" bằng số.

---

## 10. Hằng số khởi điểm (chỉnh qua audit-only)

| Hằng số | Lean (online) | Offline | Ghi chú |
|---|---|---|---|
| `MAX_NODES_PER_SID` | 1_000_000 | 100_000 | trần cũ là trần bộ nhớ; node lean nới 10× |
| `MAX_AUTOMATA_PER_SID` | 32 | 32 | trần CPU — không đổi theo kiến trúc |
| `MAX_LIVE_NODES_PER_ROOT` | 500_000 | 50_000 | node lean |
| `SHIP_QUEUE_CAP` / drop policy | 64k event, drop T0-first | ring đĩa 512MB | counter drop bắt buộc |
| `ARM_TTL` mặc định | 15 phút (lease gia hạn) | giữ đến hết TTL | không có arm vĩnh viễn |
| `MAX_LIVE_ARMS` (sanity) | 1_000/host, 64/root | như online | chống backend-bị-chiếm |

---

## Tóm tắt một đoạn

Khi backend nhận được toàn bộ event, kiến trúc tối ưu không phải là chỉnh knob của stack tự chứa
mà là **đổi vai trò của nó**: agent giữ *toàn bộ* trạng thái phát hiện (automata, binding, arm,
DSU — vì rẻ và vì inline không được chờ mạng) và *không giữ gì* cho forensic (node lean, cạnh
phù du — vì backend làm tốt hơn); stack `engine_state_optimization.md` §7 tụt xuống làm chế độ
offline; backend khâu những gì agent chủ động cắt và vũ trang ngược xuống qua kênh directive có
ký. Kết quả trên hai nguồn FN chủ động: **admission bị loại bỏ hoàn toàn**, hub-split thu về
đúng **cửa sổ trễ mạng** — mức tối thiểu mà mọi kiến trúc phân tán phải chịu.
