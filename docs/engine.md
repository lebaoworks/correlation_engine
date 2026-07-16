# Lõi phát hiện phân tách endpoint–backend — Thuật toán

> Kiến trúc hai phía cho một EDR phòng-ngừa (prevention) chạy inline:
> **endpoint** giữ *trạng thái phát hiện* và chặn tại chỗ — **nhanh (O(1)/event), nhẹ (bộ nhớ
> bounded), chính xác (precision cao)**; **backend** nhận toàn bộ event stream, giữ *đồ thị
> forensic* đầy đủ, tương quan không giới hạn và vũ trang ngược xuống endpoint để thực thi.
>
> Ý tưởng cốt lõi: thứ khiến trạng thái phình vô hạn (đồ thị provenance) chỉ phục vụ **điều tra**;
> việc phát hiện inline không cần nó. Nên endpoint **ship-and-forget** mọi event lên backend và
> **không dựng đồ thị cục bộ** — nó chỉ duy trì một *working set* bị chặn bởi một **bất biến bộ
> nhớ** đơn giản (§3), không phải một chính sách dọn dẹp.

---

## 0. Bài toán & nước đi

Trên một host thật, luồng event tích luỹ vô hạn theo thời gian. Phân rã trạng thái cần giữ theo
cấu trúc:

| Thành phần | Kích thước | Tăng theo | Ai thật sự cần? |
|---|---|---|---|
| Cạnh (edges) của đồ thị nhân-quả | ~50B/cạnh | **hoạt động — vô hạn** | chỉ forensic/điều tra |
| Node + index | ~100–200B/node | số thực thể distinct theo thời gian | phát hiện cần *identity + tuyến*; phần còn lại là forensic |
| `Automaton` (tiến độ khớp mẫu) | ~200B–1KB | số chuỗi đang khớp (nhỏ) | **phát hiện — không được mất** |

Hai quan sát quyết định:

1. **Thứ phình vô hạn (cạnh, và phần lớn thuộc tính node) chỉ phục vụ điều tra.** Phát hiện inline
   không đọc cạnh lịch sử — nó đọc tiến độ automaton + identity đang bind + vài bộ đếm trượt.
2. **Nếu điều tra là việc của backend, endpoint không cần lưu cạnh, không cần lịch sử.** Cái còn
   lại (automata + tuyến hiện hành) có **cận trên tự nhiên theo thời gian sống của automaton** —
   bound được mà không cần chính sách evict.

⟹ **Nước đi:** endpoint **ship-and-forget** mọi event lên backend, **không dựng đồ thị cục bộ**;
nó chỉ duy trì working set đủ để chạy automata cho các chuỗi *đang diễn ra trong cửa sổ thời gian
ngắn*. Mọi tương quan vượt tầm đó là việc của backend (§8), và backend **vũ trang ngược** xuống
endpoint để thực thi (§9).

Đây không phải "cắt bớt để tiết kiệm" mà là **phân vai đúng chủ sở hữu**: cái nặng-mà-để-điều-tra
về backend; cái rẻ-mà-để-chặn ở lại endpoint và được giữ *hào phóng, trung thực*.

---

## 1. Phân vai & khế ước phát hiện

```
ENDPOINT  = bộ chặn inline theo CỬA SỔ (bounded-window inline blocker)
            • O(1)/event, không chờ mạng trên đường verdict
            • bộ nhớ bounded bởi BẤT BIẾN working-set (§3), không bởi chính sách evict
            • chặn được chuỗi mà bằng chứng đến trong khi automaton còn sống
BACKEND   = bộ tương quan KHÔNG CỬA SỔ (unbounded correlator)
            • đồ thị provenance đầy đủ, bền, đa-host, không trần
            • matcher chạy lại không deadline: window dài, khâu thành phần, subgraph, baseline rarity
            • phát hiện cái vượt tầm endpoint → VŨ TRANG ngược xuống để thực thi
```

**Khế ước (nói thẳng, không mập mờ):**

- **Endpoint bảo đảm**: mọi mẫu có đủ bằng chứng xuất hiện trong khi automaton của nó còn sống
  (trong các `seg_window`, §6) và các thực thể bị bind còn "ấm" (§3) → **phát hiện + chặn tại
  chỗ, đồng bộ, không hồi tố**. Đây đúng là lớp cần chặn *hành động đầu tiên* (mã hoá, đọc LSASS,
  exfil) — nơi block inline mới có nghĩa.
- **Backend bảo đảm**: mọi thứ vượt tầm endpoint — low-and-slow kéo ngày, bàn giao qua hub, lateral
  movement xuyên host, chuỗi cần subgraph matching — được phát hiện trên đồ thị đầy đủ, rồi **arm**
  xuống endpoint. Cái giá: **cửa sổ trễ** một round-trip (§11) — giới hạn vật lý, không phải lỗi.
- **Endpoint đứng một mình được**: backend là *phần cộng thêm*, không phải phụ thuộc. Mất mạng →
  phát hiện cục bộ **không đổi** (§10); chỉ mất phần vươn xa của backend.

---

## 2. Cấu trúc dữ liệu endpoint (lean)

Endpoint chỉ giữ trạng thái phát hiện. Không có mảng node append-only, không có index toàn cục bền,
không có cạnh, không có lịch sử TTP dài.

```
# ---- thực thể chỉ còn IDENTITY + con trỏ tuyến (không cạnh, không attrs điều tra) ----
Entity ent = {
    key,            # identity ổn định (xem "Khoá identity" dưới)
    line,           # con trỏ tới Storyline hiện hành (null nếu chưa thuộc chuỗi nào)
    refcount,       # số automaton đang BIND thực thể này  (giữ nó "ấm" — §3)
    last_touch      # ts chạm gần nhất (cửa sổ working-set)
}

# ---- storyline = TẬP NHỎ tường minh (KHÔNG union-find toàn cục) ----
Storyline S = {
    members: set<key>,                 # bounded bởi MAX_NODES_PER_SID
    automata: map<pattern_id, Automaton>,   # bounded bởi MAX_AUTOMATA_PER_SID
    ttp_ring: ring<{ttp, ts}>,         # NHỎ, chỉ đủ cho rarity-anchor & scoring window
    last_activity
}

# ---- automaton: tiến độ khớp mẫu, BIND THEO IDENTITY ----
Automaton A = {
    pattern_id,
    completed_mask,          # bitset tiến độ (§6): bit i = bước i đã thoả
    step_ts[],               # mốc hoàn thành từng bit (cho seg_window & order_bonus)
    bound_ids: map<role,key>,# role -> IDENTITY (KHÔNG phải con trỏ node)  — điều kiện để nhẹ
    score,
    armed
}
```

Ba bảng sống trên endpoint, **tất cả tự-bound** (§3):

```
ACTIVE   : key -> Entity            # working set; chỉ chứa thực thể còn ấm hoặc đang bị bind
BIND_IDX : key -> set<(S,role)>     # nghịch đảo: identity nào đang bị automaton nào bind
PRED     : actor_key -> RateState   # bộ đếm trượt cho tagger (rate/dir-spread), windowed
```

Cộng với **bảng kernel-arm** (trong driver, không đếm vào RAM userland) và **hàng đợi ship**
(bounded, spill đĩa — §10). `PATTERN_TRIGGER: ttp -> set<pattern_id>` là bảng tĩnh từ rule (không
tăng), dùng để khởi động mẫu (§6).

**Khoá identity** — mọi so sánh thực thể đi qua *định danh ổn định*, không qua chuỗi path:

- **Process**: `(pid, start_ts)` — `start_ts` chống **pid reuse** (pid được cấp lại cho tiến
  trình khác).
- **File**: `(volume_serial, FileId)` [Windows] hoặc `(dev, inode)` [Linux] — **không phải path**.
  Path đổi được bằng rename và có nhiều biến thể (hoa/thường, 8.3, `\\?\`, hardlink); FileId sống
  sót qua rename và phân biệt được bản copy.
- **Socket**: `(proto, ip, port)`.

> Vì `bound_ids` giữ **identity** chứ không phải con trỏ vào graph, drop một `Entity` khỏi `ACTIVE`
> **không bao giờ làm gãy binding** — đây là tiền đề để bất biến §3 đúng, và để "ghi X rồi chạy
> đúng X" nhận diện được kể cả sau `rename X→Y` (§7).

---

## 3. Bất biến working-set (trái tim của endpoint)

Thay vì một *chính sách eviction* (ai bị bỏ, khi nào, theo tiêu chí nào — mỗi lựa chọn là một edge
case), endpoint giữ một **bất biến duy nhất**:

> **Giữ `Entity e` trong `ACTIVE` ⟺ `e.refcount > 0` (đang bị ≥1 automaton bind) HOẶC
> `e.last_touch ≥ now − W` (chạm trong cửa sổ W).**
> Bỏ `e` ngay khi cả hai sai. Bản forensic của `e` **đã được ship** nên bỏ là *không mất mát*.

Ba hệ quả khoá chặt bộ nhớ, không cần thêm luật nào:

**(a) Tiến độ automaton không bao giờ mất vì áp lực bộ nhớ.** Thực thể mà một automaton đang bind
có `refcount > 0` → *bất khả bỏ*. Automaton chỉ chết theo `seg_window` của chính nó (§6), không
theo độ nguội hay theo trần. ⟹ **không có "LRU giết chuỗi lén lút"**, không cần khái niệm "sticky".

**(b) Thực thể nguội-và-không-bị-bind bỏ đi là an toàn.** Nếu không automaton nào bind `e`, thì
không tiến độ phát hiện nào phụ thuộc `e`; mất liên kết `e → storyline` chỉ mất khả năng *merge
nhân-quả trong tương lai* của một chuỗi **chưa** khởi động — mà chuỗi đó, nếu khởi động, sẽ tự
bind `e` (xem (c)). Và backend vẫn giữ trọn.

**(c) Cái gì đáng theo dõi thì tự ghim mình.** Mọi mẫu seed **tại** bước gốc của nó và **bind ngay**
thực thể quan trọng. Ví dụ dropper: event `write X` vừa seed automaton vừa `bind dropped:=X` → từ
giây đó `X.refcount>0`, `X` ở lại bất kể nguội, tới khi `exec X` khớp hoặc automaton hết
`seg_window`. Bind theo FileId nên `rename X→Y` cũng vô hại (§2).

**Cận bộ nhớ (chứng minh phác):**
```
|ACTIVE| ≤  Σ (arity bind của các automaton sống)           # thành phần "bị ghim"
          + |{thực thể chạm trong W}|                        # thành phần "còn ấm"
        ≤  MAX_AUTOMATA_GLOBAL × MAX_BIND_ARITY  +  event_rate × W
```
Cả hai số hạng là **hằng số theo cấu hình**, không phụ thuộc tổng số thực thể từng thấy hay tổng
hoạt động tích luỹ. `BIND_IDX`, `PRED` cũng bị kẹp bởi cùng hai đại lượng. ⟹ **RAM phẳng.**

Dọn dẹp là **lười, amortized**: mỗi event kiểm `last_touch` của vài thực thể chạm gần (hoặc một
sweep vòng nhẹ), bỏ cái hết hạn & `refcount==0`. Không danh sách LRU liên kết, không cấu trúc ưu
tiên, không stop-the-world. Tăng dần → không spike p99.

> Điểm cốt lõi: **cái bị bỏ không bao giờ là trạng thái phát hiện** — chỉ là node graph mà backend
> mới là chủ sở hữu thật. Chuỗi vượt cửa sổ W **không** được cứu bởi endpoint; nó là *việc của
> backend* theo khế ước §1. Ta đổi "cố cứu mọi thứ tại chỗ (đẻ edge case)" lấy "một ranh giới trách
> nhiệm sắc nét".

---

## 4. Vòng lặp chính endpoint (per-event)

```
function ON_EVENT(e):                                   # tất cả bước O(1) amortized
    a = TOUCH(e.actor)                                  # get-or-create Entity, cập nhật last_touch
    o = TOUCH(e.object)

    S = LINK(a, o, e.op)                                # merge nhân-quả trong working set (§5)

    SHIP(e, meta={host, sid=id(S), seq++})              # (!) đẩy async lên backend — KHÔNG lưu cạnh

    ttps = TAG_TTP(e, a, o, S)                          # gán technique (§6.0), dùng PRED cho rate/spread

    verdict = ADVANCE(S, ttps, e)                       # seed + push automata + score (§6)

    SWEEP_A_LITTLE(now)                                 # GC automaton hết seg_window + bỏ entity nguội

    return DECIDE(verdict, e)                           # DENY/ALLOW inline (§8-endpoint)
```

**Cạnh không tồn tại trong bất kỳ cấu trúc cục bộ nào.** Một cạnh chỉ sống đúng một khoảnh khắc:
1. cập nhật `LINK` (merge nhân-quả, nếu là op causal),
2. cập nhật `PRED` (bộ đếm tagger),
3. đi vào hàng đợi ship,
rồi biến mất khỏi endpoint. Đồ thị mà SOC xem được dựng **hoàn toàn ở backend** (§8).

`SHIP` là push lock-free vào ring; nén/gửi ở thread riêng, **ngoài hot path** — cam kết O(1) giữ
nguyên. `seq` đơn điệu per-host để backend phát hiện lỗ stream (mất event = tín hiệu, không im
lặng).

`DECIDE`: `BLOCK → DENY` (kernel trả `-EPERM`/chặn I/O); mọi verdict khác → `ALLOW`. **Fail-open**:
nếu daemon quá tải/không phản hồi trong ngân sách latency, kernel **allow** (ưu tiên ổn định) —
trạng thái đã đẩy sẵn xuống kernel (arm, §9) vẫn giữ được điểm nghẽn dù userland chậm.

---

## 5. LINK — merge nhân-quả trên tập nhỏ tường minh

Một storyline là **tập nhỏ có trần**, không phải một thành phần của union-find toàn cục. Nhờ đó
xoá member là O(1) và merge là union-by-size bounded — không cần tombstone/rebuild.

```
function LINK(a, o, op):
    Sa = a.line ?? NEW_STORYLINE(a)
    if not IS_CAUSAL(op):                 # read/open/connect: chỉ chạm — không merge
        return Sa                         # (cạnh đã được SHIP cho forensic)

    So = o.line
    if So == null:
        JOIN(o, Sa)                       # object kế thừa storyline actor
        return Sa
    if So == Sa: return Sa

    # merge — NHƯNG có trần: hub không được nuốt cả máy
    if |Sa.members| + |So.members| > MAX_NODES_PER_SID
       or |Sa.automata| + |So.automata| > MAX_AUTOMATA_PER_SID:
        return Sa                         # KHÔNG merge tại endpoint; backend sẽ khâu (§8).
                                          # cạnh causal đã SHIP → backend có đủ để nối.
    return MERGE_BY_SIZE(Sa, So)          # dời members/automata tập nhỏ vào tập lớn: O(nhỏ), có trần
```

- **`IS_CAUSAL`**: `exec/inject/create/dup/write` → **merge** (quan hệ *sản sinh/điều khiển*: object
  trở thành sản phẩm của storyline actor). `read/open/connect` → **chỉ ship cạnh**, không merge.
  Đây là van chống bùng nổ phụ thuộc *ngữ nghĩa*: chỉ quan hệ sản sinh mới hợp nhất chuỗi; quan hệ
  *đụng chạm* chỉ để lại cạnh phục vụ scoring/điều tra.
- **Trần merge** là van chống bùng nổ *kích thước* (hub `services.exe`/`explorer.exe` là cha của
  gần như cả máy). Khi chạm trần, endpoint **không merge** — hai storyline sống riêng; tương quan
  xuyên điểm đó do backend làm trên đồ thị đầy đủ. Chỉ **một trần và một fallback** — không thêm cơ
  chế đặc biệt nào để xử lý hub.
- **Xoá gọn**: bỏ một member nguội = `S.members.remove(key)` + `ACTIVE.remove(key)`. Storyline hết
  `members` **và** hết `automata` → tự tiêu.

> Storyline chỉ cần tương quan trong working set nhỏ (tương quan toàn lịch sử là việc backend), nên
> một tập tường minh có trần là đủ — và xoá được, khác với union-find toàn cục.

---

## 6. ADVANCE — partial-order matching + vòng đời

### 6.0 TAG_TTP — gán technique

Mỗi event được gán tập TTP bằng các **tagger** thuần, bounded (predicate closed-set trên `op`,
`image`, `entropy`, rate/spread…). Rate/spread là **stateful nhẹ**: mọi `write` cộng vào bộ đếm
trượt của actor (`PRED`), cập nhật O(1). Tagger là lớp platform-specific; đầu ra là tập `ttps`.

### 6.1 Mẫu = precedence DAG

Mỗi mẫu tấn công là một **thứ tự bộ phận (partial order) = DAG**, tiến độ theo **bitmask các bước
đã hoàn thành**. Không FSM tuyến tính (giả định thứ tự cứng), không subgraph matching (NP-hard).

```
Pattern = { id, steps[], required_mask, scope, block_at, theta_alert, theta_block, root_gate }
Step    = { bit, match, prereq_mask, seg_window, enforceable, optional, bindings }
```
- `match`: khớp theo `ttp:ID`, **OR-slot** `ttp_any:A|B|C` (biến thể công cụ), hoặc raw `op:OP`.
- `prereq_mask`: các bit phải xong **trước** — mã hoá toàn bộ thứ tự bộ phận. "x phải đầu", "nhóm
  tự do thứ tự", "mốc giữa hai nhóm" đều rơi ra từ đây, **không cần liệt kê hoán vị**.
- `bindings`: role → nguồn identity (`object|image|actor`), ràng buộc biến (§6.2).
- `scope` ∈ `same_storyline | same_actor | free`; `block_at` = bit điểm nghẽn chặn được.

### 6.2 Tiến trạng thái

```
function ADVANCE(S, ttps, e):
    # (a) seed: mẫu có bước gốc (prereq_mask==0) khớp e và qua root_gate, chưa có trên S
    for pid in PATTERN_TRIGGER[t] for t in ttps:
        if matches_root(pid, e, ttps) and root_gate(pid).ok(e) and pid not in S.automata:
            S.automata[pid] = NEW_AUTOMATON(pid)         # (trần MAX_AUTOMATA_PER_SID là lưới an toàn)

    # (b) push mọi automaton đang sống trên S
    for A in S.automata:
        for step where step.match khớp (e, ttps):
            if TRY_COMMIT(A, step, e): rescore_and_emit(A, S, e, step)
    return best_verdict
```

`TRY_COMMIT` gồm 4 vị từ, **đều O(1)** — thiếu bất kỳ cái nào thì bỏ qua an toàn (không set bit,
không vỡ chuỗi):

```
PREREQ_OK      : (step.prereq_mask & A.completed_mask) == step.prereq_mask   # đủ tiền đề
SEG_WINDOW_OK  : e.ts − max(A.step_ts[b] for b in prereq) ≤ step.seg_window  # deadline theo đoạn
SCOPE_OK       : same_storyline → true ; same_actor → e.actor ∈ A.bound_ids ; free → true
BINDING_OK     : ∀ binding: identity_of(e, src) khớp A.bound_ids[role] nếu đã có; xung đột → false
```

`COMMIT_STEP` (khi cả 4 đúng):
```
A.completed_mask |= (1 << step.bit);  A.step_ts[step.bit] = e.ts
for binding in step.bindings:
    key = identity_of(e, binding.src)                    # object | image | actor
    if binding.role NEW to A:
        A.bound_ids[binding.role] = key
        ent(key).refcount += 1;  BIND_IDX[key].add((S, role))   # GHIM entity (§3a)
```

Chi phí mỗi event: một phép AND + một phép OR trên machine word — thứ tự tự do/xen kẽ đều **miễn
phí**. Thứ *đắt* duy nhất là binding + thứ tự tự do đồng thời; giữ bounded bằng `scope=
same_storyline`, neo TTP hiếm trước, và trần `MAX_BIND_ARITY` per-pattern.

**Deadline theo từng đoạn (`seg_window`), không window toàn cục.** Mỗi bước có deadline riêng tính
từ khi `prereq` vừa đủ. Nhờ vậy chuỗi dài có thể cách nhau lâu miễn **mỗi đoạn** diễn ra đủ nhanh;
đoạn đến quá muộn thì bỏ qua (không set bit) chứ không vỡ toàn chuỗi.

> **Không có cổng lọc (admission) nào chen giữa seed.** Cứ bước gốc khớp là seed. Được phép "rộng
> tay" vì automaton chỉ ~1KB và **không kéo theo graph**; số lượng automaton do GC theo `seg_window`
> + trần lo (§6.4). Nhờ đó chuỗi toàn-bước-phổ-biến (living-off-the-land) vẫn có automaton từ event
> đầu tiên.

### 6.3 Verdict, arm & chấm điểm

```
function rescore_and_emit(A, S, e, step):
    A.score = KILL_CHAIN_SCORE(A)
    accepting = (A.completed_mask & required_mask) == required_mask
    at_block  = (step.bit == block_at) and step.enforceable

    if accepting:
        if A.score ≥ θ_block and at_block:  return BLOCK      # chặn đúng bước nghẽn, không hồi tố
        if A.score ≥ θ_alert:               return ALERT
        return SUSPECT

    # chưa đủ tập, nhưng đủ điểm + còn một bước enforceable đang chờ → vũ trang kernel
    if A.score ≥ θ_block and not A.armed and has_pending_enforceable(A):
        A.armed = true
        KERNEL_ARM[identity_scope(A, e)] = pending_enforceable_op(A)   # arm THEO IDENTITY (§9)
    return (ALERT if A.score ≥ θ_alert else NONE)
```

**Chấm điểm kill-chain:**
```
KILL_CHAIN_SCORE(A) = w1·(#tactic phủ) + w2·Σseverity + w3·order_bonus + w4·Σrarity
```
- Thứ tự chỉ là **thưởng** (`order_bonus` = tỉ lệ cặp bước đến đúng chiều thời gian), **không** phải
  điều kiện chấp nhận — partial-order vẫn accept dù sai thứ tự, chỉ mất phần thưởng này.
- `rarity` = nghịch đảo tần suất baseline → TTP hiếm kéo điểm lên nhanh, neo vào hành vi bất thường.
- Trọng số hiệu chỉnh để **một mình severity không đủ chặn**: phải phủ nhiều giai đoạn kill-chain
  mới vượt `θ_block`. Hành vi lẻ (đơn TTP) chỉ cảnh báo; chuỗi phủ nhiều tactic mới bị chặn.

**Điểm mấu chốt:** chỉ `BLOCK` khi event hiện tại đúng là bước `block_at` enforceable (mã hoá / đọc
LSASS / exfil). Nếu chuỗi đủ điểm nhưng event enforcing chưa tới, ta ở trạng thái **armed** — đẩy
cờ chặn xuống kernel để chặn nó **ngay trong kernel** lần tới, không round-trip userland.

### 6.4 GC theo `seg_window`

```
GC_AUTOMATON(A, S, now):                # gọi trong SWEEP_A_LITTLE, lười/amortized
    if không bước kế tiếp nào còn kịp (mọi bước enabled đã quá seg_window từ t_enabled):
        for (role,key) in A.bound_ids:                    # NHẢ ghim
            ent(key).refcount -= 1;  BIND_IDX[key].discard((S, role))
        S.automata.remove(A.pattern_id)
    # entity vừa hết refcount + nguội sẽ bị SWEEP bỏ ở lượt sau (§3)
```

Cận số automaton sống: `seed_rate × avg_seg_window`. `seed_rate` bị siết vì bước gốc thường đặc thù
(một LOLBin cụ thể, một PE-write). Trần cứng `MAX_AUTOMATA_GLOBAL`/`_PER_SID` chỉ là **lưới an
toàn**: chạm trần thì endpoint **ngừng seed thêm** — event vẫn được SHIP nên backend vẫn thấy.
**Trần luôn degrade thành "backend bắt", không bao giờ thành mất-âm-thầm.**

---

## 7. Tính chính xác tại endpoint (precision)

"Chính xác" nghĩa là: **khi endpoint DENY thì nó đúng** — không chặn nhầm phần mềm lành tính (với
prevention đây là lỗi đắt nhất). Bốn hàng rào:

1. **Đa-tactic mới chặn** (§6.3): trọng số làm *một mình severity không đủ*; phải phủ nhiều giai
   đoạn kill-chain mới vượt `θ_block`.
2. **Bind theo identity** (§2, §6.2): "ghi X rồi chạy đúng X" phân biệt được với "ghi X chạy Y" →
   khử false-positive dropper. Ví dụ: installer/updater ghi rồi chạy *đúng* file đó → binding khớp
   nhưng điểm thấp (đơn tactic) → chỉ SUSPECT. "Ghi X chạy Y" → binding xung đột → mẫu không accept.
   Rename vô hiệu vì khoá FileId.
3. **Chỉ chặn tại `block_at` enforceable, không hồi tố** (§6.3): DENY đúng hành động nghẽn hiện tại,
   không dựa vào suy đoán quá khứ.
4. **Endpoint chỉ tự chặn theo matcher của chính nó.** Kết luận của backend không tự biến thành
   block; nó hạ xuống thành *arm theo identity + action cụ thể* (§9), và **kernel chỉ deny đúng
   hành động đó trên đúng identity đó**. Backend bị lỗi/bị chiếm cũng không thể "chặn cả máy" — có
   trần sanity (§9).

Precision đến từ **ngữ nghĩa mẫu + binding**, không từ độ lớn đồ thị. Cái endpoint nhường cho
backend là **recall của chuỗi dài/rộng**, không phải precision.

---

## 8. Backend forensic — không cửa sổ, không trần

Backend chạy **cùng lõi matcher** (RESOLVE/UNIFY/ADVANCE/SCORE) nhưng bỏ mọi ràng buộc bounded:

- **Đồ thị đầy đủ, bền, đa-host.** Giữ mọi cạnh + attrs; persistence ⟹ sống qua reboot. Storyline
  graph cho SOC lấy từ đây (endpoint không còn nghĩa vụ forensic).
- **Khâu (stitch) cái endpoint không merge.** Nhận đủ cạnh causal (nhờ SHIP), backend merge **không
  trần** → nối lại chuỗi bị cắt tại hub hoặc tại trần kích thước, rồi chạy lại matcher trên chuỗi
  đã khâu.
- **Matcher không deadline.** `seg_window` nới hoặc bỏ → bắt low-and-slow kéo ngày. Được phép làm
  phép đắt endpoint cấm: subgraph alignment, binding tổ hợp lớn, cửa sổ dài tuỳ ý.
- **Xuyên host.** Nối identity chéo host (remote logon, SMB write A→B) → phát hiện lateral movement.
- **Baseline rarity thật.** Đếm tần suất TTP trên toàn fleet (offline, không cần cấu trúc gần đúng)
  → thay bảng `rarity` tĩnh; đẩy bảng mới xuống endpoint định kỳ (§9).
- **Đo FP audit-only.** Replay stream ở chế độ không-chặn để hiệu chỉnh `θ`/trọng số trước khi bật
  arm.

Backend **không** có verdict đồng bộ. Mọi kết luận đi xuống dưới dạng *thay đổi trạng thái* của
endpoint (arm/watch/rule), để lần chạm kế bị chặn **trong kernel**. Không có đường "event chờ
backend trả lời rồi mới allow" — điều đó vi phạm fail-open (§4).

---

## 9. Kênh backend → endpoint (thực thi cái backend phát hiện)

Kênh điều khiển có xác thực, đẩy trạng thái xuống endpoint:

```
ArmDirective  = { scope:IDENTITY, action, ttl, reason, seq }   # deny 'action' khi chạm 'scope'
WatchDirective= { scope:IDENTITY, boost }                      # KHÔNG chặn — chỉ cộng điểm/ghim
TableUpdate   = { rarity_table | rules }                       # cập nhật knob vận hành
```

- **Arm theo identity** (FileId/(pid,start)), không theo path — nhất quán §2, rename vô hiệu. Kernel
  áp vào bảng arm (hash nonpaged trong driver) tại **hook đồng bộ**: minifilter pre-op cho
  `write/create`, `ObRegisterCallbacks` cho mở handle process (strip `PROCESS_VM_READ`),
  `PsSetCreateProcessNotifyRoutineEx` cho `exec` → `STATUS_ACCESS_DENIED` tại chỗ, không round-trip.
- **Watch** là mức mềm cho kết luận chưa đủ chắc: chạm identity → storyline thăng nghi ngờ + cộng
  điểm để matcher **cục bộ** tự vượt ngưỡng. Backend *mớm*, không *phán* thay.
- **An toàn kênh (bề mặt tấn công mới — arm giả = DoS chặn nhầm hàng loạt):** mTLS + **ký từng
  directive** (khoá riêng control-plane); `seq` đơn điệu (bỏ replay/lùi); **`ttl` theo lease**
  (backend phải gia hạn; mất backend thì arm tự tan — không để trạng thái chặn mồ côi); **trần
  sanity** `MAX_LIVE_ARMS` per-host/per-root (backend bị chiếm cũng không biến endpoint thành công
  tắc tắt máy → từ chối + alert khi vượt).

---

## 10. Đứng một mình & offline

Vì phát hiện cục bộ **không phụ thuộc** backend (backend chỉ cộng thêm), "offline" gần như không
thay đổi gì:

| | Online | Backend mất kết nối |
|---|---|---|
| Phát hiện cục bộ (§3–§7) | chạy | **y nguyên** |
| SHIP | gửi trực tiếp | ghi **disk ring-buffer** bounded (drop cũ nhất khi đầy; counter) |
| Arm hiện có | lease gia hạn | giữ đến hết `ttl` rồi tự rơi |
| Phần vươn xa (stitch/cross-host/low-slow) | có | tạm mất — bắt lại khi nối lại + replay theo `seq` |

Nối lại: replay ring theo `seq`; backend dedupe `(host, seq)`, đối chiếu, có thể phát arm bù. Cái
mất khi offline **đúng bằng** phần recall-vươn-xa — không có "phình bộ nhớ" hay "mất tiến độ" nào
để lo, vì working set vẫn bounded như thường.

---

## 11. Ranh giới phát hiện (trung thực)

Vẽ rõ để không nhầm "endpoint nhẹ" với "endpoint yếu":

- **Trong tầm endpoint (chặn hành-động-đầu-tiên, đồng bộ):** mọi chuỗi mà các đoạn nằm gọn trong
  `seg_window` và thực thể bind còn trong cửa sổ `W`. Gần như toàn bộ ransomware-burst, đọc LSASS,
  chuỗi exec→impact nhanh — đúng lớp mà block inline có ý nghĩa.
- **Chỉ backend (phát hiện + arm, chịu cửa sổ trễ):** low-and-slow vượt `W`; bàn giao qua hub /
  vượt trần merge; xuyên host; mẫu cần subgraph/binding tổ hợp lớn.
- **Cửa sổ trễ** = từ lúc backend kết luận đến lúc arm hiệu lực trong kernel (một RTT). Hành động
  độc **trong** cửa sổ này lọt — giới hạn vật lý của mọi kiến trúc phân tán. Hệ quả thiết kế:
  **mẫu nào cần chặn hành-động-đầu-tiên PHẢI khớp được bằng state cục bộ** (nằm trong rule của
  endpoint), không được chỉ trông vào backend. **Metric chính** của kiến trúc = *số hành động lọt
  trong cửa sổ trễ* trên các kịch bản chỉ-backend-thấy.
- **Giới hạn mô hình:** tagger nhận diện theo tên file còn giòn (cần chữ ký/hash); kênh nhân-quả
  ngầm (WMI/COM/scheduled-task) chưa mô hình hoá — kẻ tấn công sinh tiến trình qua các kênh này cắt
  được quan hệ cha-con, backend nhìn xa hơn nhưng vẫn chỉ thấy cạnh mà sensor phát ra.
- **Tiền đề phải kiểm bằng số:** "ship được toàn bộ event" là giả định về băng thông ingest, nhất
  là `write` tần suất cao — phải đo, không mặc định đúng.

---

## 12. Độ phức tạp & bộ nhớ

| Bước | Chi phí |
|---|---|
| TOUCH / resolve identity | O(1) hash |
| LINK (merge có trần) | O(size storyline nhỏ) ≤ `MAX_NODES_PER_SID` |
| SHIP | O(1) enqueue (nén/gửi off-path) |
| TAG_TTP | O(#candidate_ttps) + O(1) cập nhật PRED |
| ADVANCE | O(#automata trong storyline) ≤ `MAX_AUTOMATA_PER_SID` |
| SWEEP_A_LITTLE | O(1) amortized (lười) |
| **Tổng / event** | **O(1) amortized** |
| **Bộ nhớ** | **O(automata sống × arity bind + event_rate × W)** — hằng số cấu hình, §3 |

Không bước nào phụ thuộc tổng số thực thể từng thấy, tổng cạnh, hay kích thước đồ thị toàn cục —
phù hợp streaming inline.

---

## 13. Hằng số khởi điểm (hiệu chỉnh qua audit-only)

| Hằng số | Mặc định | Ý nghĩa |
|---|---|---|
| `W` (cửa sổ working-set) | 120 s | thực thể không-bind nguội quá W → bỏ (§3) |
| `MAX_NODES_PER_SID` | 4 096 | trần kích thước storyline (van hub, §5) |
| `MAX_AUTOMATA_PER_SID` | 32 | trần chi phí per-event một storyline |
| `MAX_AUTOMATA_GLOBAL` | 100 000 | lưới an toàn tổng (≈ vài chục MB) |
| `MAX_BIND_ARITY` | 8 | số role bind tối đa/pattern (kẹp thành phần "bị ghim") |
| `SHIP_RING` | 64k event RAM / 512 MB đĩa | hàng đợi + spill offline (§10) |
| `ARM_TTL` | 15 phút (lease) | arm tự tan nếu backend không gia hạn (§9) |
| `MAX_LIVE_ARMS` | 1 000/host · 64/root | trần sanity chống backend-bị-chiếm (§9) |

`W` và `seg_window` cùng quyết định *ranh giới tầm endpoint* (§11): nới chúng = bắt được chuỗi dài
hơn tại chỗ, đổi bằng RAM (`event_rate × W`). Đây là **một** núm đánh đổi trực giác — trực tiếp
giữa recall cục bộ và bộ nhớ.
