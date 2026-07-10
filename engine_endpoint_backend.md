# Lõi phát hiện phân tách endpoint–backend — Thuật toán (bản làm lại)

> Bản **làm lại** của `engine.md` theo một tiền đề kiến trúc: **backend nhận toàn bộ event
> stream và giữ đồ thị forensic**; endpoint chỉ giữ *trạng thái phát hiện*. Mục tiêu tại endpoint:
> **nhanh (O(1)/event), nhẹ (bộ nhớ bounded), chính xác (precision cao)**.
>
> Xuất phát điểm là **chính `engine.md`** và khoảng cách nó tự ghi ở §13.1: *không có
> GC/eviction/trần → chạy dài thì phình bộ nhớ vô hạn / OOM.* Thay vì thêm một **chính sách dọn
> dẹp** lên endpoint (mỗi luật dọn là một knob và một bề mặt né tránh), bản này khử nguyên nhân
> gốc bằng cách **dời forensic sang backend** — để endpoint có một *bất biến bộ nhớ* đơn giản
> thay cho một chính sách.
>
> Kế thừa nguyên vẹn từ `engine.md`: khoá identity (§2), partial-order matching bằng bitmask (§5),
> kill-chain scoring (§6), điểm hook kernel & đường inline (§8). Chỉ **lược bỏ** phần khiến graph
> phình trên endpoint và **thêm** ranh giới endpoint↔backend.

---

## 0. Đặt lại bài toán

`engine.md` §13.1 ghi thẳng khoảng cách lớn nhất: *không có GC/eviction/trần → chạy dài trên
event thật thì phình bộ nhớ vô hạn / OOM.* Phân rã cái phình đó theo cấu trúc dữ liệu ở
`engine.md` §0:

| Thành phần | Kích thước | Tăng theo | Ai thật sự cần? |
|---|---|---|---|
| Cạnh (edges) | ~50B/cạnh | **hoạt động — vô hạn** | chỉ forensic/điều tra |
| Node + index | ~100–200B/node | số thực thể distinct theo thời gian | detection cần *identity + tuyến*; phần còn lại là forensic |
| `AutomatonInstance` | ~200B–1KB | số chuỗi đang khớp (nhỏ) | **detection — không được mất** |

Hai quan sát quyết định:

1. **Thứ phình vô hạn (cạnh, và phần lớn thuộc tính node) chỉ phục vụ điều tra.** Detection inline
   không đọc cạnh lịch sử — nó đọc tiến độ automaton + identity đang bind + vài bộ đếm trượt.
2. **Nếu điều tra là việc của backend, endpoint không cần lưu cạnh, không cần lịch sử.** Cái còn
   lại (automata + tuyến hiện hành) có **cận trên tự nhiên theo thời gian sống của automaton** —
   không cần chính sách evict.

⟹ **Một nước đi duy nhất:** endpoint **ship-and-forget** mọi event lên backend, **không dựng đồ
thị cục bộ**; nó chỉ duy trì một *working set* đủ để chạy automata cho các chuỗi *đang diễn ra
trong cửa sổ thời gian ngắn*. Mọi tương quan vượt tầm đó là việc của backend (§8), và backend
**vũ trang ngược** xuống endpoint để thực thi (§9).

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
  detection cục bộ **không đổi** (§10); chỉ mất phần vươn xa của backend.

Điểm khác cốt lõi với `engine.md`: ở engine gốc, endpoint tự gánh *cả* forensic (giữ trọn đồ thị)
nên không có cách bound bộ nhớ mà không hy sinh điều tra. Ở đây forensic ra backend, nên endpoint
chỉ còn một working set bounded — không cần chính sách dọn dẹp nào để mà cân nhắc.

---

## 2. Cấu trúc dữ liệu endpoint (lean)

Đối chiếu `engine.md` §0 — bỏ hẳn `Node.edges`, `NODE_INDEX` toàn cục bền, `ttp_history` dài.

```
# ---- thực thể chỉ còn IDENTITY + con trỏ tuyến (không cạnh, không attrs điều tra) ----
Entity ent = {
    key,            # identity ổn định: (vol,FileId) | (pid,start_ts) | (proto,ip,port)  — §2 engine.md
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

# ---- automaton: y hệt engine.md §5.2 nhưng BIND THEO IDENTITY ----
Automaton A = {
    pattern_id,
    completed_mask,          # bitset tiến độ  (§5)
    step_ts[],               # mốc từng bit    (seg_window & order_bonus)
    bound_ids: map<role,key>,# role -> IDENTITY (KHÔNG phải con trỏ node)  — điều kiện để nhẹ
    score,                   # gấp thẳng vào automaton (không cần state storyline riêng)
    armed
}
```

Ba bảng sống trên endpoint, **tất cả tự-bound** (§3):

```
ACTIVE   : key -> Entity            # working set; chỉ chứa thực thể còn ấm hoặc đang bị bind
BIND_IDX : key -> set<(S,role)>     # nghịch đảo: identity nào đang bị automaton nào bind
PRED     : actor_key -> RateState   # bộ đếm trượt cho tagger (rate/dir-spread), windowed
```

Cộng với **bảng kernel-arm** (trong driver/kernel, không đếm vào RAM userland) và **hàng đợi ship**
(bounded, spill đĩa — §10). Không có `SID_INDEX`, không có `dsu_parent`, không có mảng `nodes`
append-only. `PATTERN_TRIGGER: ttp -> set<pattern_id>` giữ nguyên (bảng tĩnh từ rule, không tăng).

> Vì `bound_ids` là **identity** chứ không phải con trỏ vào graph, drop một `Entity` khỏi `ACTIVE`
> **không bao giờ làm gãy binding**. Đây là tiền đề để §3 đúng — và là khác biệt trực tiếp với
> `engine.md` §5.2, nơi `bound_nodes` giữ `uid` trỏ vào mảng node nên không thể bỏ node.

---

## 3. Bất biến working-set (trái tim của bản làm lại)

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
thực thể quan trọng. Ví dụ dropper (`engine.md` §5.8): event `write X` vừa seed automaton vừa
`bind dropped:=X` → từ giây đó `X.refcount>0`, `X` ở lại bất kể nguội, tới khi `exec X` khớp hoặc
automaton hết `seg_window`. Kẻ tấn công có `rename X→Y` cũng vô hại vì bind theo FileId (§2).

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

    ttps = TAG_TTP(e, a, o, S)                          # §4 engine.md, dùng PRED cho rate/spread

    verdict = ADVANCE(S, ttps, e)                       # §5 engine.md: seed + push automata + score

    SWEEP_A_LITTLE(now)                                 # GC automaton hết seg_window + bỏ entity nguội

    return DECIDE(verdict, e)                           # §8 engine.md: DENY/ALLOW inline
```

Khác biệt **duy nhất mà đáng kể** so với `engine.md` §1: bước `ADD_EDGE` biến mất, thay bằng
`SHIP`. Cạnh không tồn tại trong bất kỳ cấu trúc cục bộ nào — nó chỉ:
1. cập nhật `LINK` (merge nhân-quả, nếu causal),
2. cập nhật `PRED` (bộ đếm tagger),
3. đi vào hàng đợi ship,
rồi biến mất khỏi endpoint. Đồ thị mà SOC xem được dựng **hoàn toàn ở backend**.

`SHIP` là push lock-free vào ring; nén/gửi ở thread riêng, **ngoài hot path** — cam kết O(1) giữ
nguyên. `seq` đơn điệu per-host để backend phát hiện lỗ stream (mất event = tín hiệu, không im
lặng). Đường single-event nguy hiểm (LSASS/vssadmin) vẫn chặn thẳng bằng rule tĩnh trong kernel
(`engine.md` §8), không đợi §4 này.

---

## 5. LINK — merge nhân-quả không dùng union-find toàn cục

`engine.md` §3 dùng DSU (union-find) trên **mọi** node để hợp nhất chuỗi nhân-quả; DSU không xoá
gọn (muốn bỏ một node đã merge phải tombstone hoặc rebuild). Ở đây storyline là **tập nhỏ tường
minh có trần**, nên xoá tầm thường và merge là union-by-size bounded:

```
function LINK(a, o, op):
    Sa = a.line ?? NEW_STORYLINE(a)
    if not IS_CAUSAL(op):                 # read/open/connect: chỉ chạm — không merge (giữ nguyên §3)
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

- **`IS_CAUSAL`** y nguyên `engine.md` §3: `exec/inject/create/dup/write` → merge; `read/open/
  connect` → chỉ ship cạnh. Đây vẫn là van chống bùng nổ phụ thuộc *ngữ nghĩa*.
- **Trần merge** là van chống bùng nổ *kích thước* (hub `services.exe`/`explorer.exe` là cha của
  gần như cả máy). Khi chạm trần, endpoint **không merge** — hai storyline sống riêng; tương quan
  xuyên điểm đó do backend làm trên đồ thị đầy đủ (đã có mọi cạnh nhờ SHIP). Chỉ **một trần và một
  fallback** — không thêm cơ chế đặc biệt nào để xử lý hub.
- **Xoá gọn**: bỏ một member nguội = `S.members.remove(key)` + `ACTIVE.remove(key)`. Storyline hết
  `members` **và** hết `automata` → tự tiêu. Không tombstone, không rebuild.

> Vì sao đơn giản hơn mà vẫn đúng: DSU cần thiết khi ta muốn *một* cấu trúc tương quan bao trùm
> toàn lịch sử. Ở đây tương quan toàn lịch sử là việc backend; endpoint chỉ cần tương quan trong
> working set nhỏ → tập tường minh có trần là đủ và xoá được.

---

## 6. ADVANCE + GC — matching giữ nguyên, thêm vòng đời

Thuật toán tiến trạng thái **không đổi** so với `engine.md` §5.3–§5.5: seed qua `PATTERN_TRIGGER`,
đẩy bit qua `PREREQ_OK / SEG_WINDOW_OK / SCOPE_OK / BINDING_OK`, `MAYBE_EMIT` sinh verdict + armed.
Scoring **không đổi** so với §6. Ba điều chỉnh để hợp với endpoint lean:

**(a) Seed giữ nguyên ngữ nghĩa `engine.md`.** Cứ TTP khớp step gốc (`prereq_mask==0`) là seed qua
`PATTERN_TRIGGER` — không có cổng lọc nào chen giữa. Được phép làm "rộng tay" vậy vì automaton trên
endpoint chỉ ~1KB và **không kéo theo graph** (graph ở backend); cận số lượng automaton do GC theo
`seg_window` + trần lo (mục (c)), không cần siết ở khâu seed.

**(b) COMMIT_STEP cập nhật refcount + BIND_IDX.**
```
COMMIT_STEP(A, step, e):
    A.completed_mask |= (1 << step.bit);  A.step_ts[step.bit] = e.ts
    if step.bind:
        key = identity_of(e, step.bind.src)      # object | image | actor  (§2)
        A.bound_ids[step.bind.role] = key
        ent(key).refcount += 1;  BIND_IDX[key].add((S, role))   # GHIM entity (§3a)
```

**(c) GC theo `seg_window` (đóng khoảng trống §13.1 của engine.md).**
```
GC_AUTOMATON(A, S, now):                # gọi trong SWEEP_A_LITTLE, lười/amortized
    if ∀ bước kế tiếp: (now − t_enabled(step)) > step.seg_window:   # không bước nào còn kịp
        for (role,key) in A.bound_ids:                              # NHẢ ghim
            ent(key).refcount -= 1;  BIND_IDX[key].discard((S,role))
        S.automata.remove(A.pattern_id)
    # entity vừa hết refcount + nguội sẽ bị SWEEP bỏ ở lượt sau (§3)
```

Cận số automaton sống: `seed_rate × avg_seg_window`. `seed_rate` bị siết vì step gốc thường đặc thù
(một LOLBin cụ thể, một PE-write). Trần cứng `MAX_AUTOMATA_GLOBAL`/`_PER_SID` chỉ là **lưới an
toàn**: khi chạm trần, endpoint **ngừng seed thêm** (log counter) — event vẫn được SHIP nên backend
vẫn thấy. **Trần luôn degrade thành "backend bắt", không bao giờ thành mất-âm-thầm.**

---

## 7. Tính chính xác tại endpoint (precision)

"Chính xác" ở endpoint nghĩa là: **khi nó DENY thì nó đúng** (không chặn nhầm phần mềm lành tính —
với prevention đây là lỗi đắt nhất, `engine.md` §13.2). Bốn hàng rào, đều kế thừa engine gốc và
được bản làm lại giữ trọn:

1. **Đa-tactic mới chặn** (`engine.md` §6): trọng số hiệu chỉnh để *một mình severity không đủ*;
   phải phủ nhiều giai đoạn kill-chain mới vượt `θ_block`. Hành vi lẻ → chỉ ALERT.
2. **Bind theo identity** (§2, §5.8): "ghi X rồi chạy đúng X" phân biệt được với "ghi X chạy Y" →
   khử FP dropper. Rename vô hiệu vì khoá FileId, không phải path.
3. **Chỉ chặn tại `block_at` enforceable, không hồi tố** (`engine.md` §5.5): DENY đúng hành động
   nghẽn hiện tại (mã hoá/đọc LSASS/exfil), không dựa vào suy đoán quá khứ.
4. **Endpoint chỉ tự chặn theo matcher của chính nó.** Kết luận của backend không tự biến thành
   block; nó hạ xuống thành *arm theo identity + action cụ thể* (§9), và **kernel chỉ deny đúng
   hành động đó trên đúng identity đó**. Backend bị lỗi/bị chiếm cũng không thể "chặn cả máy" —
   có trần sanity (§9).

Endpoint **không** hy sinh precision để bù cho việc bỏ forensic: precision đến từ ngữ nghĩa mẫu +
binding, không từ độ lớn đồ thị. Cái nó nhường cho backend là **recall của chuỗi dài/rộng**, không
phải precision.

---

## 8. Backend forensic — không cửa sổ, không trần

Backend chạy **cùng crate lõi** (RESOLVE/UNIFY/ADVANCE/SCORE) nhưng bỏ mọi ràng buộc bounded:

- **Đồ thị đầy đủ, bền, đa-host.** Giữ mọi cạnh + attrs; persistence sẵn có ⟹ sống qua reboot
  (vá §13.1). Storyline graph cho SOC lấy từ đây.
- **Khâu (stitch) cái endpoint không merge.** Nhận đủ cạnh causal (nhờ SHIP), backend merge **không
  trần** → nối lại chuỗi bị cắt tại hub hoặc tại trần kích thước. Rồi chạy lại matcher trên chuỗi
  đã khâu.
- **Matcher không deadline.** `seg_window` nới hoặc bỏ → bắt low-and-slow kéo ngày. Được phép làm
  phép đắt endpoint cấm: subgraph alignment kiểu POIROT, binding tổ hợp vượt trần, cửa sổ dài tuỳ ý.
- **Xuyên host.** Nối identity chéo host (remote logon, SMB write A→B) → lateral movement, vá giới
  hạn "chỉ một host" của §13.2.
- **Baseline rarity thật.** Đếm tần suất TTP trên toàn fleet (không cần cấu trúc gần đúng vì offline)
  → thay bảng `rarity` tĩnh chỉnh tay; đẩy bảng mới xuống endpoint định kỳ (§9).
- **Đo FP audit-only.** Replay stream ở chế độ không-chặn để hiệu chỉnh `θ`/trọng số trước khi bật
  arm — vá §13.2 ("scoring chưa hiệu chỉnh").

Backend **không** có verdict đồng bộ. Mọi kết luận đi xuống dưới dạng *thay đổi trạng thái* của
endpoint (arm/watch/rule), để lần chạm kế bị chặn **trong kernel**. Không có đường "event chờ
backend trả lời rồi mới allow" — điều đó vi phạm fail-open.

---

## 9. Kênh backend → endpoint (thực thi cái backend phát hiện)

Mở rộng `PUSH_KERNEL_ARM` (`engine.md` §5.5) thành kênh điều khiển có xác thực:

```
ArmDirective  = { scope:IDENTITY, action, ttl, reason, seq }   # deny 'action' khi chạm 'scope'
WatchDirective= { scope:IDENTITY, boost }                      # KHÔNG chặn — chỉ cộng điểm/ghim
TableUpdate   = { rarity_table | rules }                       # cập nhật knob vận hành
```

- **Arm theo identity** (FileId/(pid,start)), không theo path — nhất quán §2, rename vô hiệu. Kernel
  áp vào bảng arm (hash nonpaged, khoá `(sid|FileId|pid)` — `engine.md` §8.1); event enforcing khớp
  → `STATUS_ACCESS_DENIED` tại chỗ, không round-trip.
- **Watch** là mức mềm cho kết luận chưa đủ chắc: chạm identity → storyline thăng nghi ngờ + cộng
  điểm để matcher **cục bộ** tự vượt ngưỡng. Backend *mớm*, không *phán* thay.
- **An toàn kênh (bắt buộc — bề mặt tấn công mới):** mTLS + **ký từng directive** (khoá riêng
  control-plane); `seq` đơn điệu (bỏ replay/lùi); **`ttl` theo lease** (backend phải gia hạn; mất
  backend thì arm tự tan — không để trạng thái chặn mồ côi); **trần sanity** `MAX_LIVE_ARMS`
  per-host/per-root (backend bị chiếm cũng không biến endpoint thành công tắc tắt máy → từ chối +
  alert khi vượt).

---

## 10. Đứng một mình & offline

Vì detection cục bộ **không phụ thuộc** backend (backend chỉ cộng thêm), "offline" ở đây không phải
một chế độ degraded phức tạp — nó gần như không thay đổi gì:

| | Online | Backend mất kết nối |
|---|---|---|
| Detection cục bộ (§3–§7) | chạy | **y nguyên** |
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
- **Giới hạn kế thừa (không liên quan vị trí trạng thái, `engine.md` §13.2):** tagger theo tên file
  còn giòn (cần chữ ký/hash); kênh nhân-quả ngầm WMI/COM/scheduled-task chưa mô hình hoá — backend
  nhìn xa hơn nhưng vẫn chỉ thấy cạnh mà sensor phát ra.
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

Không bước nào phụ thuộc tổng số thực thể từng thấy, tổng cạnh, hay kích thước đồ thị toàn cục.

---

## 13. Khác biệt so với `engine.md` gốc & vì sao ít edge case

Bản này thay đổi đúng những chỗ khiến `engine.md` phình trên endpoint (§13.1 của nó), giữ nguyên
phần lõi phát hiện:

| Chủ đề | `engine.md` gốc | **Bản này** |
|---|---|---|
| Đồ thị forensic | trên endpoint, **không trần → OOM** (§13.1) | **ở backend**; endpoint không giữ cạnh (§0,§4) |
| Bound bộ nhớ | không có (§13.1) | *bất biến* working-set: refcount ∨ cửa sổ W (§3) |
| Giữ tiến độ khớp | in-memory, **không GC** (§13.1) | refcount ghim; GC theo `seg_window` (§6c) |
| Binding | `bound_nodes` giữ `uid` → node không bỏ được | `bound_ids` giữ identity → bỏ node vẫn an toàn (§2) |
| Hợp nhất chuỗi | DSU toàn cục, xoá phải tombstone (§3) | tập nhỏ tường minh có trần, xoá O(1) (§5) |
| Hub nuốt cả máy | merge tất → nổ (§13.2) | **một trần merge → fallback backend khâu** (§5) |
| Chuỗi dài/xuyên host | không mô hình / chỉ một host (§13.2) | **giao backend** không cửa sổ, cross-host (§8) |
| Persistence | mất khi restart (§13.1) | backend bền; endpoint offline ghi disk ring-buffer (§8,§10) |
| Enforcement | chỉ arm cục bộ (§5.5) | arm cục bộ **+** backend-arm có ký (§9) |

Tinh thần: `engine.md` bắt endpoint *tự gánh mọi thứ trong bộ nhớ hữu hạn* → không có cách bound mà
không hy sinh điều tra. Bản này rút gọn câu hỏi thành *"cái này để chặn hay để điều tra?"* —
để-điều-tra thì lên backend, để-chặn thì ở lại và được một bất biến đơn giản bảo vệ. Ít cơ chế, ít
knob, ít bề mặt né tránh — đổi lại một khế ước phân vai phải nói thẳng: **endpoint không tự bắt
chuỗi dài; đó là việc backend, trả bằng cửa sổ trễ.**

---

## 14. Hằng số khởi điểm (hiệu chỉnh qua audit-only)

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

`W` và `seg_window` cùng quyết định *ranh giới tầm endpoint* (§11): nới chúng = bắt được chuỗi
dài hơn tại chỗ, đổi bằng RAM (`event_rate × W`). Đây là **một** núm đánh đổi trực giác — trực
tiếp giữa recall cục bộ và bộ nhớ.
