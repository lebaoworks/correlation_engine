# Tối ưu trạng thái: giới hạn bộ nhớ mà vẫn bắt tối đa

> Bổ trợ cho `engine.md` §7 (chống nổ tài nguyên) và §13.1 (khoảng cách prototype: chưa có
> GC/eviction/trần). Tài liệu này đặc tả **cách bound bộ nhớ mà tối thiểu hoá false negative**.
>
> Nguyên lý xuyên suốt: **đừng cắt đều tay.** Tách trạng thái *rẻ-mà-quan-trọng* (tiến độ khớp mẫu)
> khỏi trạng thái *nặng-mà-thay-thế-được* (đồ thị chi tiết), cắt mạnh cái thứ hai, giữ bền cái thứ
> nhất. Mọi trần phải **theo nguồn**, không toàn cục — nếu không, chính cơ chế giới hạn trở thành cần
> gạt né tránh (evict-as-evasion).

## 0. Vì sao "cap ngây thơ" là bẫy

Một LRU + hard-cap toàn cục mở ra hai lỗ đúng vào mục tiêu của engine:

1. **False negative:** evict một storyline giữa chừng → mất tiền tố chuỗi → chuỗi không hoàn tất.
   Tấn công *low-and-slow* nằm im lâu nhất nên **bị LRU giết trước** — đúng loại cần bắt nhất.
2. **Evict-as-evasion:** kẻ tấn công biết trần N sẽ spam event vô hại để **đẩy chính storyline độc
   của mình (hoặc của người khác) ra khỏi cache**, giữ storyline độc "nguội" trong lúc tạo nhiễu.

Sáu hướng dưới đây được thiết kế để **không** rơi vào hai lỗ này.

---

## Hướng 1 — Tách "trạng thái phát hiện" khỏi "đồ thị forensic" (nền tảng)

### 1.1 Quan sát định lượng
Kích thước thật của trạng thái, theo cấu trúc trong `engine.md` §0 / prototype `lib.rs`:

| Thành phần | Kích thước điển hình | Vai trò |
|---|---|---|
| `AutomatonInstance` | `completed_mask` 8B + `step_ts` ≤64×16B + `bound_nodes` vài×24B ≈ **200B–1KB** | **tiến độ khớp mẫu — KHÔNG được mất** |
| `Node` + `NODE_INDEX` entry | ~100–200B/node, **số lượng khổng lồ** | định danh + tra cứu |
| Cạnh (edges) causality graph | ~50B/cạnh, **nổ theo hoạt động** | forensic / điều tra |

⟹ **Thứ phình bộ nhớ là graph (node/edge/index), không phải automata.** 100k chuỗi đang chạy đồng
thời mà chỉ giữ automaton ≈ vài chục MB — chịu được. Vậy chính sách đảo ngược trực giác:
**giữ automaton hào phóng, cap graph thật chặt.**

### 1.2 Hai pool
```
HOT  (detection state): map<sketch_key, AutomatonSketch>   # nhỏ, giữ bền, gần như không evict
COLD (forensic graph) : nodes + edges + NODE_INDEX chi tiết # lớn, cap cứng, evict/nén mạnh
```

### 1.3 Phép "xẹp" (collapse) — nén thay vì xoá
Trước khi bỏ một storyline khỏi COLD, **chưng cất** nó thành sketch nhỏ và giữ trong HOT:
```
AutomatonSketch = {
    pattern_id,
    completed_mask,                 # giữ nguyên — đây là tiến độ
    step_ts_compact,                # chỉ mốc của các bit đã set
    bound_ids,                      # role -> node IDENTITY (FileId/(pid,start)), KHÔNG giữ node object
    armed,
    score, last_activity,
    seen_ttps: small_set|bloom      # cho scoring khi rehydrate
}
```
Điểm mấu chốt: sketch **không** tham chiếu `Node`/cạnh — nó lưu **identity** (FileId, (pid,start))
để có thể **so khớp lại** khi event tương lai chạm đúng identity đó. Ta mất chi tiết đồ thị (chỉ cần
cho SOC điều tra), **không** mất khả năng tiếp tục khớp chuỗi.

### 1.4 Rehydrate
Khi một event tới và `NODE_INDEX` không còn node (đã bị evict khỏi COLD) nhưng identity của nó khớp
`bound_ids` của một sketch trong HOT → **dựng lại node tối thiểu**, gắn vào sketch, tiếp tục `ADVANCE`.
Chuỗi tiếp diễn dù đồ thị chi tiết đã bị bỏ.

### 1.5 Đánh đổi
- **Được:** gần như không bao giờ mất tiến độ phát hiện; RAM do COLD chi phối và COLD bị bound cứng.
- **Mất:** đồ thị forensic của storyline nguội (có thể spill ra đĩa — Hướng 5). Rehydrate thêm một
  nhánh tra cứu theo identity (vẫn O(1) hash).

---

## Hướng 2 — Giữ theo mức nghi ngờ, không LRU thuần

LRU thuần evict theo *thời gian nguội* → giết đúng chuỗi lén lút. Thay bằng **retention priority**.

### 2.1 Hàm ưu tiên
```
priority(S) =  w_a * armed(S)                         # đã vũ trang kernel → tối đa
             + w_k * max_killchain_progress(S)        # số tactic đã phủ
             + w_r * max_rarity_anchor(S)             # TTP hiếm nhất đã thấy
             + w_b * has_live_binding(S)              # đang giữ ràng buộc node
             - w_c * coldness(now - last_activity)    # càng nguội càng dễ bỏ
```

### 2.2 Quy tắc sticky (bất khả evict)
- `armed == true` (đang chờ chặn điểm nghẽn trong kernel).
- có automaton `score ≥ θ_alert` (đang trong chuỗi tấn công — như §7 đã nêu).
- neo vào TTP có `rarity ≥ ρ_anchor`.
Những cái này **chỉ vào HOT dạng sketch**, không nằm trong diện evict của COLD.

### 2.3 Cấu trúc & thao tác
Chia COLD thành **buckets theo priority tier**; trong mỗi bucket dùng LRU. Evict = lấy bucket
thấp nhất, bỏ phần tử nguội nhất. Cập nhật priority tăng dần (khi automaton tiến bộ, thăng tier).
```
function EVICT_ONE():
    for tier in ascending_priority_tiers:
        if tier.nonempty():
            victim = tier.lru_pop()
            if is_suspicious(victim): COLLAPSE_TO_HOT(victim)   # Hướng 1
            else:                     DROP(victim)
            return
```

### 2.4 Đánh đổi
- **Được:** chuỗi khả nghi sống dai bất kể nguội; trực tiếp vá lỗi "LRU giết chuỗi lén lút".
- **Mất:** bookkeeping priority (cập nhật tier khi tiến bộ) — O(1) amortized nhưng có hằng số.
  Cần chọn trọng số `w_*` và `ρ_anchor` (thêm knob — xem mục Rủi ro chung).

---

## Hướng 3 — Ngân sách theo nguồn/subtree (chống flooding)

Đây là **hàng rào chống evict-as-evasion**. Không dùng một trần toàn cục; cấp **hạn ngạch theo từng
root-entity** (cây tiến trình / nguồn).

### 3.1 Cơ chế
```
per_source_quota[root] = { live_nodes_cap, node_create_rate_cap }
```
- **Trần số node sống** theo root: khi một nguồn vượt trần, eviction chỉ đụng **node nguội của chính
  nguồn đó**, không đẩy được storyline nguồn khác ra.
- **Rate-limit tạo node** theo root: một process spam hàng nghìn file/con bị bóp lại; **và bản thân
  churn bất thường trở thành một tín hiệu** đưa vào scoring (§6) — flooding tự tố cáo.

### 3.2 Chặn bán kính nổ của hub
Process sống lâu (`services.exe`, `explorer.exe`) merge rất nhiều con → storyline khổng lồ (§13.2).
- Áp `MAX_AUTOMATA_PER_SID` (đã nêu §7): trần số mẫu theo dõi đồng thời trên một storyline.
- **Không cho một storyline nuốt tất cả:** khi hub vượt trần, tách **sub-storyline** cho nhánh mới
  thay vì hấp thụ tiếp (giới hạn chi phí per-event và bộ nhớ do một node hub gây ra).

### 3.3 Đánh đổi
- **Được:** vô hiệu hoá đòn state-exhaustion cross-storyline; chi phí hub bounded.
- **Mất:** tách hub có thể **cắt một correlation hợp lệ** đi xuyên hub (hiếm, nhưng có). Cần định
  nghĩa "root-entity" hợp lý (cây tiến trình theo ancestor gần nhất ổn định).

---

## Hướng 4 — Sketch xác suất cho phần "đã từng thấy"

Nhiều predicate chỉ cần **đếm/membership**, không cần tập chính xác. Thay cấu trúc chính xác bằng
cấu trúc **bounded** với sai số có kiểm soát.

| Nhu cầu | Cấu trúc chính xác (tốn) | Thay bằng | Bộ nhớ |
|---|---|---|---|
| dir-spread: số thư mục distinct đã ghi | `HashSet<dir>` | **HyperLogLog** | cố định (vài KB) |
| tần suất write / rate | ring buffer đầy đủ | **Count-Min Sketch** | cố định |
| "đã thấy TTP hiếm này trên storyline chưa" | `HashSet<ttp>` | **Bloom filter** nhỏ | cố định |
| baseline rarity (đếm toàn cục) | bảng đếm lớn | **Count-Min + decay** | cố định |

### 4.1 Ví dụ ánh xạ (predicate T1486 §4)
`distinct_dirs(actor, window) > θ_spread` → thay `RateState.distinct_dirs()` (đang dùng `HashSet`
trong `rules.rs`) bằng **HLL theo actor**: bộ nhớ cố định bất kể ghi bao nhiêu thư mục.

### 4.2 Đánh đổi
- **Được:** bộ nhớ predicate **cố định theo cardinality** — chặn nổ theo hoạt động.
- **Mất:** sai số (false-positive membership của Bloom, sai số ±% của HLL/CMS). **Quan trọng:** sai
  số ở đây chủ yếu làm lệch *độ chính xác điểm số*, hiếm khi làm mất *cả chuỗi* — nên chấp nhận được.
  Chọn kích thước sketch theo sai số mục tiêu; hướng cấu hình **fail toward detection** (thà tính hơi
  cao spread còn hơn bỏ sót).

---

## Hướng 5 — Spill trạng thái nguội-nhưng-đáng-ngờ ra đĩa

Thay vì **bỏ** storyline khả nghi nhưng ít hoạt động, **serialize sketch ra đĩa** và rehydrate khi
cần. Bounds RAM mà không mất tấn công dài ngày; **đồng thời vá luôn giới hạn "mất state khi reboot"**
(§13.1).

### 5.1 Cơ chế
```
SPILL(sketch): ghi AutomatonSketch (Hướng 1) ra store trên đĩa, index theo bound_ids (identity).
REHYDRATE(event): nếu event.identity khớp một bound_id trong disk-index → nạp sketch lại vào HOT,
                  tiếp tục ADVANCE.
```
Chỉ **sketch nhỏ** spill (không phải graph). Khoá rehydrate là **identity có thể tái kích hoạt**
(FileId của file đã bind, (pid,start) của process đã bind).

### 5.2 Đánh đổi
- **Được:** RAM bounded; sống sót qua reboot & low-and-slow rất dài; vẫn giữ tiến độ khớp mẫu.
- **Mất:** I/O đĩa (làm **bất đồng bộ, ngoài hot path** để không gây jitter); cần chính sách dọn
  disk store (TTL dài + cap dung lượng). Rehydrate thêm một tra cứu disk-index (chỉ khi RAM miss).

---

## Hướng 6 — Kiểm soát nạp tại nguồn (neo hiếm trước, mới tạo state)

Đừng tạo trạng thái bền cho tới khi nó **đáng**. Bound state **ngay tại nguồn** thay vì dọn dẹp sau.

### 6.1 Cơ chế
Tổng quát hoá `root_gate` (đã có trong prototype `pattern.rs`) thành **admission control theo rarity**:
- Chỉ **seed automaton** / thăng storyline lên diện theo-dõi-bền khi xuất hiện **neo hiếm**
  (`rarity ≥ ρ_admit`) hoặc bước gốc đủ đặc thù (vd `pe_write` cho dropper).
- Event vô hại phổ biến (`open/read` thường, write file thường) **không sinh state lâu dài** — chỉ
  cập nhật sketch nhẹ rồi quên.

Đây đúng tư tưởng **"neo vào signal hiếm"** của RapSheet/POIROT (`engine.md` §6): tiêu bộ nhớ **quanh
tín hiệu hiếm**, không rải đều.

### 6.2 Đánh đổi
- **Được:** cắt state tại gốc — rẻ nhất, không cần evict về sau; giảm cả chi phí per-event.
- **Mất:** nếu `ρ_admit` quá cao → bỏ lỡ chuỗi mà **mọi** bước đều "phổ biến" (tấn công living-off-the-
  land thuần). Giảm rủi ro bằng cách vẫn cho phép seed khi **mật độ tổ hợp** bất thường (nhiều bước
  phổ biến dồn trong cửa sổ) chứ không chỉ theo rarity đơn lẻ.

---

## 7. Kết hợp đề xuất (stack thực dụng)

Nếu chọn một cấu hình mặc định: chồng **1 + 2 + 3** làm lõi, thêm 4/5/6 theo nhu cầu.

```
                 ┌─────────────── admission (Hướng 6) ───────────────┐
 event ──▶ seed chỉ khi neo hiếm / root-gate ─┐                      │
                                              ▼                      │
        ┌───────────── HOT: AutomatonSketch (Hướng 1) ─────────────┐ │  sticky:
        │  nhỏ · giữ bền · gần như không evict                     │ │  armed / ≥θ_alert /
        └──────────────────────────────────────────────────────────┘ │  neo rarity cao (Hướng 2)
                       ▲ collapse / rehydrate                         │
        ┌───────────── COLD: forensic graph ──────────────────────┐   │
        │  lớn · cap CỨNG · evict theo priority (Hướng 2)          │   │
        │  hạn ngạch theo nguồn/hub (Hướng 3)                      │   │
        │  predicate dùng sketch xác suất (Hướng 4)                │   │
        └──────────────────────────────────────────────────────────┘  │
                       ▼ spill (Hướng 5, async, ngoài hot path)        │
        ┌───────────── DISK: sketch store (sống qua reboot) ───────────┘
        └──────────────────────────────────────────────────────────┘
```

Rút gọn quy tắc vàng:
1. **Cái phải giữ (tiến độ khớp mẫu) thì rẻ → giữ lâu / spill, không bỏ.**
2. **Cái nặng (đồ thị) thì thay thế được → nén rồi bỏ trước.**
3. **Trần phải theo nguồn → không biến thành cần gạt né tránh.**

---

## 8. Bảng đánh đổi tổng hợp

| Hướng | Bound cái gì | Rủi ro FN | Rủi ro né tránh | Chi phí thêm |
|---|---|---|---|---|
| 1 · tách detection/forensic | graph nặng | rất thấp | thấp | logic collapse/rehydrate |
| 2 · priority retention | chọn cái bỏ | thấp | thấp | bookkeeping tier + tuning `w` |
| 3 · ngân sách theo nguồn | flood/hub | thấp | **triệt evict-as-evasion** | định nghĩa root-entity |
| 4 · sketch xác suất | predicate cardinality | thấp (sai số) | thấp | sai số ±%; chọn kích thước |
| 5 · spill đĩa | RAM tổng | rất thấp | thấp | I/O async + dọn disk |
| 6 · admission theo rarity | state tại gốc | trung bình* | thấp | tuning `ρ_admit` |

\* Hướng 6 là chỗ dễ tạo FN nhất (bỏ lỡ chuỗi toàn-bước-phổ-biến) → giảm bằng seed theo **mật độ tổ
hợp**, không chỉ rarity đơn lẻ.

---

## 9. Ánh xạ vào prototype (điểm chạm code)

| Thay đổi | File / cấu trúc hiện tại |
|---|---|
| Tách HOT (sketch) / COLD (graph) | `lib.rs`: `Storyline`, `Automaton`, `nodes`, `node_index` |
| Collapse + rehydrate theo identity | mới, cạnh `resolve()` / `merge()` |
| Priority tiers + `EVICT_ONE` | mới; thay việc "không bao giờ xoá" hiện tại |
| GC theo `seg_window` + sticky ≥θ_alert | `try_commit()` (đã có check window) + vòng GC mới |
| Ngân sách theo nguồn / hub-split | `unify()` / `merge()` (DSU) + trần per-root |
| Sketch xác suất | `rules.rs`: `RateState` (`HashSet` → HLL/CMS) |
| Admission theo rarity | `pattern.rs`: `RootGate` → thêm biến thể theo rarity |

Lưu ý DSU: union-find **không xoá gọn** — evict node đã merge cần tombstoning hoặc rebuild định kỳ
(tăng dần, **không** stop-the-world để tránh spike latency). Đây là điểm khó nhất khi hiện thực.

> Đặc tả thay đổi **chi tiết đến mức struct/hàm** cho Hướng 1+2+3 (lõi của stack §7): xem **§11**.

---

## 10. Cách kiểm chứng

- **Dataset "flood":** một storyline tấn công thật xen giữa hàng chục nghìn event vô hại từ một nguồn
  khác. **Tiêu chí:** storyline tấn công **không** bị đẩy ra (Hướng 2+3), vẫn DENY đúng chỗ.
- **Dataset "low-and-slow":** chuỗi kéo giãn qua nhiều lần vượt ngưỡng nguội. **Tiêu chí:** sketch
  (Hướng 1/5) giữ được tiến độ, chuỗi vẫn hoàn tất.
- **Đo bộ nhớ theo thời gian** dưới tải cao: RAM phải **phẳng** (bounded), không tăng tuyến tính.
- **Đo latency p99 per-event:** GC/eviction **không** tạo spike (kiểm chứng tính tăng dần).
- **Đo sai số sketch (Hướng 4):** lệch dir-spread/rate so với chính xác phải trong ngưỡng, và luôn
  **fail toward detection**.

> Các tiêu chí này nên thành test hành vi mới trong `engine/tests/`, song song 4 test hiện có.

---

## 11. Đặc tả hiện thực chi tiết — Hướng 1 + 2 + 3

Mục này chuyển ba hướng lõi thành thay đổi cụ thể trên prototype (`engine/src/`). Trạng thái hiện
tại (điểm xuất phát):

- `lib.rs`: `Node { key, sid }` sống trong `nodes: Vec<Node>` (uid = chỉ số vec, **không xoá được**);
  `node_index: HashMap<NodeKey, usize>`; `Storyline { automata, ttp_history, score, last_activity }`;
  `Automaton { completed_mask, step_ts, bound_nodes: HashMap<String, usize /*uid*/>, armed }`;
  DSU `dsu_parent` + `find()` / `merge()`; `rate: HashMap<usize /*a_uid*/, RateState>`;
  `kernel_arm: HashMap<usize /*sid*/, Op>`.
- Không có eviction/GC nào — mọi thứ chỉ tăng.

### 11.0 Refactor nền (bắt buộc trước): bind theo **identity**, không theo uid

Điều kiện để collapse/rehydrate (Hướng 1) rẻ là automaton **không được trỏ vào node object**.
Hiện `Automaton.bound_nodes` giữ `uid` (chỉ số vào `nodes`) — evict node là gãy binding.

**Thay đổi:**

```rust
// lib.rs — Automaton
- bound_nodes: HashMap<String, usize>,          // role -> uid
+ bound_ids:   HashMap<String, NodeKey>,        // role -> identity (FileId / (pid,start))
```

Điểm chạm (đều là so sánh tương đương, không đổi ngữ nghĩa):

| Chỗ sửa | Trước | Sau |
|---|---|---|
| `try_commit` BINDING_OK | `existing != uid` | `existing != *key` (so `NodeKey`) — nguồn key: `RoleSource::Object → &e.object`, `Actor → &e.actor`, `Image → e.image_key()` |
| `try_commit` `Scope::SameActor` | `bound_nodes.values().any(\|&u\| u == a_uid)` | `bound_ids.values().any(\|k\| k == &e.actor)` |
| `merge()` gộp automaton | `bound_nodes.entry(role).or_insert(uid)` | `bound_ids.entry(role).or_insert(key)` |

Sau refactor này `try_commit` **không cần** `a_uid/o_uid/img_uid` nữa (bớt 3 tham số); node graph
chỉ còn phục vụ forensic + tra sid — đúng ranh giới HOT/COLD của Hướng 1.

### 11.1 Hướng 1 — Tách HOT/COLD + collapse/rehydrate

#### (a) Cấu trúc mới (file mới `state.rs` đề xuất)

```rust
pub struct AutomatonSketch {
    pub pattern_id: String,
    pub completed_mask: Mask,
    pub step_ts: Vec<(u8, u64)>,            // chỉ mốc của bit đã set (compact)
    pub bound_ids: HashMap<String, NodeKey>,
    pub armed: bool,
    pub score: f64,
    pub last_activity: u64,
}

pub struct Hot {
    sketches: HashMap<SketchKey, AutomatonSketch>,   // SketchKey = (root_id, pattern_id)
    by_identity: HashMap<NodeKey, Vec<SketchKey>>,   // index rehydrate: identity -> sketches chờ
}
```

`step_ts` compact đủ để: (1) `SEG_WINDOW_OK` tiếp tục đúng khi rehydrate, (2) `kill_chain_score`
tính lại nguyên vẹn (nó chỉ đọc `completed_mask` + `step_ts` + pattern — xem `kill_chain_score()`
trong `lib.rs`). `ttp_history` **không** đưa vào sketch (scoring không dùng nó; chỉ forensic cần).

#### (b) COLD phải xoá được: đổi `nodes: Vec<Node>` thành slab

```rust
struct NodeSlot { key: NodeKey, sid: usize }
nodes: Vec<Option<NodeSlot>>,   // slab + free-list
free:  Vec<usize>,
```

Evict node = `nodes[uid] = None` + đẩy `uid` vào `free` + `node_index.remove(&key)` +
`rate.remove(&uid)` (RateState treo theo uid — **phải dọn cùng lúc**, không thì leak).
`resolve()` cấp uid từ `free` trước khi push mới.

#### (c) COLLAPSE — chưng cất trước khi bỏ

```text
COLLAPSE_STORYLINE(sid):
    s = storylines[sid]
    for (pid, a) in s.automata where IS_SUSPICIOUS(a, s):     # tiêu chí ở 11.2(b)
        hot.insert((root_of(sid), pid), sketch_from(a, s.score, s.last_activity))
        for key in a.bound_ids.values(): hot.by_identity[key].push(sketch_key)
    # phần bỏ: mọi node/edge/index thuộc sid + ttp_history + rate của các uid đó
    for uid in members[sid]: free_node(uid)
    storylines.remove(sid); members.remove(sid); dead_sids.insert(sid)
```

Cần thêm **reverse index** `members: HashMap<usize /*sid*/, Vec<usize /*uid*/>>` — cập nhật tại
`resolve()` (thêm uid vào sid mới) và `merge()` (nối `members[child]` vào `members[root]`, O(|child|)
amortized). Đây chính là lời giải "DSU không xoá gọn" ở §9: không rebuild DSU, chỉ cần biết
*node nào thuộc storyline nào* để dọn trọn gói; `dsu_parent` entry chết giữ lại làm tombstone
(`dead_sids`), dọn dần trong vòng GC nền, **không** stop-the-world.

#### (d) REHYDRATE — móc vào `on_event()`

Đặt ngay sau `resolve(actor/object/image)`, trước `advance()`:

```text
REHYDRATE(e, sid):
    for key in [e.actor, e.object, e.image_key()?]:
        for sk in hot.by_identity.remove(key) or []:
            sketch = hot.sketches.remove(sk)
            s = storylines[sid]                       # storyline hiện hành của event
            s.automata.entry(sketch.pattern_id)
                      .merge_or_insert(automaton_from(sketch))   # gộp mask/ts như merge() hiện có
            if sketch.armed: kernel_arm[sid] = ...    # khôi phục arm
            # gỡ sk khỏi by_identity của các identity còn lại
```

Chi phí: 1 tra hash/identity/event khi **miss** (hầu hết event, `by_identity` rỗng cho key đó) —
O(1) đúng cam kết §1.5. Node của storyline cũ **không** dựng lại; chỉ automaton sống lại và tiếp
tục `try_commit` bằng identity (nhờ 11.0).

### 11.2 Hướng 2 — Priority retention thay LRU thuần

#### (a) Tier — cụ thể hoá hàm priority thành 4 bậc

Không cần hàm điểm liên tục + heap; 4 bucket là đủ và rẻ:

```text
T3 STICKY  : automaton armed == true, hoặc s.score >= θ_alert(pattern)   # bất khả evict
T2 SUSPECT : automaton đã qua >= 2 bước, hoặc chạm TTP rarity >= ρ_anchor,
             hoặc đang giữ bound_ids không rỗng
T1 SEEDED  : có automaton nhưng mới 1 bước (mới seed)
T0 PLAIN   : storyline không automaton (chỉ graph forensic)
```

`tier(sid)` tính từ dữ liệu sẵn có trong `Storyline`/`Automaton`; lưu cache `tier: u8` trong
`Storyline`, cập nhật tại đúng 2 chỗ đã sửa trạng thái: cuối `try_commit()` (tiến bộ → có thể thăng
T1→T2) và trong `rescore_and_emit()` (score vượt `theta_alert` hoặc set `armed` → T3).

#### (b) `IS_SUSPICIOUS` (dùng ở COLLAPSE, 11.1c) = `tier >= T1` — nghĩa là **mọi automaton đã seed
đều được chưng cất thành sketch**, chỉ T0 (graph thuần) bị DROP thẳng. Automaton rẻ (§1.1) nên hào
phóng ở đây là đúng thiết kế.

#### (c) LRU lười (lazy) trong mỗi tier — không cần danh sách liên kết

```rust
struct Evictor {
    queues: [VecDeque<(usize /*sid*/, u64 /*seen_at*/)>; 3],  // T0..T2; T3 không có queue
}
```

- Mỗi lần `s.last_activity` được cập nhật (`on_event()`): push `(sid, e.ts)` vào queue của tier
  hiện tại. **Không xoá entry cũ** — chấp nhận entry lặp/ôi.
- `EVICT_ONE()`: pop từ queue thấp nhất không rỗng; entry là *stale* (sid đã chết, đã thăng tier,
  hoặc `seen_at != storylines[sid].last_activity`) thì bỏ qua pop tiếp. Amortized O(1), không có
  bookkeeping trên hot path.

```text
EVICT_ONE():
    for q in queues[T0], queues[T1], queues[T2]:
        while let (sid, seen) = q.pop_front():
            if dead(sid) or tier(sid) đã đổi or seen != last_activity(sid): continue  # stale
            if tier == T0: DROP_STORYLINE(sid)          # bỏ thẳng, không sketch
            else:          COLLAPSE_STORYLINE(sid)      # 11.1(c)
            return true
    return false        # chỉ còn T3 — KHÔNG evict; báo saturation (log + counter)
```

#### (d) Khi nào gọi

Thêm bộ đếm `cold_stats { live_nodes, live_storylines }` cập nhật tại resolve/free. Cuối
`on_event()`: `while cold_stats vượt trần: EVICT_ONE()` — mỗi event tối đa dọn vài phần tử, chi phí
trải đều (tăng dần, đúng yêu cầu p99 của §10). Trần xem bảng hằng số ở 11.4.

#### (e) GC theo `seg_window` (hoàn tất khoảng trống §13.1)

Vòng quét lười cùng nhịp `EVICT_ONE`: automaton mà **mọi** bước kế tiếp đều đã quá `seg_window`
tính từ `t_enabled` (điều kiện `SEG_WINDOW_OK` trong `try_commit` không bao giờ còn qua được) →
xoá automaton khỏi storyline; storyline hết automaton rơi về T0.

### 11.3 Hướng 3 — Ngân sách theo nguồn + tách hub

#### (a) Root-entity

```rust
root_of: HashMap<usize /*sid gốc khi tạo*/, RootId>   // RootId = NodeKey của process "gốc ổn định"
stable_hubs: HashSet<String>                          // từ rule file: services.exe, explorer.exe, svchost.exe...
```

Gán tại event `Exec` (chỗ duy nhất sinh quan hệ cha-con): con kế thừa `root_of[cha]`; **trừ khi**
cha nằm trong `stable_hubs` — khi đó con **tự làm root mới** (`RootId = NodeKey` của con). Danh sách
hub đặt trong rule file (schema §11 của `engine.md`) chứ không hardcode — đây là knob vận hành.

#### (b) Ngân sách

```rust
struct SourceBudget { live_nodes: usize, created_window: VecDeque<u64> }
budgets: HashMap<RootId, SourceBudget>
```

- `resolve()` tạo node mới → `live_nodes += 1` cho root của **actor**; `free_node()` → `-= 1`.
- `live_nodes > MAX_LIVE_NODES_PER_ROOT` → gọi `EVICT_ONE_IN(root)`: bản `EVICT_ONE` (11.2c) nhưng
  **lọc victim cùng root** — nguồn flood chỉ tự dọn nhà nó, không đẩy được storyline nguồn khác.
  Trần toàn cục (11.2d) chỉ là lưới an toàn thứ hai, đi sau trần per-root.
- `created_window` (mốc tạo node trong cửa sổ trượt): vượt `NODE_RATE_PER_ROOT` → **không từ chối
  tạo node** (từ chối = tự tạo FN); thay vào đó phát tín hiệu `churn_anomaly(root)` cho scoring §6
  (flooding tự tố cáo — đúng §3.1) và ưu tiên EVICT_ONE_IN(root) ngay.

#### (c) Tách hub trong `unify()`/`merge()`

Chặn **trước khi** merge, tại `unify()`:

```text
unify(a_uid, o_uid, op):
    ...như hiện tại...
    if automata(sa) + automata(so) > MAX_AUTOMATA_PER_SID
       or |members[sa]| + |members[so]| > MAX_NODES_PER_SID:
        link_weak(sa, so)          # ghi cạnh tham chiếu cross-sid cho forensic, KHÔNG hợp DSU
        return sa                  # hai storyline sống riêng: sub-storyline
    return merge(sa, so)
```

`link_weak` chỉ là một cặp `(sid, sid)` trong log/graph forensic — đủ cho SOC lần vết, nhưng
automaton hai bên không chia sẻ tiến độ (đánh đổi §3.3: có thể cắt một correlation hợp lệ xuyên hub;
chấp nhận để bound chi phí hub).

Đồng thời siết seed tại `advance()` bước (a): storyline đã có `MAX_AUTOMATA_PER_SID` automaton →
không seed thêm (log counter để tuning).

### 11.4 Hằng số mặc định, thứ tự triển khai, test

**Hằng số khởi điểm** (chỉnh qua audit-only, xem §10):

| Hằng số | Mặc định đề xuất | Ghi chú |
|---|---|---|
| `MAX_LIVE_NODES_GLOBAL` | 1_000_000 | trần lưới-an-toàn COLD (~vài trăm MB) |
| `MAX_LIVE_NODES_PER_ROOT` | 50_000 | Hướng 3 đi trước trần toàn cục |
| `NODE_RATE_PER_ROOT` | 5_000 node / 60s | vượt → churn signal + evict nội bộ root |
| `MAX_AUTOMATA_PER_SID` | 32 | trần chi phí per-event của một storyline |
| `MAX_NODES_PER_SID` | 100_000 | ngưỡng tách hub |
| `ρ_anchor` | 0.6 | rarity đủ để lên T2 |

**Thứ tự triển khai** (mỗi bước xanh test rồi mới bước tiếp):

1. **11.0** bind theo identity (refactor thuần, 4 test hiện có phải giữ xanh — không đổi hành vi).
2. **11.1(b)** slab + free-list + `members` reverse-index (chưa evict gì — vẫn không đổi hành vi).
3. **11.2** tier + Evictor + trần toàn cục + GC seg_window → chạy được nhưng còn evict "mù nguồn".
4. **11.1(c,d)** COLLAPSE/REHYDRATE + pool HOT → eviction hết mất tiến độ.
5. **11.3** budgets per-root + hub-split → đóng nốt evict-as-evasion.

(Đúng trình tự đã phân tích: 1 → 2 → 3, vì evict-as-evasion chỉ tồn tại khi đã có eviction.)

**Test hành vi mới** (`engine/tests/`, hiện thực hoá §10):

- `flood_cross_source`: nguồn A chạy chuỗi ransomware demo; nguồn B spam 50k write vô hại xen kẽ →
  A vẫn `DENY` tại chokepoint; RAM (đo `cold_stats`) phẳng.
- `low_and_slow_collapse`: chuỗi dropper giãn thời gian ép storyline bị collapse giữa chừng →
  event chạm `bound_ids` rehydrate đúng, chuỗi vẫn hoàn tất.
- `hub_split`: 200 con của một hub trong `stable_hubs` → không sid nào vượt `MAX_NODES_PER_SID`,
  từng nhánh vẫn khớp mẫu độc lập.
- `sticky_never_evicted`: ép trần thật thấp, storyline `armed` không bao giờ bị evict, `EVICT_ONE`
  trả saturation thay vì đụng T3.
