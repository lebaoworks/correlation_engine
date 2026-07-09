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
