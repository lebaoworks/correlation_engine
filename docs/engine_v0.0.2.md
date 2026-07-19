# Engine v0.0.2 — pattern = partial-order DAG (thứ tự bộ phận)

> Bản nâng cấp từ [`engine_v0.0.1.md`](engine_v0.0.1.md), thực hiện mục **1** của
> [`todo.md`](todo.md): thay `stage` tuyến tính bằng **bitmask tiến độ + `prereq_mask`** cho từng
> bước — automaton khớp theo **thứ tự bộ phận (partial order)**, không còn giả định thứ tự cứng.
>
> Đây là bước tối ưu **một-thay-đổi**: chỉ đổi cách automaton ghi tiến độ. Mọi thứ khác — `LINE`,
> `Storyline`, `DISARMED`, cách seed — giữ y nguyên v0.0.1. Tham chiếu thiết kế đích:
> [`engine.md §6.1`](engine.md).

---

## 1. Vấn đề của thiết kế trước — thứ tự cứng

`stage` tuyến tính của v0.0.1 giả định các bước tới **đúng theo vị trí** viết trong mẫu:
`steps[stage]` khớp thì tiến 1, không thì đứng yên. Nhưng chuỗi tấn công thật không nợ ai thứ tự
đó — hai bước không phụ thuộc nhân-quả (do thám thư mục và xoá Shadow Copy) có thể tới theo bất kỳ
chiều nào, tuỳ timing hệ thống hoặc tuỳ ý kẻ tấn công.

Lấy đúng kịch bản [`replay.md`](replay.md): nếu `vssadmin` (T1490, bước 2) chạy **trước** bước liệt
kê Documents (T1083, bước 1), event T1490 tới lúc automaton còn đang chờ `steps[1]` — không khớp,
**bị bỏ qua không dấu vết**; khi T1083 tới, automaton tiến sang chờ `steps[2]` (T1490) — nhưng
T1490 đã trôi qua và không tới lại. Kẹt vĩnh viễn ở `stage=2`: bước mã hoá T1486 không bao giờ được
khớp, dù cả bốn hành vi đều đã xảy ra đầy đủ. Một **false negative** trọn vẹn, và đồng thời là
đường bypass rẻ nhất có thể: *đảo thứ tự bước để né rule*. Vá bằng rule tuyến tính nghĩa là liệt kê
mọi hoán vị hợp lệ — k bước tự do thứ tự = k! pattern.

Đây là khiếm khuyết **duy nhất** bản này giải.

---

## 2. Phương án — chỉ đổi cách ghi tiến độ

**`stage` tuyến tính → `done_mask` bitmask.** Mỗi bước giữ một `bit` cố định và một `prereq_mask` —
tập bit phải xong **trước** nó. Một bước khớp được khi mọi bit tiền đề đã bật (`prereq_mask ⊆
done_mask`), bất kể vị trí viết trong mẫu. "Tuyến tính", "nhóm tự do thứ tự", "mốc giữa hai nhóm",
"bước tuỳ chọn" đều chỉ là các cách đặt `prereq_mask` khác nhau (§6) — chi phí khớp per-event là
một phép AND trên machine word.

`LINE`, `Storyline`, `DISARMED`, `ON_EVENT`, cách seed automaton — **không đổi** so với v0.0.1.
Automaton chỉ nặng thêm đúng một machine word (`done_mask` thay cho `stage`).

> **Ghi chú — action/verdict (chính thức từ bản này).** Step chỉ có **hai** hành vi cưỡng chế:
> `block` và `disarm(ops)`; trường `action` là *tuỳ chọn* — bước không mang action là bước **chỉ
> báo hiệu**. `ignore`/`inspect` không phải action mà là **verdict** engine trả về: `ignore` =
> event không kích hoạt bước nào; `inspect` = event vừa kích hoạt ít nhất một bước không cưỡng
> chế. Thang verdict: `ignore < inspect < block < disarm`. (Áp ngược cho cả base/v0.0.1.)

---

## 3. Cấu trúc dữ liệu

```
# ---- không đổi so với v0.0.1: LINE, DISARMED ----
LINE     = map<key, Storyline>
DISARMED = map<actor_key, set<Op>>

# ---- storyline: automata vẫn là LIST instance mỗi pattern (không đổi so với v0.0.1) ----
Storyline S = {
    members: set<key>,
    automata: map<pattern_id, list<Automaton>>,
    last_activity
}

# ---- pattern = precedence DAG, k ≤ 64 bước — done_mask nằm gọn một machine word ----
Pattern = { id, steps: [Step_0 .. Step_{k-1}] }
Step    = { bit, match, prereq_mask, action? }   # action ∈ {block, disarm(ops)} | ∅

# ---- automaton: tiến độ = bitmask (thay cho stage tuyến tính). KHÔNG có gì khác. ----
Automaton A = { pattern_id, done_mask }
```

- `prereq_mask == 0` ⟹ **bước gốc** — điểm được phép seed automaton (§5).
- `Automaton` không mang thêm trường nào ngoài `done_mask`. Các trường phục vụ chấm điểm hay ràng
  buộc identity (`required_mask`, mốc thời gian, identity đã bind…) xuất hiện đúng lúc có người
  dùng ở các bản `engine_v*` sau, không thêm sẵn ở đây.

---

## 4. Vòng lặp chính (per-event)

```
function ON_EVENT(e):                      # KHÔNG ĐỔI so với v0.0.1 §4
    if e.op in DISARMED.get(e.actor, {}):  # kiểm trước mọi thứ
        return block

    S = UNIFY_STORYLINE(e.actor, e.object) # gộp theo storyline

    ttps = TAG_TTP(e)

    return ADVANCE(S, ttps, e)             # chỉ ruột ADVANCE đổi (§5)
```

Không thêm dòng nào so với v0.0.1. Thay đổi duy nhất nằm trong `ADVANCE`.

---

## 5. ADVANCE — seed như cũ, tiến theo bitmask

```
function ADVANCE(S, ttps, e):
    verdict = ignore

    # (a) seed: mỗi bước GỐC (prereq_mask==0) khớp e thì thêm MỘT automaton mới vào list.
    #     Giống hệt cách v0.0.1 seed khi steps[0] khớp — chỉ khác "bước đầu" giờ là "bước gốc".
    for pid in ALL_PATTERNS:
        for step in PATTERN[pid].steps where step.prereq_mask == 0 and step.match ⊨ (e, ttps):
            S.automata[pid].append({ pattern_id: pid, done_mask: 0 })
            # (bước gốc được commit ngay ở (b), như mọi automaton)

    # (b) tiến mọi automaton trong S: mọi bước chưa done mà tiền đề đủ + match khớp đều commit
    for pid in S.automata:
        for A in S.automata[pid]:
            for step in PATTERN[pid].steps:
                if step.bit ∉ A.done_mask
                   and (step.prereq_mask & A.done_mask) == step.prereq_mask   # PREREQ_OK
                   and step.match ⊨ (e, ttps):
                    A.done_mask |= (1 << step.bit)
                    verdict = max(verdict, APPLY(step, e))   # APPLY: không đổi (∅→inspect,
                                                              # block→block, disarm→DISARMED+disarm)
    return verdict
```

Vị từ commit của bản này chỉ còn **một** — `PREREQ_OK` (tiền đề đủ). Không scope, không binding,
không ràng buộc thời gian — những cái đó là chuyện các bản sau. Ba khác biệt hành vi so với v0.0.1,
đều do partial-order:

1. **Một event có thể commit nhiều bước** của cùng automaton (hai bước cùng đủ tiền đề, cùng khớp)
   — verdict vẫn là phản ứng mạnh nhất trong các bước vừa kích hoạt.
2. **Bước đã done không commit lại** — event lặp một hành vi đã ghi nhận không kích hoạt gì.
3. **Bước khớp bất kể thứ tự đến**, miễn tiền đề đã đủ — đây chính là chỗ khử false negative của §1.

Seed vẫn theo mô hình **list** của v0.0.1 (mỗi bước gốc khớp thêm một instance).

---

## 6. Viết mẫu — các hình thái thứ tự

Mọi hình thái chỉ là cách đặt `prereq_mask`; matcher không cần biết gì thêm:

| Hình thái | Cách mã hoá |
|---|---|
| Tuyến tính (như v0.0.1) | `prereq(i) = {i−1}` — chuỗi phụ thuộc nối đuôi |
| Nhóm tự do thứ tự | các bước trong nhóm cùng `prereq` = {các bước trước nhóm} |
| Mốc (milestone) | bước mốc `prereq` = {mọi bit của nhóm trước nó} |
| Bước tuỳ chọn | một bước không nằm trong `prereq` của bất kỳ bước nào — commit và nổ action khi xảy ra, không chặn ai |

Mẫu ransomware của [`replay.md`](replay.md) viết lại thành DAG — do thám (bit 1) và xoá Shadow Copy
(bit 2) **tự do thứ tự** sau bước gốc; mã hoá (bit 3) là **mốc** đòi cả hai:

| bit | match | prereq | action |
|---|---|---|---|
| 0 | T1059 — chạy LOLBin bất thường | ∅ (gốc) | ∅ (báo hiệu) |
| 1 | T1083 — liệt kê thư mục/file | {0} | ∅ |
| 2 | T1490 — xoá Shadow Copy | {0} | ∅ |
| 3 | T1486 — ghi hàng loạt entropy cao | {1, 2} | `disarm(write, exec, …)` |

Chuỗi `T1059 → T1490 → T1083 → T1486` (đảo bước 1↔2 so với kịch bản gốc) — thứ làm v0.0.1 kẹt —
giờ khớp trọn: bit 2 commit trước bit 1, mốc bit 3 mở khi cả hai đã bật. Không một pattern nào phải
viết thêm.

Người viết rule chỉ nghĩ theo đồ thị phụ thuộc thay vì dãy tuần tự — trả một lần lúc viết rule.
Trình compile rule kiểm: `prereq` không chu trình (DAG thật), bit không trùng / không vượt k ≤ 64,
mọi bit đạt được từ ít nhất một bước gốc.

---

## 7. Độ phức tạp & bộ nhớ

| Bước | Chi phí |
|---|---|
| `DISARMED` / `UNIFY_STORYLINE` | không đổi so với v0.0.1 |
| khớp một bước | O(1) — một AND (`PREREQ_OK`) + kiểm `match` |
| `ADVANCE` | O(#pattern + Σ (bước × instance) của automaton trong S) |
| **Bộ nhớ** | **không đổi** so với v0.0.1 — bản này không thêm/bớt cấu trúc nào |

Mặt bộ nhớ giữ y nguyên v0.0.1 (đã phân tích ở [`engine_v0.0.1.md §7`](engine_v0.0.1.md)); việc
đặt trần bộ nhớ là một bước riêng của lộ trình ([`todo.md`](todo.md) bước 5 — bounded working-set),
ngoài phạm vi bản này.

---

## 8. Giới hạn / đánh đổi

- **Khớp theo *loại* sự kiện, chưa ràng *thực thể*.** "Ghi X rồi chạy Y khác" vẫn tiến như "ghi X
  rồi chạy đúng X" miễn cùng storyline; partial-order còn nới thêm chiều tự do này. → *Khắc phục:
  bước 2 (bindings) của [`todo.md`](todo.md).*
- **Rule phức tạp hơn** (viết `prereq` thay vì dãy tuần tự) — chấp nhận, trả một lần lúc viết rule.

(Các giới hạn về mặt bộ nhớ đã có ở v0.0.1 vẫn còn nguyên — bản này không giải quyết cũng không làm
xấu đi; chúng thuộc [`todo.md`](todo.md) bước 5.)
