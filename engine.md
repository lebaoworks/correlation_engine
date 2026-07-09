# Lõi phát hiện (Detection Core) — Thuật toán chi tiết

> Phần này đặc tả **thuật toán** của lõi phát hiện trong daemon userland: nhận luồng event
> đã gắn `candidate_ttp` từ kernel, dựng **causality graph (storyline)**, chạy **automata
> matching tăng dần O(1)**, chấm điểm **kill-chain**, và ra **verdict inline** để kernel chặn.
>
> Ràng buộc xuyên suốt: **mỗi event xử lý trong thời gian bounded** (không thao tác NP-hard trên
> đường nóng). Mọi cấu trúc tra cứu là hash/index O(1) amortized.

---

## 0. Ký hiệu & cấu trúc dữ liệu

```
Event e = {
    ts,                     # timestamp đơn điệu tăng
    op,                     # exec|open|read|write|connect|inject|create|delete|load|dup
    actor,                  # {pid, start_ts} — process gây ra hành động (khoá ổn định)
    object,                 # {type, key} — file path / socket / pid đích / registry key ...
    candidate_ttps,         # tập TTP-id kernel đã gợi ý (có thể rỗng)
    attrs                   # entropy, remote_ip, image_hash, access_mask, ...
}

Node n = {
    uid,                    # định danh nội bộ
    type, key,              # process|file|socket|... + khoá tự nhiên
    storyline_id,
    first_seen, last_seen
}

StorylineState S = {
    sid,
    nodes: set<uid>,
    automata: map<pattern_id, AutomatonInstance>,   # các mẫu đang chạy trên storyline này
    ttp_history: ring<{ttp, ts, node}>,             # TTP gần đây (cho window/scoring)
    score,                                          # điểm kill-chain hiện tại
    last_activity
}

AutomatonInstance A = {
    pattern_id,
    completed_mask,         # bitset: bit i = bước i đã thoả (KHÔNG lưu thứ tự — xem §5.2)
    step_ts[],              # thời điểm hoàn thành từng bit (seg_window & order_bonus)
    bound_nodes,            # role -> node đã gắn (kiểm scope + variable binding)
    armed                   # đã đẩy cờ chặn xuống kernel chưa
}
```

Ba chỉ mục toàn cục (đều O(1) tra cứu):
```
NODE_INDEX     : (type, key)      -> uid            # tìm/ tạo node
ACTOR_INDEX    : (pid, start_ts)  -> uid            # node của process theo khoá ổn định
SID_INDEX      : uid              -> sid            # node thuộc storyline nào
PATTERN_TRIGGER: ttp_id           -> set<pattern_id> # TTP nào khởi động/đẩy mẫu nào
```

---

## 1. Vòng lặp chính (per-event pipeline)

```
function ON_EVENT(e):
    # (1) chuẩn hoá & phân giải node
    a_uid = RESOLVE_NODE(e.actor, PROCESS)
    o_uid = RESOLVE_NODE(e.object)

    # (2) hợp nhất storyline theo quan hệ nhân-quả
    sid = UNIFY_STORYLINE(a_uid, o_uid, e.op)

    # (3) gắn cạnh vào causality graph
    ADD_EDGE(sid, a_uid, o_uid, e.op, e.ts)

    # (4) gán TTP đầy đủ (kernel mới chỉ gợi ý)
    ttps = TAG_TTP(e, a_uid, o_uid, sid)

    # (5) đẩy automata + chấm điểm; thu verdict
    verdict = ADVANCE(sid, ttps, e)

    # (6) trả quyết định inline cho kernel
    return DECIDE(verdict, e)
```

Mọi bước (1)–(6) là O(1) amortized theo số automata đang sống trên storyline liên quan (chặn trên
bằng hằng số `MAX_AUTOMATA_PER_SID`, xem §7).

---

## 2. RESOLVE_NODE — phân giải/khởi tạo node

```
function RESOLVE_NODE(ref, type_hint):
    key = NORMALIZE(ref)                  # path chuẩn hoá, (pid,start_ts), (ip,port)...
    uid = NODE_INDEX.get((type, key))
    if uid == null:
        uid = NEW_NODE(type, key)
        NODE_INDEX[(type, key)] = uid
    NODE(uid).last_seen = now
    return uid
```

`start_ts` trong khoá process chống **pid reuse** (pid được cấp lại cho tiến trình khác).

Với **file**, khoá tự nhiên là **identity của file, KHÔNG phải chuỗi path**:
- **Windows**: `(volume_serial, FILE_ID)` — lấy trong minifilter qua `FltGetFileNameInformation`
  / `FILE_ID_INFORMATION`. Path trên Windows nhiều biến thể cho cùng một file (hoa/thường,
  short name 8.3 `PROGRA~1`, prefix `\\?\`, hardlink, junction) và **đổi được bằng rename**;
  FileId sống sót qua rename.
- **Linux**: `(dev, inode)`.

Path chuẩn hoá vẫn lưu trong `attrs` để hiển thị/điều tra, nhưng mọi so sánh node (kể cả
variable binding §5.8) đi qua khoá identity này.

---

## 3. UNIFY_STORYLINE — hợp nhất chuỗi nhân-quả

Mục tiêu: gán cùng `storyline_id` cho các thực thể có quan hệ nhân-quả. Dùng **Union-Find
(DSU)** với path compression → gần O(1).

```
function UNIFY_STORYLINE(a_uid, o_uid, op):
    sa = SID_INDEX.get(a_uid) ?? NEW_STORYLINE(a_uid)

    if IS_CAUSAL(op):                     # exec, inject, write, create, dup...
        so = SID_INDEX.get(o_uid)
        if so == null:
            JOIN(o_uid, sa)               # object kế thừa storyline của actor
        elif so != sa:
            sa = MERGE_STORYLINE(sa, so)  # DSU union + gộp automata/ttp_history
    return sa
```

Quy tắc `IS_CAUSAL` (cạnh nào lan truyền storyline):
- `exec` (parent→child), `inject`, `create process/thread`, `dup/inherit handle` → **có**.
- `write file` → **có** (file trở thành sản phẩm của storyline; nếu sau này bị `exec` thì nối tiếp).
- `read`, `connect`, `open` thuần → **không** tự merge (tránh dependency explosion), chỉ ghi cạnh.

> Đây là chỗ chống **bùng nổ phụ thuộc**: chỉ quan hệ *sản sinh/điều khiển* mới hợp nhất storyline;
> quan hệ *đụng chạm* chỉ để lại cạnh phục vụ scoring/điều tra.

`MERGE_STORYLINE` phải gộp `automata` và `ttp_history` của hai storyline; để tránh chi phí lớn,
giữ storyline nhỏ merge vào lớn (union by size).

---

## 4. TAG_TTP — gán technique đầy đủ

Kernel chỉ gợi ý `candidate_ttps` (lọc rẻ). Userland xác nhận bằng predicate đầy đủ (có ngữ cảnh
graph mà kernel không có).

```
function TAG_TTP(e, a_uid, o_uid, sid):
    result = {}
    for t in e.candidate_ttps ∪ CHEAP_LOOKUP(e.op):
        if TTP_TABLE[t].predicate(e, a_uid, o_uid, GRAPH(sid)):
            result.add(t)
            S(sid).ttp_history.push({t, e.ts, o_uid})
    return result
```

`predicate` là hàm thuần, bounded. Ví dụ:
```
T1486 (data encrypted for impact):
    e.op == write
    AND e.attrs.entropy_delta > θ_entropy
    AND rate(write, actor, 1s) > θ_rate
    AND distinct_dirs(actor, window) > θ_spread

T1003.001 (LSASS memory read):
    e.op == read
    AND e.object.type == process
    AND NODE(o_uid).key.image == "lsass.exe"
    AND (e.attrs.access_mask & PROCESS_VM_READ)

T1490 (inhibit recovery):
    e.op == exec
    AND matches(cmdline, /vssadmin.*delete.*shadows|wbadmin.*delete/)
```

Một predicate có thể **stateful nhẹ** (rate, spread) nhưng phải cập nhật O(1) bằng bộ đếm trượt.

---

## 5. ADVANCE — partial-order matching tăng dần (LÕI)

Đây là trái tim. Thay vì FSM tuyến tính (một `cur_stage` chạy thẳng — giả định thứ tự cứng, và
nếu cố mã hoá "mọi thứ tự" thì **nổ n! đường đi**), ta biểu diễn mỗi mẫu tấn công là một
**thứ tự bộ phận (partial order) = DAG**, và theo dõi tiến độ bằng **bitmask các bước đã hoàn
thành**. Nhờ đó xử lý được thứ tự tự do, xen kẽ, nhóm-trước / nhóm-giữa / nhóm-sau — mà vẫn
**O(1)/event** (thao tác bitwise trên machine word). Không subgraph matching (NP-hard, POIROT).

### 5.1 Định nghĩa mẫu (pattern) — precedence DAG
```
Pattern = {
    id,
    steps: [ Step ],             # mỗi step gắn 1 bit
    required_mask,               # các bit bắt buộc để chấp nhận
    scope,                       # same_storyline | same_actor | free
    block_at,                    # step-id là điểm chặn (enforceable)
}
Step = {
    bit,                         # vị trí bit trong mask
    ttps,                        # OR-slot: bất kỳ TTP nào trong tập này thoả step
    prereq_mask,                 # các bit phải xong TRƯỚC (mã hoá thứ tự bộ phận)
    enforceable,                 # là hành động nghẽn chặn được?
    optional,                   # không nằm trong required_mask
    seg_window                   # deadline cục bộ tính từ khi prereq đủ (§5.6)
}
```

Ba mệnh đề thứ tự đều rơi ra từ `prereq_mask`, **không cần liệt kê hoán vị**:
- **"x phải đầu"** ⟸ mọi step khác có `x` trong `prereq_mask`.
- **"nhóm {b,c,d} tự do thứ tự"** ⟸ chúng không có nhau trong `prereq_mask` của nhau.
- **"mốc M giữa hai nhóm"** ⟸ `prereq_mask[M] = toàn bộ bit nhóm trước`; mỗi phần tử nhóm sau có `prereq_mask = {M}`.

Ghép nhiều mốc ⇒ chuỗi tuỳ ý dài: `G0 → A → G1 → E → G2 → …` (xem ví dụ §5.7).

### 5.2 Trạng thái automaton
```
AutomatonInstance A = {
    pattern_id,
    completed_mask   = 0,        # bit i = step i đã thoả (KHÔNG lưu thứ tự)
    step_ts[]        = {},       # thời điểm hoàn thành từng bit (cho seg_window & order_bonus)
    bound_nodes      = {},       # node đã gắn từng step (kiểm scope + variable binding, §5.8)
    armed            = false
}
```

### 5.3 Thuật toán tiến trạng thái
```
function ADVANCE(sid, ttps, e):
    S = STORYLINE(sid)
    fired = NONE

    for t in ttps:
        # (a) khởi động mẫu: t khớp một step CÓ prereq_mask == 0
        for pid in PATTERN_TRIGGER[t]:
            if not S.automata.has(pid) and matches_root_step(pid, t):
                S.automata[pid] = NEW_AUTOMATON(pid)

        # (b) đẩy các automaton đang sống trên storyline
        for A in S.automata.values():
            for step in steps_matching(A, t):          # step nào có t trong step.ttps (OR-slot)
                bit = step.bit
                if bitset(A.completed_mask, bit):       continue   # đã thoả rồi
                if not PREREQ_OK(A, step):              continue   # thiếu tiền đề → bỏ qua an toàn
                if not SEG_WINDOW_OK(A, step, e):       continue   # quá deadline đoạn (§5.6)
                if not SCOPE_OK(A, e, sid):             continue   # sai scope nhân-quả
                if not BINDING_OK(A, step, e):          continue   # ràng buộc node (§5.8)

                COMMIT_STEP(A, step, e)                 # set bit, ghi step_ts, cập nhật bound_nodes
                S.score = KILL_CHAIN_SCORE(A, S)        # §6
                fired = max(fired, MAYBE_EMIT(A, S, e, step))

    GC_EXPIRED(S, e.ts)
    return fired
```

### 5.4 Các vị từ phụ (đều O(1))
```
PREREQ_OK(A, step):          # đủ tiền đề chưa? — mã hoá thứ tự bộ phận
    return (step.prereq_mask & A.completed_mask) == step.prereq_mask

IS_ACCEPTING(A):             # đủ tập bit bắt buộc, không quan tâm thứ tự đến
    return (A.completed_mask & pattern(A).required_mask) == pattern(A).required_mask

SCOPE_OK(A, e, sid):
    switch pattern(A).scope:
        same_storyline: return sid == A.sid
        same_actor:     return e.actor.uid in A.bound_nodes.values()
        free:           return true
```

`COMMIT_STEP` chỉ là `A.completed_mask |= (1 << step.bit)` + ghi `step_ts[bit]=e.ts` — hằng số.

### 5.5 MAYBE_EMIT — sinh verdict + "armed"
```
function MAYBE_EMIT(A, S, e, step):
    conf = S.score
    at_block = (step.id == pattern(A).block_at) and step.enforceable

    if IS_ACCEPTING(A):
        if conf >= θ_block and at_block:
            return BLOCK(reason=pattern(A).id, node=e.object)   # chặn đúng hành động nghẽn
        if conf >= θ_alert:
            return ALERT(pattern(A).id, storyline=S)
        return SUSPECT(pattern(A).id)

    # chưa đủ tập, nhưng đã đủ điểm + còn 1 hành động enforceable đang chờ → vũ trang kernel
    if conf >= θ_block and not A.armed and has_pending_enforceable(A):
        A.armed = true
        PUSH_KERNEL_ARM(S.sid, action=pattern(A).block_at.op, scope=A.bound_nodes)
        # kernel tự deny khi event enforcing khớp tới, không cần round-trip userland
    return NONE
```

> Điểm mấu chốt giữ nguyên: **chỉ BLOCK khi event hiện tại đúng là bước `block_at` enforceable**
> — chặn hành động nghẽn (mã hoá / đọc LSASS / exfil), không hồi tố. Nếu chuỗi đủ điểm nhưng
> event enforcing chưa tới, ta ở trạng thái **armed** chờ chặn nó ngay trong kernel.

### 5.6 Window theo từng đoạn (không dùng window toàn cục)

Một window toàn cục cho chuỗi dài `G0→A→G1→E→G2` là quá chặt. Thay bằng **deadline cục bộ theo
mốc**: mỗi step có `seg_window` tính từ thời điểm `prereq_mask` của nó vừa đủ.
```
SEG_WINDOW_OK(A, step, e):
    t_enabled = max( A.step_ts[b] for b in bits(step.prereq_mask) )   # mốc mở khoá đoạn này
    return (e.ts - t_enabled) <= step.seg_window
```
Nhờ vậy đoạn đầu có thể cách đoạn cuối rất lâu mà chuỗi vẫn hợp lệ, miễn **mỗi đoạn** diễn ra đủ
nhanh. `GC_EXPIRED` huỷ automaton khi đoạn đang chờ vượt `seg_window` mà không tiến.

### 5.7 Ví dụ: `{P,Q} → A → {B,C,D} → E → {F,G,H}`

Nhóm đầu tự do, mốc A, nhóm giữa tự do, mốc E, nhóm cuối tự do:
```
Bit:  P=0 Q=1   A=2   B=3 C=4 D=5   E=6   F=7 G=8 H=9

prereq[P]=prereq[Q]           = {}          # nhóm đầu: khởi động được, tự do thứ tự
prereq[A]                     = {P,Q}       # mốc: cần cả nhóm đầu
prereq[B]=prereq[C]=prereq[D] = {A}         # nhóm giữa: tự do thứ tự
prereq[E]                     = {B,C,D}     # mốc: cần cả nhóm giữa
prereq[F]=prereq[G]=prereq[H] = {E}         # nhóm cuối: tự do thứ tự
required_mask                 = tất cả bit
block_at                      = E  (hoặc một step ∈ nhóm cuối, tuỳ hành động nghẽn)
```

DAG:
```
P ┐          B ┐          F
  ├─► A ─►   C ┼─► E ─►   G
Q ┘          D ┘          H
```

Trace một thứ tự hợp lệ trong nhiều thứ tự:
```
completed
A  ─ prereq{P,Q} chưa đủ → IGNORE (đến sớm, chuỗi không vỡ)
P  ─ prereq{} ok         → 0000000001
Q  ─ prereq{} ok         → 0000000011
A  ─ prereq{P,Q} ⊆ ok    → 0000000111        # mốc A qua → score nhảy nấc
C  ─ prereq{A} ⊆ ok      → 0000010111        # C trước B,D — hợp lệ
B  ─ prereq{A} ⊆ ok      → 0000011111
E  ─ prereq{B,C,D}? D chưa → IGNORE
D  ─ prereq{A} ⊆ ok      → 0000111111
E  ─ prereq{B,C,D} ⊆ ok  → 0001111111        # mốc E qua → nếu đủ điểm, armed nhóm cuối
F,H,G (bất kỳ thứ tự) ⊆ ok → 1111111111 → ACCEPT
```
"A đến sớm" và "E đến sớm" đều **bị bỏ qua an toàn** (không set bit, không vỡ chuỗi), rồi được
nhận khi tiền đề đủ. Mỗi event chỉ 1 phép AND + 1 phép OR.

### 5.8 Variable binding & giới hạn (khi thứ tự tự do gặp ràng buộc node)

Nếu các step trong một nhóm đòi **cùng ràng buộc vào một node cụ thể** (vd "đọc file F" rồi
"gửi *đúng* F đó ra ngoài") thì phải nhớ node nào điền step nào — đây là chỗ partial-order
matching **tiệm cận subgraph matching**.
```
BINDING_OK(A, step, e):
    for (role, uid) in step.node_constraints(e):     # vd role="file" phải trùng step trước
        if A.bound_nodes.has(role) and A.bound_nodes[role] != uid:
            return false                              # xung đột binding
    return true

COMMIT_STEP cũng ghi: A.bound_nodes[role] = uid
```
Giữ bounded bằng: **neo vào TTP hiếm trước** (cố định binding quanh node hiếm), **`scope=
same_storyline`** (chỉ binding trong một chuỗi nhân-quả), trần số binding sống per-pattern; vượt
trần thì **hạ cấp xuống ALERT** thay vì vét cạn. Binding mơ hồ → **giảm confidence**, không bỏ
cũng không duyệt toàn bộ.

#### Ví dụ chuẩn: dropper "ghi file X → chạy file X"

Đây là ca minh hoạ vì sao binding là **bắt buộc**, không phải tối ưu:

```
Pattern dropper_write_then_exec (trích 2 step):
  step WRITE: op=write, commit: bound_nodes["dropped"] = object.uid
  step EXEC : op=exec,  node_constraint: object.uid == bound_nodes["dropped"]
```

- **Không có binding** (chỉ TTP + `scope=same_storyline`): tiến trình ghi file log X rồi khởi
  chạy app Y không liên quan vẫn set đủ 2 bit → **false positive**. `completed_mask` chỉ nhớ
  *step nào đã xảy ra*, không nhớ *trên node nào*.
- **Có binding**: exec Y → `BINDING_OK` false → bit không set; chỉ exec đúng X mới tiến. Chi phí
  vẫn O(1) (một phép so sánh uid).

Hai quy tắc đi kèm để binding không phản tác dụng:

1. **Bind theo identity, không theo path** (§2). Kẻ tấn công ghi X rồi `rename X→Y` rồi chạy Y:
   bind theo path → **false negative**; bind theo FileId/(dev,inode) → rename vô hiệu. Trường hợp
   *copy* X→Y sinh FileId mới — xử lý bằng cạnh causal `create/copy` lan truyền trong storyline
   (§3), không hash nội dung trên đường nóng.
2. **Match đúng ≠ đáng chặn.** "Ghi X rồi chạy đúng X" là hành vi lành tính cực phổ biến
   (installer, self-updater, package manager, build system chạy binary vừa compile). Mẫu 2 bước
   này một mình chỉ đáng `SUSPECT`; nó nên là *một đoạn* trong DAG dài hơn, và cần scoring §6
   kéo lên (file unsigned/chưa từng thấy → rarity; actor là process mặt-mạng browser/Office;
   ghi vào thư mục temp/ADS) mới chạm `θ_alert`/`θ_block`. Đúng triết lý chung: đơn lẻ → cảnh
   báo, chuỗi phủ nhiều tactic → mới chặn.

> Ranh giới cần nhớ: **độ phức tạp thứ tự (DAG bao nhiêu tầng, nhóm lồng, AND/OR) là miễn phí**;
> thứ *thật sự* đắt là variable binding + thứ tự tự do đồng thời. Nếu số step > 64, dùng bitset
> nhiều word → O(#step/64), thực tế vẫn coi như hằng số.

---

## 6. KILL_CHAIN_SCORE — chấm điểm (tư duy HOLMES + RapSheet)

```
function KILL_CHAIN_SCORE(A, S):
    completed = bits(A.completed_mask)
    stages = distinct_tactics(completed)             # số giai đoạn kill-chain đã phủ
    sev    = Σ severity(bit) over completed
    order_bonus = β * ORDER_OBSERVED(A)              # thứ tự là THƯỞNG, không phải điều kiện
    rarity = Σ rarity(ttp) over completed            # neo signal hiếm (RapSheet/POIROT)
    return w1*stages + w2*sev + w3*order_bonus + w4*rarity

ORDER_OBSERVED(A):
    # tỉ lệ cặp bước đã đến ĐÚNG chiều thời gian so với gợi ý kill-chain
    # dùng step_ts[]; partial-order vẫn accept dù sai thứ tự, chỉ mất phần thưởng này
    return fraction_of_pairs_in_expected_temporal_order(A.step_ts)
```

Trọng số hiệu chỉnh sao cho **một mình severity không đủ chặn** — phải phủ nhiều giai đoạn kill-chain
thì mới vượt `θ_block`. Nhờ vậy hành vi lẻ (đơn TTP) chỉ cảnh báo, chuỗi APT mới bị chặn.

Với mẫu **partial-order**, thứ tự chỉ là **thưởng** (`order_bonus`), không phải điều kiện chấp
nhận — nên đặt `θ_block` cao hơn một chút so với mẫu có thứ tự chặt để bù phần bằng chứng thời
gian bị mất khi cho phép thứ tự tự do.

`rarity(ttp)`: nghịch đảo tần suất quan sát trong baseline → TTP hiếm kéo điểm lên nhanh, giúp
neo vào node/hành vi bất thường và thu hẹp vùng đánh giá.

---

## 7. Chống dependency explosion & giới hạn tài nguyên

| Cơ chế | Hiệu quả |
|---|---|
| Chỉ cạnh **causal** mới merge storyline (§3) | Chặn nổ storyline khổng lồ |
| `MAX_AUTOMATA_PER_SID`, `MAX_NODES_PER_SID` | Trần chi phí per-event |
| **Deadline theo đoạn** (`seg_window`, §5.6) + `GC_EXPIRED` | Trạng thái không phình vô hạn |
| Edge coalescing (gộp write lặp cùng (actor,object)) | Giảm cạnh trùng |
| Neo vào TTP hiếm trước khi mở rộng | Giảm vùng phải xét |
| Automaton quá `seg_window` mà không tiến → huỷ ngay | Giải phóng bộ nhớ liên tục |
| Bitmask ≤ 64 bước / 1 word (đa word nếu hơn) | Tiến trạng thái O(1) |

Khi vượt trần: áp dụng **eviction** LRU theo `last_activity` cho storyline nguội, nhưng **không
evict** storyline đang có automaton ≥ `θ_alert` (đang trong chuỗi tấn công).

> ⚠️ LRU thuần là **bẫy** (giết chuỗi lén lút + mở đòn evict-as-evasion). Chiến lược bound bộ nhớ
> mà vẫn bắt tối đa — tách detection-state/forensic-graph, giữ-theo-nghi-ngờ, ngân sách theo nguồn,
> sketch xác suất, spill đĩa, admission theo rarity — xem **`engine_state_optimization.md`**.

---

## 8. DECIDE — biên với kernel (đường inline)

```
function DECIDE(verdict, e):
    switch verdict.kind:
        BLOCK:   return DENY            # kernel trả -EPERM / chặn I/O
        ALERT:   log(verdict); return ALLOW
        SUSPECT: return ALLOW
        NONE:    return ALLOW
```

- **Fail-open**: nếu daemon quá tải/không phản hồi trong `T_budget`, kernel **allow** (ưu tiên ổn
  định). Trạng thái "armed" đã đẩy sẵn xuống kernel giúp vẫn chặn được điểm nghẽn dù userland chậm.
- **Latency budget**: đường single-event nguy hiểm (LSASS, vssadmin) được chặn **thẳng trong
  kernel** bằng bảng rule tĩnh, không đợi §1–§6.

### 8.1 Điểm hook theo `op` — Windows (ưu tiên thử nghiệm trước) & Linux

Chọn hook phải theo tiêu chí **deny được đồng bộ** (làm `enforceable`/`block_at`), không chỉ notify:

| `op` | Windows — sensor & enforcement | Deny? | Linux |
|---|---|---|---|
| `write`/`create`/`delete` file | Minifilter pre-op (`IRP_MJ_CREATE`, `IRP_MJ_WRITE`, `IRP_MJ_SET_INFORMATION`) | **Có** — `FLT_PREOP_COMPLETE` + `STATUS_ACCESS_DENIED` | `bpf_lsm` (`file_open`, `inode_*`) |
| `exec` process | `PsSetCreateProcessNotifyRoutineEx` | **Có** — set `CreationStatus = STATUS_ACCESS_DENIED` | `bpf_lsm` (`bprm_check_security`) |
| `open`/`read` process (LSASS) | `ObRegisterCallbacks` (pre-op handle) | **Có** — strip `PROCESS_VM_READ` khỏi access mask | `bpf_lsm` (`ptrace_access_check`) |
| `inject` (remote thread) | `PsSetCreateThreadNotifyRoutine` chỉ **notify** → chặn từ gốc bằng `ObRegisterCallbacks` (strip `PROCESS_CREATE_THREAD`/`VM_WRITE` khi mở handle) | Gián tiếp | `bpf_lsm` (`ptrace`, `bpf`) |
| `load` module/image | `PsSetLoadImageNotifyRoutine` chỉ **notify** → chặn qua minifilter tại section-map (`IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION`) | Gián tiếp | `bpf_lsm` (`bprm`, `kernel_read_file`) |
| registry (persistence) | `CmRegisterCallbackEx` (pre-op) | **Có** | — (tương đương: file config) |
| `connect` | WFP callout (ALE layers) | **Có** | `bpf_lsm`/cgroup hook (`socket_connect`) |

Hai điểm khớp với mô hình armed (§5.5):

- **Rename/exec khép kín trong kernel:** `PsSetCreateProcessNotifyRoutineEx` cho FileObject của
  image → lấy được **FileId** ngay tại chỗ để so với cờ armed (bind theo identity, §2/§5.8) —
  không cần round-trip userland đúng như PUSH_KERNEL_ARM yêu cầu.
- **"eBPF map" phía Windows** = bảng hash trong driver (nonpaged, khoá `(sid | FileId | pid)`),
  daemon cập nhật qua IOCTL/FilterSendMessage; ngữ nghĩa giống `BPF_MAP_TYPE_HASH` chiều xuống.

---

## 9. Độ phức tạp

| Bước | Chi phí |
|---|---|
| RESOLVE_NODE | O(1) hash |
| UNIFY_STORYLINE | ~O(α) — DSU path compression |
| TAG_TTP | O(#candidate_ttps) — hằng số nhỏ |
| ADVANCE | O(#automata liên quan) ≤ `MAX_AUTOMATA_PER_SID` |
| KILL_CHAIN_SCORE | O(độ dài mẫu) — hằng số |
| **Tổng / event** | **O(1) amortized** |

Không có bước nào phụ thuộc kích thước toàn graph → phù hợp streaming inline. (Trái ngược POIROT:
subgraph isomorphism theo kích thước graph, NP-hard.)

---

## 10. Ví dụ chạy đầu-cuối (ransomware)

Mẫu có nhóm giữa **tự do thứ tự** `{T1490 inhibit recovery, T1083 file discovery}` — cả hai có
thể xảy ra trước/sau nhau — kẹp giữa mốc đầu `T1059 (exec script)` và mốc chặn `T1486 (encrypt)`:
```
Pattern ransomware_fast_encrypt:
  scope: same_storyline, block_at: T1486
  bit:  T1059=0   T1490=1  T1083=2   T1486=3
  prereq[T1059]              = {}                 # mốc đầu
  prereq[T1490]=prereq[T1083]= {T1059}            # nhóm giữa: tự do thứ tự
  prereq[T1486]              = {T1490, T1083}     # mốc chặn: cần cả nhóm giữa
  required_mask              = {T1059,T1490,T1083,T1486}
  T1490, T1486: enforceable ; seg_window mỗi đoạn = 60s

1. exec powershell        → RESOLVE, storyline S1, TAG T1059
                            prereq{} ok → NEW_AUTOMATON, completed=0001
2. read nhiều thư mục     → TAG T1083, prereq{T1059} ⊆ ok → completed=0101   # nhóm giữa (thứ tự A)
3. exec vssadmin delete   → TAG T1490, prereq{T1059} ⊆ ok → completed=0111   # nhóm giữa (thứ tự B)
                            score ≥ θ_block, còn pending T1486 enforceable
                            → A.armed=true; PUSH_KERNEL_ARM(S1, action=write) # vũ trang
4. write *.docx entropy↑  → predicate T1486 đúng, prereq{T1490,T1083} ⊆ ok
                            kernel thấy S1 đã "armed" cho write
                            → DENY ngay trong kernel (chặn ghi mã hoá đầu tiên)
                          → completed=1111 ACCEPT → EMIT: BLOCK, dựng storyline graph cho SOC
```
Bước 2 và 3 có thể đảo chiều (T1490 trước T1083) mà kết quả không đổi — đó là nhóm tự do thứ tự.

Kết quả: chuỗi bị chặn **đúng tại hành động mã hoá đầu tiên**, không cần chờ userland round-trip,
không hồi tố, và có graph đầy đủ để điều tra.

---

## 11. Schema RULE — cách viết mẫu (file `rules/*.rules`)

Bộ rule **tách rời khỏi code**, nạp lúc chạy (thêm/sửa mẫu không build lại). Định dạng dòng-lệnh,
zero-dependency (parser ở `engine/src/rules.rs`). Mỗi dòng là một **directive**; `#` là chú thích;
dòng trống bỏ qua. Có 4 directive: `ttp`, `tagger`, `pattern`, `step`.

### 11.1 `ttp` — metadata cho scoring (§6)
```
ttp <ID> tactic=<tactic> severity=<0..10> rarity=<0..1>
```
- `tactic` ∈ `execution | discovery | defense_evasion | credential_access | impact | staging`.
- `severity` mức độ độc; `rarity` = nghịch đảo tần suất baseline (hiếm → kéo điểm nhanh, neo signal).
- TTP không khai báo → mặc định `staging, severity=1, rarity=0.15`.

### 11.2 `tagger` — luật gán TTP từ 1 event (§4)
```
tagger <ID> <cond> <cond> ...
```
Phát ra `<ID>` khi **mọi** `<cond>` đúng. Tập điều kiện là **closed-set** (không phải ngôn ngữ
biểu thức) — đủ diễn đạt technique mà vẫn bounded/auditable:

| cond | ý nghĩa |
|---|---|
| `op=a\|b\|c` | `e.op` thuộc tập (phân tách bằng `\|`) |
| `image_base_in=a.exe,b.exe` | basename(`attrs.image`) thuộc tập (so sánh lowercase) |
| `target_image_base=x.exe` | basename(`attrs.target_image`) thuộc tập |
| `attr_true=<k>` | `attrs[k]` ∈ {`1`,`true`} |
| `entropy_gt=<f>` | `attrs.entropy` > f |
| `write_rate_ge=<n>` | ≥ n lần write của cùng actor trong cửa sổ trượt 1s |
| `dir_spread_ge=<n>` | write chạm ≥ n thư mục (`attrs.dir`) trong cửa sổ 1s |
| `cmd_recovery_inhibit` | builtin: `attrs.cmd` khớp mẫu xoá shadow/catalog/resize shadowstorage |

> `write_rate_ge`/`dir_spread_ge` là **stateful nhẹ**: mọi event `op=write` tự động cộng vào bộ đếm
> trượt của actor (dùng `attrs.dir`), cập nhật O(1). Thêm một *dạng* cond mới vẫn cần sửa code — đúng
> chủ đích, vì tagger là lớp platform-specific (§8.1); pattern thì hoàn toàn data-driven.

### 11.3 `pattern` + `step` — mẫu tương quan = precedence DAG (§5)
```
pattern <NAME> scope=<scope> theta_alert=<f> theta_block=<f> [root_gate=<gate>]
  step <NAME> bit=<n> match=<matcher> [prereq=<n,n>] seg_window=<ms> [enforceable] [optional] [block] [bind=<role>:<src>]
  step ...
```
Các dòng `step` gắn vào `pattern` gần nhất phía trên.

**Trường của `pattern`:**
- `scope` ∈ `same_storyline | same_actor | free` — phạm vi nhân-quả các step phải cùng (§5.4).
- `theta_alert` / `theta_block` — ngưỡng cảnh báo / chặn (§6). Mẫu partial-order nên đặt `theta_block`
  cao hơn để bù phần bằng chứng thứ tự bị mất.
- `root_gate` ∈ `always | pe_write` (mặc định `always`) — cổng khởi tạo automaton, giữ số automaton
  bounded (§7). `pe_write` = chỉ event ghi file thực thi (`attrs.pe=1`) mới seed (dùng cho dropper).

**Trường của `step`:**
- `bit=<n>` — vị trí bit trong `completed_mask` (0..63). Mỗi step một bit.
- `match=` — điều kiện khớp step:
  - `ttp:<ID>` — khớp khi event được gán TTP đó.
  - `ttp_any:A|B|C` — **OR-slot**: bất kỳ TTP nào trong tập (biến thể công cụ, §5.1).
  - `op:<op>` — khớp theo raw op (step cấu trúc, không cần TTP).
- `prereq=<n,n>` — các bit phải xong **trước** (mã hoá thứ tự bộ phận). Bỏ trống ⇒ **step gốc** (khởi
  động được). "x phải đầu", "nhóm tự do", "mốc giữa" đều rơi ra từ `prereq` (§5.1).
- `seg_window=<ms>` — deadline cục bộ tính từ khi `prereq` vừa đủ (§5.6). Chuỗi dài không bị siết bởi
  một window toàn cục.
- `enforceable` (cờ) — step là điểm nghẽn chặn đồng bộ được (§8.1).
- `optional` (cờ) — không nằm trong `required_mask` (không bắt buộc để ACCEPT).
- `block` (cờ) — đánh dấu `block_at`: điểm engine ra verdict BLOCK / vũ trang kernel.
- `bind=<role>:<src>` — ràng buộc biến (§5.8). `src` ∈ `object | image | actor`. Cùng `role` ở nhiều
  step phải phân giải về **cùng một node identity**; xung đột ⇒ step không khớp. Đây là thứ phân biệt
  "ghi X rồi chạy X" với "ghi X rồi chạy Y".

`required_mask` = OR các bit **không** `optional`. ACCEPT ⟺ `(completed_mask & required_mask) ==
required_mask` (§5.4).

### 11.4 Ví dụ đầy đủ (dropper + ransomware, trích `rules/builtin.rules`)
```
ttp T1059 tactic=execution       severity=3 rarity=0.10
ttp T1490 tactic=defense_evasion severity=7 rarity=0.80
ttp T1486 tactic=impact          severity=9 rarity=0.90

tagger T1059 op=exec image_base_in=powershell.exe,cmd.exe,wscript.exe,mshta.exe
tagger T1490 op=exec image_base_in=vssadmin.exe,wbadmin.exe,bcdedit.exe cmd_recovery_inhibit
tagger T1486 op=write entropy_gt=0.85 write_rate_ge=3 dir_spread_ge=2

# dropper: ghi X -> chạy X (binding theo identity). Tự thân chỉ SUSPECT.
pattern dropper_write_then_exec scope=same_storyline theta_alert=6 theta_block=12 root_gate=pe_write
  step write_executable bit=0 match=op:write prereq=  seg_window=300000             bind=dropped:object
  step exec_dropped     bit=1 match=op:exec  prereq=0 seg_window=300000 enforceable bind=dropped:image block

# ransomware: T1059 -> {T1490, T1083} (nhóm giữa tự do) -> T1486
pattern ransomware_fast_encrypt scope=same_storyline theta_alert=6 theta_block=12
  step T1059 bit=0 match=ttp:T1059 prereq=    seg_window=120000
  step T1490 bit=1 match=ttp:T1490 prereq=0   seg_window=120000 enforceable
  step T1083 bit=2 match=ttp:T1083 prereq=0   seg_window=120000
  step T1486 bit=3 match=ttp:T1486 prereq=1,2 seg_window=120000 enforceable block
```

---

## 12. Schema DATASET — cách viết telemetry thử nghiệm (file `datasets/*.evt`)

Dataset mô phỏng luồng event đã chuẩn hoá đưa vào lõi (thay cho sensor kernel), dùng để replay
audit-mode và test. Một event mỗi dòng, các cặp `key=value` cách nhau bằng khoảng trắng; value chứa
dấu cách thì bọc `"..."`; `#` là chú thích (parser ở `engine/src/dataset.rs`).

### 12.1 Khoá cấu trúc (5 khoá đặc biệt) + attrs
| key | bắt buộc | ý nghĩa | định dạng |
|---|---|---|---|
| `ts` | có | timestamp ms, **đơn điệu tăng** | số nguyên |
| `op` | có | loại thao tác | `exec\|open\|read\|write\|connect\|inject\|create\|delete\|load\|dup` |
| `actor` | có | process gây hành động (luôn là process) | `<pid>.<start_ts>` |
| `object` | có | đối tượng bị tác động | `proc:<pid>.<start>` \| `file:<FileId>` \| `sock:<key>` \| `<kind>:<key>` |
| `image` | tùy | (exec) FileId của ảnh thực thi | token file (dùng cho `image_base_in` & `bind=…:image`) |
| *khác* | tùy | thuộc tính → `attrs` | `entropy=0.96`, `cmd="..."`, `enum=1`, `pe=1`, `dir=...`, `vm_read=1`, `target_image=...` |

Quy ước quan trọng:
- **Process key = `pid.start_ts`** chống pid-reuse (§2): `200.5` và `200.9` là hai node khác nhau.
- **`file:<FileId>`** — token đóng vai **FileId trừu tượng**: hai event dùng **cùng token** ⇒ **cùng
  một file identity** (rename giữ nguyên token; copy đổi token). Đây là cách dataset mô phỏng binding
  theo identity (§5.8) thay vì theo path.
- **`op` causal** (`exec/inject/create/dup/write`) hợp nhất storyline actor↔object (§3); `read/open/
  connect` chỉ ghi cạnh, không merge.
- Ở `exec`: `object` = **process con** (cho spawn/storyline), `image` = **file ảnh** (cho tagging &
  binding). Một callback process-create thật cung cấp cả hai.

### 12.2 attrs mà các tagger builtin cần
| attr | tagger dùng | ví dụ |
|---|---|---|
| `image` | T1059/T1490 (`image_base_in`), binding image | `image=C:\...\powershell.exe` |
| `cmd` | T1490 (`cmd_recovery_inhibit`) | `cmd="delete shadows /all /quiet"` |
| `enum` | T1083 (`attr_true=enum`) | `enum=1` |
| `entropy`,`dir` | T1486 (`entropy_gt`,`dir_spread_ge`) | `entropy=0.96 dir=C:\Users\a\Documents` |
| `target_image`,`vm_read` | T1003 (`target_image_base`,`attr_true=vm_read`) | `target_image=C:\...\lsass.exe vm_read=1` |
| `pe` | `root_gate=pe_write` | `pe=1` (file thực thi) |

### 12.3 Ví dụ (trích `datasets/ransomware.evt`)
```
ts=1000 op=exec  actor=100.1 object=proc:200.5  image=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe cmd="-enc SQBFAFgA"
ts=1500 op=open  actor=200.5 object=file:DIR_documents enum=1
ts=2000 op=exec  actor=200.5 object=proc:300.10 image=C:\Windows\System32\vssadmin.exe cmd="delete shadows /all /quiet"
ts=2500 op=write actor=200.5 object=file:DOC1 dir=C:\Users\a\Documents entropy=0.96 pe=0
```
→ exec powershell (T1059, seed automaton) → open enum (T1083) → exec vssadmin (T1490, ARM) → write
entropy cao (bị DENY do storyline đã armed). Xem `engine/README.md` cho bảng dataset & kết quả kỳ vọng.

### 12.4 Chạy
```
cargo run --bin edr-replay -- datasets/<x>.evt [rules/<y>.rules]   # audit-mode; rule tùy chọn
cargo test                                                         # test hành vi
```

---

## 13. Giới hạn hiện tại

Ghi lại trung thực các giới hạn của bản hiện tại để không nhầm "chạy trên dữ liệu giả" với "dùng
được trên endpoint thật". Chia hai nhóm: **(A) khoảng cách prototype ↔ thiết kế** (thiết kế có, code
chưa làm) và **(B) giới hạn mô hình & đối kháng** (thuộc bản chất, cần nghiên cứu thêm).

> Ngoài phạm vi mục này: phần **sensor kernel** và **đường enforcement thật** (chặn đồng bộ trong
> kernel, ngân sách latency, fail-open) — được coi là hạng mục kiến trúc riêng, không liệt kê ở đây.

### 13.1 (A) Khoảng cách prototype ↔ thiết kế

- **Không có GC / eviction / trần tài nguyên.** §7 mô tả `GC_EXPIRED`, `MAX_AUTOMATA_PER_SID`,
  `MAX_NODES_PER_SID`, eviction LRU — code **chưa** implement cái nào. Automaton không bị xoá sau
  accept/block hay khi quá `seg_window` (seg_window chỉ chặn *commit* bước muộn, không giải phóng
  automaton); storyline chỉ bị xoá khi merge. ⟹ chạy dài trên luồng event thật → **phình bộ nhớ vô
  hạn / OOM**. Đây là khoảng cách rõ nhất.
- **`completed_mask` là `u64` → tối đa 64 bước/mẫu.** Đa-word (§5.8) chưa làm; mẫu > 64 bước không
  biểu diễn được.
- **Chưa có trần binding / hạ cấp ALERT.** §5.8 yêu cầu giới hạn số binding sống và hạ cấp thay vì
  vét cạn khi vượt trần — code chưa có, nên góc "binding + thứ tự tự do" (tiệm cận subgraph matching)
  hiện **không có phanh**.
- **Không lưu trạng thái bền (persistence).** Toàn bộ graph/automata ở in-memory, mất khi restart →
  tấn công kéo dài qua reboot bị mất storyline. Chưa có snapshot.
- **Độ phủ luật mỏng.** Chỉ 5 tagger (T1059/T1083/T1490/T1486/T1003) và 3 mẫu demo; thực tế cần hàng
  trăm. Tagger là logic **Windows hardcode** trong `rules.rs`; nhánh Linux mới ở mức thiết kế (chưa
  tách `platform/windows` · `platform/linux`).
- **Identity/FileId chưa xử lý thật.** Prototype dùng token chuỗi trừu tượng; chưa implement FileId
  128-bit + VolumeGuid + sequence, chưa vô hiệu node khi `delete`, chưa chống MFT-reuse / đụng độ
  volume-serial, chưa degrade trên FAT/exFAT/mạng (xem §2). Binding hiện chỉ an toàn *trong mô phỏng*.
- **Kiểm thử/benchmark hạn chế.** Mới 4 test hành vi trên dữ liệu tự chế; **chưa** chạy DARPA TC,
  chưa red-team, chưa đo hiệu năng thật (throughput/latency dưới tải event thực). "O(1)" là phân
  tích, chưa có số đo.

### 13.2 (B) Giới hạn mô hình & đối kháng

- **Phát hiện phụ thuộc chuỗi phải chạm một bước "arm được" trước khi gây hại.** Ví dụ: ransomware
  đi thẳng `T1059 → T1486` (bỏ discovery và xoá shadow) thì mẫu không đủ nhóm giữa → **không arm,
  không chặn**. Kể cả khi có, predicate T1486 cần 3 write/2 thư mục → **ít nhất 2 file đã mã hoá**
  trước khi tagger bật; chỉ cơ chế arm (từ T1490) mới cứu được file đầu tiên.
- **Storyline vỡ là mất tất cả.** Mô hình nhân-quả hiện đơn giản (exec cha-con, write file). Windows
  có nhiều kênh nhân-quả ngầm — WMI, COM/ALPC, scheduled task, service creation, kế thừa
  token/handle — **chưa mô hình hoá**. Kẻ tấn công sinh tiến trình qua WMI để cắt quan hệ cha-con
  ⟹ chuỗi bị chia nhỏ, correlation thất bại.
- **Tagger nhận diện theo tên file — giòn.** Copy `powershell.exe` → `a.exe` rồi chạy: basename
  không khớp tập → **T1059 trượt → cả mẫu không seed**. Cần khoá theo chữ ký / `OriginalFilename` /
  hash thay vì tên.
- **Scoring chưa hiệu chỉnh.** Trọng số `w1..w4`, ngưỡng `θ`, bảng severity/rarity là **số chỉnh tay
  cho demo**; `rarity` tĩnh, không đo từ baseline thật. Chưa có audit-only đo tỉ lệ false-positive —
  mà với prevention, **FP = chặn nhầm phần mềm hợp lệ**, là lỗi đắt nhất.
- **Né bằng mimicry / chuỗi im lặng / chậm dưới window.** Làm chuỗi độc trông như installer
  ("ghi X chạy X") để ở mức SUSPECT; tránh TTP hiếm/ồn để không đủ điểm arm; kéo giãn từng đoạn để
  không đoạn nào vượt `seg_window`.
- **Chỉ trên một host.** Không correlate xuyên host (lateral movement) inline — phải đẩy lên backend.
- **Không tự bảo vệ (self-protection).** Chưa chống kẻ tấn công đủ quyền tắt agent, gỡ driver, hay
  **sửa file rule** (`rules/*.rules` là plaintext, không ký/không bảo vệ toàn vẹn).

> Ưu tiên thu hẹp: (1) implement GC + trần tài nguyên (§13.1) để không OOM; (2) tagger theo chữ
> ký/hash + mở rộng độ phủ; (3) chế độ audit-only + đo FP trên telemetry thật để hiệu chỉnh ngưỡng;
> (4) mô hình thêm kênh nhân-quả ngầm (WMI/COM/service) để storyline không dễ vỡ.
