# Engine — thuật toán ban đầu (base)

> Bản phác thảo đầu tiên của lõi phát hiện: ý tưởng cốt lõi là dựng một **provenance graph**
> theo thời gian thực, nhóm các thực thể liên thông thành **storyline**, và chạy một
> **automaton** cho mỗi mẫu tấn công trong mỗi storyline để khớp chuỗi sự kiện. Tài liệu này chỉ
> mô tả thuật toán ở dạng nguyên bản — không có code tương ứng.

---

## 0. Bài toán

Input là một luồng event thô, vô hạn theo thời gian: process tạo process con, ghi file, đọc
file, mở kết nối mạng, inject… Một cuộc tấn công không nằm gọn trong một event — nó là **một
chuỗi event liên quan nhân-quả với nhau** trải dài qua thời gian (ví dụ: LOLBin spawn → ghi
payload → tắt Volume Shadow Copy → mã hoá hàng loạt file). Mục tiêu: nhận ra một chuỗi như vậy
đang hình thành, càng sớm càng tốt, từ chính luồng event đang chạy — không phải phân tích offline
sau khi đã có toàn bộ log.

Hai việc phải làm cho mọi event tới:

1. **Biết event này thuộc "câu chuyện" nào** — tức thực thể (process/file/socket) nó động vào
   có liên quan nhân-quả gì tới các event trước đó không.
2. **Biết câu chuyện đó đã tiến tới đâu** trong các mẫu tấn công đã biết — event này có phải là
   bước kế tiếp của một pattern đang khớp dở không.

---

## 1. Ý tưởng cốt lõi

> **Dựng một đồ thị provenance sống theo thời gian thực; nhóm các thực thể liên thông với nhau
> thành "storyline"; chạy song song cho mỗi storyline, một automaton cho mỗi mẫu tấn công đã
> biết — automaton tiến một bước mỗi khi thấy đúng sự kiện kế tiếp trong mẫu.**

Engine giữ mọi node, mọi cạnh, mọi automaton, từ lúc khởi động, không bao giờ xoá. Một tiến trình
duy nhất vừa nhận event, vừa dựng graph, vừa chạy automaton, vừa ra verdict

---

## 2. Cấu trúc dữ liệu

```
# ---- node của provenance graph — sống mãi, không bao giờ bị gỡ ----
Node n = {
    key,        # định danh ổn định: (pid, start_ts) cho process, FileId cho file, ...
    kind,       # process | file | socket | ...
    line        # con trỏ tới Storyline hiện hành (null nếu chưa thuộc chuỗi nào)
}

# ---- cạnh — mỗi event sinh đúng một cạnh, lưu vĩnh viễn ----
Edge g = { from: key, to: key, op, ts }

# ---- provenance graph toàn cục ----
GRAPH = { nodes: map<key, Node>, edges: list<Edge> }

# ---- op bị tước quyền theo từng actor — hiệu lực TỪ THỜI ĐIỂM bị disarm, mãi mãi ----
DISARMED = map<actor_key, set<Op>>

# ---- storyline = thành phần liên thông của graph ----
Storyline S = {
    members: set<key>,
    automata: map<pattern_id, list<Automaton>>,  # có thể nhiều instance cùng pattern
    last_activity
}

# ---- automaton: tiến độ khớp một pattern, TUYẾN TÍNH ----
Automaton A = {
    pattern_id,
    stage,          # chỉ số bước đã khớp — 0..len(steps), tăng dần 1-1
    stage_ts,       # thời điểm khớp bước gần nhất
}
```

`stage` là một số nguyên tăng dần theo thứ tự bước trong mẫu; automaton không giữ ràng buộc
identity nào giữa các bước (`bound_ids`) — chỉ cần đúng *loại* sự kiện ở đúng vị trí.

**Pattern** là một dãy bước có thứ tự cố định; mỗi bước tự mang sẵn **phản ứng** của riêng nó,
không có severity/threshold gộp chung:

```
Pattern = { id, steps: [ Step_1, Step_2, ..., Step_k ] }
Step    = { match, action }
```

`match` là điều kiện khớp trên `(op, ttp)` của event — mỗi bước phải khớp đúng theo thứ tự viết
trong mẫu. `action` là **phản ứng mong muốn** khi automaton vừa tiến tới bước đó — không phải mô
tả bước, mà là việc cần làm ngay, một trong bốn:

- `ignore` — không hành động.
- `inspect` — chỉ ghi nhận.
- `block` — chặn đúng hành vi vừa xảy ra ở event này (không hồi tố, không ảnh hưởng event khác).
- `disarm(ops)` — chặn hành vi vừa xảy ra ở event này **và** thêm `ops` (tập `Op`) vào
  `DISARMED[e.actor]`: từ thời điểm này, actor đó **không thể thực hiện** bất kỳ op nào trong
  `ops` nữa — mọi event sau của actor này mang một op thuộc `ops` đều bị `block` ngay, không cần
  khớp thêm bước nào của pattern nào.

---

## 3. Vòng lặp chính (per-event)

```
function ON_EVENT(e):
    if e.op in DISARMED.get(e.actor, {}):  # actor này đã bị tước quyền làm op này từ trước
        return block                       # chặn thẳng — không cần chạm graph/automaton

    a = RESOLVE_NODE(e.actor)              # get-or-create trong GRAPH.nodes
    o = RESOLVE_NODE(e.object)

    GRAPH.edges.append({from: a.key, to: o.key, op: e.op, ts: e.ts})

    S = UNIFY_STORYLINE(a, o)              # gộp theo liên thông đồ thị (§4)

    ttps = TAG_TTP(e)                      # gán technique cho event thô

    return ADVANCE(S, ttps, e)             # tiến automaton tuyến tính, trả verdict (§5)
                                            # ignore | inspect | block | disarm
```

Kiểm tra `DISARMED` đứng **trước** mọi bước khác: một op đã bị tước quyền thì event mang op đó
không bao giờ tới được graph/storyline/automaton — hệt như hành vi bị chặn thật ở tầng dưới (ví
dụ một lệnh `write` bị từ chối thì file đối tượng chưa từng tồn tại, nên chẳng có gì để ghi vào
provenance graph).

---

## 4. UNIFY_STORYLINE — gộp theo liên thông đồ thị

Storyline là **thành phần liên thông** của provenance graph, dựng bằng union-find (DSU) toàn
cục:

```
function UNIFY_STORYLINE(a, o):
    Sa = a.line ?? NEW_STORYLINE(a)
    So = o.line ?? NEW_STORYLINE(o)
    if Sa != So:
        MERGE(Sa, So)
    return find(a)
```

Mọi cạnh — bất kể loại `op` — đều gộp storyline.

---

## 5. ADVANCE — automaton tuyến tính, verdict theo từng bước

Không có severity/threshold gộp toàn automaton. Mỗi bước tự mang sẵn `action` của nó (§2); verdict
của một event là **phản ứng mạnh nhất** trong số các bước vừa được kích hoạt (seed hoặc tiến) tại
đúng event đó, theo thang: `ignore < inspect < block < disarm`.

```
function APPLY(step, e):
    if step.action is disarm(ops):
        DISARMED[e.actor] = DISARMED.get(e.actor, {}) | ops   # tước quyền TỪ BÂY GIỜ, vĩnh viễn
        return disarm
    return step.action                                        # ignore | inspect | block

function ADVANCE(S, ttps, e):
    verdict = ignore

    # (a) seed: mẫu nào có bước đầu khớp e thì tạo một automaton mới trong S
    for pid in ALL_PATTERNS:
        if PATTERN[pid].steps[0] matches (e, ttps):
            S.automata[pid].append({ pattern_id: pid, stage: 1, stage_ts: e.ts })
            verdict = max(verdict, APPLY(PATTERN[pid].steps[0], e))

    # (b) tiến mọi automaton đang có trong S theo ĐÚNG bước kế tiếp
    for pid in S.automata:
        P = PATTERN[pid]
        for A in S.automata[pid]:
            if A.stage < len(P.steps) and P.steps[A.stage] matches (e, ttps):
                verdict = max(verdict, APPLY(P.steps[A.stage], e))
                A.stage += 1
                A.stage_ts = e.ts

    return verdict            # ignore | inspect | block | disarm
```

Verdict là **thuộc tính của event hiện tại**, không phải trạng thái ghim lại: một event chỉ có
verdict khác `ignore` nếu chính nó vừa làm một automaton seed hoặc tiến bước (hoặc vừa chạm
`DISARMED` từ một `disarm` trước đó — §3). Automaton đã ở `stage == len(steps)` không còn điều
kiện nào trong (b) khớp được nữa (`A.stage < len(P.steps)` sai) — nên các event sau, dù vẫn thuộc
cùng storyline, không tự động lặp lại `action` của bước cuối; chúng chỉ có verdict khác `ignore`
nếu tự chúng kích hoạt một bước khác, **hoặc** nếu actor của chúng đã bị `disarm` từ trước và lại
mang đúng một op nằm trong `ops` đã bị tước — khi đó `DISARMED` (kiểm tra ở §3, không phải ở đây)
mới là thứ quyết định verdict `block`, không phải `ADVANCE`.

`DISARMED` là **map duy nhất trong bản base có hiệu lực vĩnh viễn theo actor**: không có bước nào
gỡ một actor khỏi `DISARMED` (không TTL, không thu hồi) — nhất quán với triết lý "giữ mọi thứ mãi
mãi" của §1.

---

## 6. Độ phức tạp & bộ nhớ

| Bước | Chi phí |
|---|---|
| `DISARMED` lookup | O(1) hash + set membership |
| `RESOLVE_NODE` | O(1) hash |
| `GRAPH.edges.append` | O(1) |
| `UNIFY_STORYLINE` | O(α(n)) amortized (DSU) |
| `ADVANCE` | O(#pattern + #automaton đang sống trong storyline) |
| **Bộ nhớ** | O(tổng số event + tổng số automaton đã seed + tổng số (actor, op) đã bị disarm, từ lúc khởi động) |
