# Engine v0.0.1 — bỏ provenance graph, chỉ giữ storyline & automaton

> Bản nâng cấp đầu tiên từ [`engine_base.md`](engine_base.md): loại bỏ hẳn provenance graph
> (`Node`, `Edge`, `GRAPH.edges`) — chỉ còn giữ lại **storyline** và **automaton**. Đây là mảnh
> đầu tiên trong loạt `engine_v*` giải quyết từng nhược điểm của bản base; các mảnh khác (bounded
> working-set, tách endpoint/backend, partial-order DAG…) là chuyện của các bản `engine_v*` sau.

---

## 1. Vấn đề của thiết kế trước

Ở bản base, mỗi event luôn tốn hai việc liên quan tới đồ thị:

```
a = RESOLVE_NODE(e.actor)              # get-or-create node, sống mãi
o = RESOLVE_NODE(e.object)
GRAPH.edges.append({from: a.key, to: o.key, op: e.op, ts: e.ts})   # (!) lưu cạnh mãi mãi
```

Bảng độ phức tạp ở [`engine_base.md §6`](engine_base.md) đã chỉ ra: `GRAPH.edges.append` là O(1)
mỗi event, nhưng vì không có bước nào xoá cạnh, **tổng số cạnh tăng đúng 1-1 theo tổng số event**
đã xử lý từ lúc engine khởi động — không phải hằng số cấu hình, mà là hàm của thời gian chạy.

Nhưng `ADVANCE` ([`engine_base.md §5`](engine_base.md)) — nơi thật sự ra quyết định — **không bao
giờ đọc `GRAPH.edges`**. Nó chỉ cần:

- `ttps` của event hiện tại,
- `S.automata` của storyline hiện hành,
- định nghĩa `Pattern`/`Step`.

`UNIFY_STORYLINE` cũng vậy: nó chỉ cần biết đúng **storyline nào** một định danh đang thuộc về
(`node.line`), không cần biết *nhờ cạnh nào* nó vào đó. Cạnh (`Edge`) tồn tại thuần tuý để phục
vụ tái dựng forensic ("ai làm gì với ai theo thứ tự nào") — một nhu cầu **điều tra**, không phải
nhu cầu **phát hiện**.

⟹ Bản base trả một chi phí bộ nhớ tăng vô hạn (một cạnh/event, mãi mãi) cho một cấu trúc mà
đường phát hiện (`ADVANCE`, `UNIFY_STORYLINE`) chưa từng dùng tới.

---

## 2. Phương án

Bỏ hẳn `GRAPH` (`Node`, `Edge`, `GRAPH.edges`). Chỉ còn ba/bốn cấu trúc sống:

- Một map định danh → storyline hiện hành (`LINE`) — đủ để `UNIFY_STORYLINE` hoạt động, thay cho
  trường `Node.line`. Không cần một bản ghi `Node` riêng, không `kind`, không cạnh.
- `Storyline` — **không đổi** so với bản base (`members`, `automata`, `last_activity`).
- `Automaton` — **không đổi** so với bản base.
- `DISARMED` — **không đổi** (không phải một phần của đồ thị, ngoài phạm vi thay đổi này).

`ON_EVENT` không còn dòng `ADD_EDGE`/`GRAPH.edges.append` nào. `ADVANCE` giữ **nguyên vẹn** logic
từ bản base — nó chưa từng phụ thuộc `GRAPH`, nên không phải sửa gì để hưởng lợi từ thay đổi này.

---

## 3. Cấu trúc dữ liệu

```
# ---- định danh → storyline hiện hành (thay cho Node.line ở bản trước) ----
LINE = map<key, Storyline>

# ---- op bị tước quyền theo từng actor — hiệu lực TỪ THỜI ĐIỂM bị disarm, mãi mãi ----
DISARMED = map<actor_key, set<Op>>

# ---- storyline = thành phần liên thông theo LINE (không cần đồ thị để biết ai-nối-ai) ----
Storyline S = {
    members: set<key>,
    automata: map<pattern_id, list<Automaton>>,  # có thể nhiều instance cùng pattern
    last_activity
}

# ---- automaton: tiến độ khớp một pattern, TUYẾN TÍNH (không đổi so với bản base) ----
Automaton A = {
    pattern_id,
    stage,          # chỉ số bước đã khớp — 0..len(steps), tăng dần 1-1
    stage_ts,       # thời điểm khớp bước gần nhất
}
```

`LINE[key]` chỉ là một con trỏ — không mang `kind`, không mang lịch sử. Bất cứ ai chưa từng xuất
hiện đều chưa có mặt trong `LINE`; lần đầu chạm tới, nó được gán vào một storyline (mới hoặc đã
có, tuỳ `UNIFY_STORYLINE`, §5).

**Pattern** giữ nguyên định nghĩa từ bản base — mỗi bước tự mang sẵn một trong bốn `action`:

```
Pattern = { id, steps: [ Step_1, Step_2, ..., Step_k ] }
Step    = { match, action }
```

- `ignore` — không hành động.
- `inspect` — chỉ ghi nhận.
- `block` — chặn đúng hành vi vừa xảy ra ở event này.
- `disarm(ops)` — chặn hành vi vừa xảy ra **và** thêm `ops` vào `DISARMED[e.actor]`: từ thời điểm
  này, actor đó không thể thực hiện bất kỳ op nào trong `ops` nữa.

---

## 4. Vòng lặp chính (per-event)

```
function ON_EVENT(e):
    if e.op in DISARMED.get(e.actor, {}):  # actor này đã bị tước quyền làm op này từ trước
        return block                       # chặn thẳng — không cần chạm LINE/automaton

    S = UNIFY_STORYLINE(e.actor, e.object) # gộp theo storyline, không qua đồ thị (§5)

    ttps = TAG_TTP(e)                      # gán technique cho event thô

    return ADVANCE(S, ttps, e)             # tiến automaton tuyến tính, trả verdict (§6)
                                            # ignore | inspect | block | disarm
```

So với bản base: không còn `RESOLVE_NODE` gọi riêng cho actor/object, không còn
`GRAPH.edges.append`. `UNIFY_STORYLINE` tự lo việc "lấy-hoặc-tạo" storyline cho cả hai định danh.

---

## 5. UNIFY_STORYLINE — gộp theo storyline, không qua đồ thị

```
function RESOLVE_LINE(key):
    if key not in LINE:
        LINE[key] = NEW_STORYLINE(key)     # storyline mới, chỉ chứa key này
    return LINE[key]

function UNIFY_STORYLINE(a_key, o_key):
    Sa = RESOLVE_LINE(a_key)
    So = RESOLVE_LINE(o_key)
    if Sa != So:
        MERGE(Sa, So)          # dời members/automata sang tập lớn hơn;
                                # với mỗi k vừa dời, cập nhật LINE[k] = storyline đích
    return LINE[a_key]
```

Mọi cạnh — bất kể loại `op` — vẫn gộp storyline, giống hệt bản base. Khác biệt duy nhất: trước
đây việc "actor và object đã từng nối với nhau" được suy ra từ một `Edge` cụ thể; giờ nó chỉ còn
là một phép so sánh con trỏ (`Sa != So`) và một lần cập nhật `LINE`. Không có gì bị mất về mặt
*kết quả* của `UNIFY_STORYLINE` — storyline dựng ra giống hệt bản base, chỉ là dựng **mà không
cần giữ lại cạnh nào để giải thích vì sao**.

---

## 6. ADVANCE — automaton tuyến tính, verdict theo từng bước

Không có severity/threshold gộp toàn automaton. Mỗi bước tự mang sẵn `action` của nó (§3); verdict
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

Toàn bộ khối này **giống hệt bản base** — bằng chứng cho thấy `ADVANCE` chưa từng phụ thuộc vào
đồ thị: bỏ `GRAPH` không đòi hỏi sửa một dòng nào ở đây.

---

## 7. Độ phức tạp & bộ nhớ

| Bước | Chi phí |
|---|---|
| `DISARMED` lookup | O(1) hash + set membership |
| `RESOLVE_LINE` | O(1) hash |
| `UNIFY_STORYLINE` | O(size storyline nhỏ hơn) — dời + cập nhật `LINE` cho từng key |
| `ADVANCE` | O(#pattern + #automaton đang sống trong storyline) |
| **Bộ nhớ** | O(số định danh **distinct** đã chạm tới + tổng số automaton đã seed + tổng số (actor, op) đã bị disarm, từ lúc khởi động) |

So với bản base — nơi bộ nhớ tăng theo **tổng số event** (mỗi event luôn sinh thêm một `Edge`) —
bản này chỉ tăng theo **số định danh khác nhau từng chạm tới**. Một actor gây ra hàng nghìn event
(ví dụ `powershell.exe` ghi hàng trăm file) giờ chỉ tốn đúng một mục trong `LINE` cho chính nó;
trước đây mỗi event của nó còn kéo theo một `Edge` mới, vĩnh viễn.

---

## 8. Giới hạn / đánh đổi

Cái đổi lấy khoản tiết kiệm bộ nhớ ở §7: mất khả năng **tái dựng lại chuỗi event theo đúng thứ
tự** — không còn `Edge` nào để đọc lại, nên không thể trả lời "actor này đã làm gì, với ai, theo
trình tự nào" sau khi sự việc xảy ra. Storyline chỉ còn cho biết **tập thực thể nào đang cùng một
câu chuyện** (`members`), không còn cho biết **con đường quan hệ cụ thể** dẫn tới kết luận đó.

Khoản mất này không ảnh hưởng `ADVANCE`/`UNIFY_STORYLINE` (§1, §6) — hai hàm đó chưa từng đọc
`GRAPH.edges` ngay ở bản base. Nên về mặt **phát hiện** (detection), hai bản cho kết quả giống hệt
nhau; cái mất chỉ nằm ở nhu cầu **điều tra/forensic** (dựng lại "ai làm gì với ai" sau khi có
alert) — một nhu cầu mà bản base *có dữ liệu sẵn* để phục vụ (dù chưa có cơ chế nào thật sự đọc
lại nó), còn bản này thì không còn dữ liệu đó nữa.
