# SDD — `edr-engine` (lõi phát hiện endpoint–backend split)

**Software Design Document** · crate `edr_engine` (v0.1.0) · zero external dependency

> Tài liệu này mô tả *thiết kế phần mềm* của lõi phát hiện: cấu trúc module, mô hình
> dữ liệu, thuật toán, giao diện và bất biến. Nó bổ trợ — không thay thế — tài liệu
> *thuật toán* [`engine.md`](engine.md); các mục §x tham chiếu tới engine.md được giữ
> nguyên trong docstring của code. Nguồn sự thật là code trong [engine/src/](engine/src/).

---

## 1. Giới thiệu

### 1.1 Mục đích
`edr-engine` là thư viện phát hiện tấn công hai nửa, tách bạch theo trách nhiệm:

- **Endpoint** — bộ chặn inline *nhanh / nhẹ / chính xác*. Bộ nhớ bị chặn cứng bởi
  bất biến working-set, **không** giữ đồ thị forensic, ship mọi event rồi quên.
- **Backend** — bộ tương quan forensic *không giới hạn*. Giữ **full provenance graph**,
  khi endpoint chặn thì dựng lại và hiển thị toàn bộ storyline dẫn tới hành vi.

### 1.2 Phạm vi
Crate là **thư viện thuần** (`#![no dependency]`), không I/O mạng, không serialize. Ranh
giới endpoint→backend trong tiến trình chỉ là `Vec<Wire>`. Transport thật (protobuf/TCP)
nằm ở crate [`proto/`](proto/) và hai service [`endpoint_service/`](endpoint_service/) ·
[`backend_service/`](backend_service/). Sensor kernel (minifilter) nằm ở
[`sensor/`](sensor/).

### 1.3 Thuộc tính chất lượng (design drivers)
| Thuộc tính | Cách đạt được |
|---|---|
| **Bộ nhớ chặn cứng ở endpoint** | Bất biến working-set (refcount ∨ cửa sổ `W`) + sweep — §5.1 |
| **Latency thấp trên hot path** | Không lưu cạnh; matching là phép bit O(1); arm chỉ identity 1 bước trước chokepoint |
| **Auditable / offline build** | Zero external crate; parser DSL viết tay |
| **Thêm mẫu không cần build lại** | Rule/pattern nạp từ file `.rules` lúc chạy |
| **Chống pid-reuse** | Node key process = `(pid, start_ts)`; binding & arm theo identity |

### 1.4 Thuật ngữ
- **TTP** — kỹ thuật tấn công (định danh kiểu `T1486`), gắn nhãn bởi *tagger*.
- **Storyline** — tập entity + automata liên đới nhân quả (đơn vị tương quan ở endpoint).
- **Automaton** — một thể hiện đang khớp của một *pattern* trong một storyline.
- **Chokepoint** — bước *enforceable* mà endpoint có thể chặn đồng bộ.
- **Arm** — đẩy `(identity, op)` xuống sensor để chỉ nó đi đường enforce đồng bộ.

---

## 2. Tổng quan kiến trúc

### 2.1 Sơ đồ thành phần

```
                   ┌─────────────────────── edr_engine (lib) ───────────────────────┐
   sensor/service  │                                                                 │
   ──Event──────►  │   ┌──────────────┐   Wire (ship-and-forget)   ┌──────────────┐  │
                   │   │   Endpoint   │ ─────────────────────────► │   Backend    │  │
   ◄─Decision───── │   │  (inline)    │   Event / BlockReport      │ (forensic)   │  │
   ◄─ArmCmd─────── │   └──────┬───────┘                            └──────┬───────┘  │
                   │          │ dùng chung                                │          │
                   │   ┌──────┴───────────────────────────────────────────┴──────┐  │
                   │   │  event · pattern · rules · dataset  (mô hình telemetry)  │  │
                   │   └───────────────────────────────────────────────────────── ┘ │
                   └─────────────────────────────────────────────────────────────────┘
                                Pipeline::feed() nối hai nửa (harness)
```

### 2.2 Bản đồ module ↔ trách nhiệm

| Module | File | Trách nhiệm |
|---|---|---|
| `lib` | [engine/src/lib.rs](engine/src/lib.rs) | Kiểu verdict/decision công khai; `Pipeline` nối endpoint↔backend |
| `event` | [engine/src/event.rs](engine/src/event.rs) | `Event`, `NodeKey`, `Op` — mô hình telemetry chuẩn hoá |
| `pattern` | [engine/src/pattern.rs](engine/src/pattern.rs) | Pattern = precedence DAG; `Step`, `RoleBinding`, `Scope`, `RootGate` |
| `rules` | [engine/src/rules.rs](engine/src/rules.rs) | DSL rule; `Tagger` (event→TTP), `RuleSet`, scoring metadata |
| `endpoint` | [engine/src/endpoint.rs](engine/src/endpoint.rs) | Working-set, storyline, matching bậc-riêng-phần, chặn inline, arm |
| `backend` | [engine/src/backend.rs](engine/src/backend.rs) | Provenance graph (DSU), dựng & render chain khi block |
| `wire` | [engine/src/wire.rs](engine/src/wire.rs) | `WireEvent` / `BlockReport` — kênh ship |
| `dataset` | [engine/src/dataset.rs](engine/src/dataset.rs) | Loader `.evt` cho replay/test |
| `main` | [engine/src/main.rs](engine/src/main.rs) | Bin `edr-replay` — replay dataset, in verdict + storyline |

### 2.3 Luồng xử lý một event (end-to-end)
Qua [`Pipeline::feed`](engine/src/lib.rs#L78):
1. `endpoint.on_event(e)` → `(Decision, Verdict)`; nội bộ ship mọi event vào `outbox`,
   và khi chặn thì ship thêm `BlockReport`.
2. Harness `drain_outbox()` đẩy từng `Wire` sang `backend.ingest()`.
3. `Wire::Event` → cập nhật graph; `Wire::Block` → `trace_chain` trả `Chain`.
4. `feed` trả `(Decision, Verdict, Option<Chain>)` — `Chain` xuất hiện đúng khi có block.

---

## 3. Mô hình dữ liệu

### 3.1 `Op` — [event.rs:11](engine/src/event.rs#L11)
Enum 10 op: `Exec, Open, Read, Write, Connect, Inject, Create, Delete, Load, Dup`.
Phân loại quan trọng: [`is_causal()`](engine/src/event.rs#L27) = `{Exec, Inject, Create, Dup, Write}`.
**Chỉ cạnh nhân quả mới hợp nhất storyline**; cạnh "touch" (read/open/connect) để lại
cạnh cho scoring/forensics nhưng không unify.

### 3.2 `NodeKey` — [event.rs:51](engine/src/event.rs#L51)
Khóa tự nhiên của node đồ thị:
- `Process { pid: u32, start_ts: u64 }` — **cặp identity chống pid-reuse**.
- `File { file_id: String }` — *token FileId* (rename giữ token, copy sinh token mới),
  **không phải path**.
- `Socket { key }`, `Other { kind, key }`.

### 3.3 `Event` — [event.rs:71](engine/src/event.rs#L71)
`{ ts: u64, op: Op, actor: NodeKey (luôn process), object: NodeKey, attrs: HashMap<String,String> }`.
Attrs mang dữ liệu tagger cần: `image`, `target_image`, `entropy`, `dir`, `enum`, `vm_read`,
`pe`, `cmd`… Helper: `attr/attr_f64/attr_bool`, và [`image_key()`](engine/src/event.rs#L90)
resolve `attrs["image"]` → `NodeKey::File`.

### 3.4 `Pattern` / `Step` — [pattern.rs](engine/src/pattern.rs)
Pattern là **precedence DAG bậc riêng phần**, tiến độ mã hoá bằng bitmask (`Mask = u64`,
≤ 64 step/pattern):

| Trường `Step` | Ý nghĩa |
|---|---|
| `bit: u8` | vị trí trong `completed_mask` |
| `matcher: StepMatch` | `ByTtp(Vec<String>)` (OR-slot biến thể công cụ) hoặc `ByOp(Op)` |
| `prereq_mask: Mask` | các bit **phải** xong trước (thứ tự = phần này, không phải stage tuyến tính) |
| `seg_window: u64` | deadline (ms) tính từ lúc prereq thỏa — §5.6 |
| `enforceable: bool` | có phải chokepoint chặn đồng bộ được không |
| `optional: bool` | loại khỏi `required_mask` |
| `bindings: Vec<RoleBinding>` | ràng buộc biến theo *identity* (role→object/image/actor) |

`Pattern` gồm `required_mask` (bit cần để accept), `scope` (`SameStoryline|SameActor|Free`),
`block_at: Option<u8>`, `theta_alert/theta_block`, và `root_gate` (`Always|PeWrite` — cổng
seed để chặn bùng nổ automata, §7).

### 3.5 `Wire` — [wire.rs](engine/src/wire.rs)
- `WireEvent { seq, endpoint_sid, ttps: Vec<String>, event }` — telemetry ship-and-forget;
  mang kèm TTP đã xác nhận để backend annotate mà **không chạy lại tagger**.
- `BlockReport { seq, pattern, score, reason, event }` — control-plane: yêu cầu backend
  dựng lại storyline.

### 3.6 Verdict / Decision — [lib.rs:31](engine/src/lib.rs#L31)
`VerdictKind = None<Suspect<Alert<Block` (Ord). `Verdict { kind, pattern, score, reason }`.
`Decision = Allow | Deny`.

---

## 4. Thiết kế thành phần: Endpoint

Struct [`Endpoint`](engine/src/endpoint.rs#L97) giữ **chỉ state phát hiện** (không có cạnh):

```
active:      HashMap<NodeKey, Entity>       // working set (entity + refcount + last_touch)
storylines:  HashMap<usize, Storyline>      // tập nhỏ tường minh, xóa được
rate:        HashMap<NodeKey, RateState>    // bộ đếm trượt cho tagger rate/spread
kernel_arm:  HashMap<NodeKey, Op>           // identity đã arm -> op bị chặn (§9)
pushed_arms: HashMap<NodeKey, Op>           // arm đã đẩy xuống sensor (để diff)
arm_outbox / outbox / seq / w_ms / caps / observability(shipped_*, swept, log)
```

- [`Entity`](engine/src/endpoint.rs#L53): `{ line: Option<sid>, refcount, last_touch }`.
  `refcount>0` ⟺ đang bị ≥1 automaton bind → **pin warm**.
- [`Storyline`](engine/src/endpoint.rs#L88): `{ members: HashSet<NodeKey>, automata:
  HashMap<pattern_id, Automaton>, ttp_ring (VecDeque cap 32), score, last_activity }`.
- [`Automaton`](engine/src/endpoint.rs#L61): `{ pattern_idx, completed_mask, step_ts,
  bound_ids: role→NodeKey, pins, armed, last_progress }`. **Bind theo identity** (`bound_ids`
  giữ `NodeKey`, không phải con trỏ node) nên xóa node không bao giờ làm hỏng automaton.

### 4.1 Vòng đời một event — [`on_event`](engine/src/endpoint.rs#L270)
```
link(actor, object, op)           → sid            (§4.2)
touch(image) nếu là exec
ttps = rules.tag(e, rate)         → cập nhật ttp_ring
SHIP Wire::Event(seq, sid, ttps, e)                (ship-and-forget)
kernel_denied? (armed op + storyline còn chokepoint pending của op)
verdict = advance(sid, ttps, e)                    (§4.3)
decision = Deny nếu verdict==Block || kernel_denied
  nếu Deny: SHIP Wire::Block(...)
gc_and_sweep(now)                                  (§5)
reconcile_arms()                                   (§4.5)
```

### 4.2 LINK & MERGE — [`link`](engine/src/endpoint.rs#L200) / [`merge`](engine/src/endpoint.rs#L212)
- `link`: lấy sid của actor; nếu op **không** nhân quả → dừng (cạnh touch, chỉ ship).
  Nếu nhân quả → hợp nhất sid(actor) với sid(object).
- `merge`: **union by size** (members+automata). Khi hợp nhất automata cùng pattern:
  OR `completed_mask`, giữ `step_ts` sớm nhất, gộp `bound_ids` (không ghi đè), **giữ pins
  của child** để refcount cân bằng lúc GC.
- **Hub cap**: nếu merge vượt `max_nodes_per_sid` (4096) hoặc `max_automata_per_sid` (32)
  thì **không merge ở endpoint** — để hai storyline riêng; backend tự stitch lại từ cạnh
  nhân quả đã ship. (Chống "execution partitioning explosion" của process hub.)

### 4.3 ADVANCE — matching bậc riêng phần — [`advance`](engine/src/endpoint.rs#L399)
1. **Seed**: với mỗi pattern chưa có automaton trong storyline, nếu có *root step*
   (`prereq==0`) khớp event **và** `root_gate.ok(e)` → tạo automaton (chặn cứng ở
   `max_automata_per_sid`).
2. **Advance**: mọi automaton, với mọi step khớp `slot_matches(e, ttps)` → `try_commit`;
   nếu commit thì `rescore_and_emit`; giữ verdict cao nhất.

[`try_commit`](engine/src/endpoint.rs#L441) là chuỗi gate O(1):
| Gate | Ý nghĩa |
|---|---|
| chưa `has(bit)` | không commit lại |
| `PREREQ_OK` | `(prereq & completed) == prereq` |
| `SEG_WINDOW_OK` | `now - max(ts prereq) ≤ seg_window` (deadline theo đoạn) |
| `SCOPE_OK` | `SameActor` yêu cầu actor ∈ bound_ids |
| `BINDING_OK` | role resolve về **cùng identity** — "ghi X, chạy Y" bị loại tại đây |

Commit: set bit, ghi `step_ts`, cập nhật `bound_ids`, **pin identity mới** (`refcount += 1`).

### 4.4 Rescore & phát verdict — [`rescore_and_emit`](engine/src/endpoint.rs#L517)
- Tính `score = kill_chain_score(...)` (§6), cập nhật `storyline.score`.
- `accepting = (completed & required_mask) == required_mask`.
- Nếu accepting **và** `score ≥ theta_block` **và** đang ở đúng `block_at` enforceable →
  **`Block`** (chặn tại chokepoint).
- accepting & `score ≥ theta_alert` → `Alert`; nếu không → `Suspect`.
- Nếu **chưa** accepting nhưng `score ≥ theta_block` và còn step enforceable pending →
  **ARM** identity actor cho op của chokepoint đó (đặt `kernel_arm`, `armed=true`).

### 4.5 Kernel-arm (§9) — [`reconcile_arms`](engine/src/endpoint.rs#L353)
Mỗi event, sau GC: tính lại tập arm **còn được biện minh** (storyline còn chokepoint
pending của op), gán lại `kernel_arm`, rồi **diff** với `pushed_arms` → phát `ArmCmd::Arm`
/ `Disarm` vào `arm_outbox`. Bảo đảm bảng arm đẩy xuống sensor không bao giờ deny một
identity cũ (pid-reused). `ArmCmd` — [endpoint.rs:45](engine/src/endpoint.rs#L45).

---

## 5. Bất biến bộ nhớ & vòng đời (§3, §6c)

### 5.1 Bất biến working-set
> Một entity được giữ trong `active` **khi và chỉ khi** nó đang bị ≥1 automaton bind
> (`refcount>0`) **hoặc** được touch trong cửa sổ `W` (`DEFAULT_W_MS = 300_000` ms).

Bộ nhớ endpoint bị chặn bởi *bất biến* này, không phải bởi chính sách evict.

### 5.2 [`gc_and_sweep`](engine/src/endpoint.rs#L580) — ba pha
1. **GC automaton chết**: [`automaton_dead`](engine/src/endpoint.rs#L652) = không tiến
   triển lâu hơn `max(seg_window)` của pattern → xóa automaton, **nhả pin** (`refcount -= 1`).
2. **Sweep entity lạnh**: `refcount==0 && now - last_touch > w_ms` → xóa khỏi `active`,
   xóa khỏi members, xóa `rate` (`swept += 1`).
3. **Drop storyline rỗng**: không còn members lẫn automata → xóa.

---

## 6. Mô hình chấm điểm (kill-chain score)

[`kill_chain_score`](engine/src/endpoint.rs#L660):

```
score = W_STAGES·|tactics| + W_SEV·Σseverity + W_ORDER·order + W_RARITY·Σrarity
        (W_STAGES=2.0, W_SEV=0.3, W_ORDER=1.0, W_RARITY=2.0)
```
- `tactics` = số tactic **khác nhau** trong các step đã completed (step `ByOp` tính vào
  `Tactic::Staging`).
- `severity`, `rarity` lấy từ metadata TTP ([`RuleSet::meta`](engine/src/rules.rs#L112);
  id lạ → default staging thấp).
- `order` = tỉ lệ cặp step liền kề đúng thứ tự thời gian
  ([`order_observed`](engine/src/endpoint.rs#L690)) — thưởng chuỗi đi đúng kill-chain.

Ngưỡng `theta_alert/theta_block` khai báo theo từng pattern trong rule file.

---

## 7. Thiết kế thành phần: Backend

[`Backend`](engine/src/backend.rs#L51) giữ **full graph, không evict**:
`nodes: Vec<BNode>`, `index: HashMap<NodeKey,usize>`, `edges: Vec<BEdge>`, và **DSU**
(`dsu: Vec<usize>`) cho thành phần liên thông.

- [`ingest`](engine/src/backend.rs#L66): `Wire::Event` → thêm node/edge; nếu op nhân quả
  thì `union(actor, object)`. Trên `exec`, gán nhãn child bằng basename image (dễ đọc).
  `Wire::Block` → `trace_chain`.
- [`trace_chain`](engine/src/backend.rs#L103): neo tại node actor của event bị chặn, lấy
  `root = find(anchor)`; chọn mọi cạnh có `from` **hoặc** `to` thuộc component; sort theo
  `(ts, idx)`; đánh dấu `blocked` đúng cạnh (ts+op+actor+object khớp `BlockReport`). Trả
  `Chain { pattern, score, reason, blocked_ts, steps, nodes }`.
- [`render_chain`](engine/src/backend.rs#L195): in storyline dạng người-đọc; cạnh nhân quả
  `->`, cạnh touch `..`, bước bị chặn gắn `*** BLOCKED ***`.

> Endpoint không giữ cạnh nên **không tự dựng chuỗi được** — đây chính là giá trị cộng
> thêm của backend.

---

## 8. Giao diện công khai (API)

```rust
// Pipeline (harness in-process)
Pipeline::new() / from_rules_str(&str) / from_rules_file(path)
Pipeline::feed(&Event) -> (Decision, Verdict, Option<Chain>)

// Endpoint
Endpoint::new() / from_rules_str / from_rules_file / with_rules(RuleSet)
Endpoint::on_event(&Event) -> (Decision, Verdict)
Endpoint::drain_outbox() -> Vec<Wire>
Endpoint::drain_arm_cmds() -> Vec<ArmCmd>
Endpoint::set_window_ms / active_len / storyline_count
// observability: shipped_events, shipped_blocks, swept, log

// Backend
Backend::new()
Backend::ingest(Wire) -> Option<Chain>
render_chain(&Chain) -> String

// Model tái xuất: Event, NodeKey, Op, Chain, ChainStep, ArmCmd, Verdict, Decision
```

**Bất biến hợp đồng**: `on_event` phải được gọi tuần tự (state không thread-safe); caller
`drain_outbox()` sau mỗi event và forward sang backend theo đúng thứ tự; `drain_arm_cmds()`
forward xuống sensor.

---

## 9. Rule DSL — [rules.rs](engine/src/rules.rs)

Parser viết tay ([`RuleSet::parse_str`](engine/src/rules.rs#L135)), một directive/dòng,
`#` comment, token cách nhau bởi khoảng trắng. **Bốn directive**: `ttp`, `tagger`,
`pattern`, `step`. `step` gắn vào `pattern` gần nhất phía trên; `block` đánh dấu chokepoint.

### 9.1 Bảng tham chiếu directive

| Directive | Cú pháp | Trường / giá trị hợp lệ |
|---|---|---|
| `ttp` | `ttp <ID> tactic=<t> severity=<f> rarity=<f>` | `tactic` ∈ `execution, discovery, defense_evasion, credential_access, impact, staging`; `severity` (0..10), `rarity` (0..1) — cho scoring §6 |
| `tagger` | `tagger <ID> <cond>...` | phát `<ID>` khi **mọi** cond đúng (§9.2) |
| `pattern` | `pattern <NAME> scope=<s> theta_alert=<f> theta_block=<f> [root_gate=<g>]` | `scope` ∈ `same_storyline, same_actor, free`; `root_gate` ∈ `always`(mặc định)`, pe_write` |
| `step` | `step <NAME> bit=<n> match=<m> [prereq=<n,n>] [seg_window=<ms>] [enforceable] [optional] [block] [bind=<role>:<src>]` | `match` (§9.3); `bind src` ∈ `object, image, actor`; flag không có `=` |

### 9.2 Tagger cond — tập đóng ([`Cond`](engine/src/rules.rs#L62))

| Cond | Ý nghĩa | Ví dụ |
|---|---|---|
| `op=A\|B` | op ∈ tập | `op=open\|read` |
| `image_base_in=a,b` | basename(`attrs["image"]`) ∈ tập (lowercase) | `image_base_in=powershell.exe,cmd.exe` |
| `target_image_base=a,b` | basename(`attrs["target_image"]`) ∈ tập | `target_image_base=lsass.exe` |
| `attr_true=K` | `attrs[K]` ∈ {`1`,`true`} | `attr_true=vm_read` |
| `entropy_gt=F` | `attrs["entropy"] > F` | `entropy_gt=0.85` |
| `write_rate_ge=N` | ≥ N write/actor trong 1000 ms | `write_rate_ge=3` |
| `dir_spread_ge=N` | write chạm ≥ N thư mục khác nhau/1000 ms | `dir_spread_ge=2` |
| `cmd_recovery_inhibit` | builtin: match chuỗi lệnh xóa shadow/catalog/bcdedit | `cmd_recovery_inhibit` |

> Thêm *hình dạng* predicate mới là việc **duy nhất** còn cần sửa code — cố ý, vì tagger
> là tầng phụ thuộc nền tảng. `write_rate_ge`/`dir_spread_ge` chạy trên bộ đếm trượt O(1)
> [`RateState`](engine/src/rules.rs#L81) (cửa sổ 1000 ms).

### 9.3 `step match=` — ba dạng

| Dạng | Nghĩa |
|---|---|
| `match=ttp:T1486` | khớp khi event mang TTP `T1486` |
| `match=ttp_any:T1547\|T1053\|T1543` | OR-slot: khớp bất kỳ TTP trong danh sách (biến thể công cụ) |
| `match=op:write` | khớp cấu trúc theo op thô (TTP-less, ví dụ dropper) |

### 9.4 Ví dụ đầy đủ — mọi directive & tùy chọn (kitchen-sink)

```text
# ── (1) ttp: metadata cho scoring — đủ 6 tactic ──────────────────────────────
ttp T1059 tactic=execution         severity=3 rarity=0.10   # interpreter
ttp T1083 tactic=discovery         severity=2 rarity=0.10   # file discovery
ttp T1490 tactic=defense_evasion   severity=7 rarity=0.80   # inhibit recovery
ttp T1003 tactic=credential_access severity=9 rarity=0.85   # LSASS dump
ttp T1486 tactic=impact            severity=9 rarity=0.90   # encrypt for impact
ttp T1547 tactic=execution         severity=5 rarity=0.60   # persistence (demo ttp_any)

# ── (2) tagger: minh hoạ đủ 8 loại cond ──────────────────────────────────────
tagger T1059 op=exec image_base_in=powershell.exe,pwsh.exe,cmd.exe               # op + image_base_in
tagger T1490 op=exec image_base_in=vssadmin.exe,wbadmin.exe cmd_recovery_inhibit  # + builtin cmd
tagger T1083 op=open|read attr_true=enum                                          # op-set + attr_true
tagger T1003 op=read target_image_base=lsass.exe attr_true=vm_read                # target_image_base
tagger T1486 op=write entropy_gt=0.85 write_rate_ge=3 dir_spread_ge=2             # entropy + rate + spread

# ── (3+4) pattern + step: scope=same_storyline, root_gate=pe_write ───────────
#   Dropper "ghi X → chạy X": binding theo identity; match=op:* (TTP-less);
#   flag bind/enforceable/block; prereq tuyến tính.
pattern dropper_write_then_exec scope=same_storyline theta_alert=6 theta_block=12 root_gate=pe_write
  step write_executable bit=0 match=op:write prereq=  seg_window=300000             bind=dropped:object
  step exec_dropped     bit=1 match=op:exec  prereq=0 seg_window=300000 enforceable bind=dropped:image block

#   Ransomware: nhóm giữa {T1490,T1083} TỰ DO thứ tự (cùng prereq=0), hội tụ ở T1486
#   (prereq=1,2). Minh hoạ prereq nhiều bit, hai step enforceable, block ở cuối.
pattern ransomware_fast_encrypt scope=same_storyline theta_alert=6 theta_block=12 root_gate=always
  step T1059_exec_interpreter bit=0 match=ttp:T1059 prereq=    seg_window=120000
  step T1490_inhibit_recovery bit=1 match=ttp:T1490 prereq=0   seg_window=120000 enforceable
  step T1083_file_discovery   bit=2 match=ttp:T1083 prereq=0   seg_window=120000
  step T1486_encrypt_impact   bit=3 match=ttp:T1486 prereq=1,2 seg_window=120000 enforceable block

#   Single-event chokepoint: scope=same_actor, một step enforceable+block (LSASS).
pattern lsass_credential_dump scope=same_actor theta_alert=4 theta_block=6 root_gate=always
  step T1003_lsass_read bit=0 match=ttp:T1003 seg_window=120000 enforceable block

#   scope=free, match=ttp_any (OR-slot), flag optional (loại khỏi required_mask).
pattern persistence_probe scope=free theta_alert=5 theta_block=99 root_gate=always
  step persist_any bit=0 match=ttp_any:T1547|T1059 prereq=  seg_window=600000
  step noisy_hint  bit=1 match=ttp:T1083           prereq=0 seg_window=600000 optional
```

Semantics thể hiện trong ví dụ:
- **`prereq=` rỗng** ⇔ root step (được seed khi khớp; lọc qua `root_gate`).
- **`root_gate=pe_write`** chỉ cho seed khi event là `write` file thực thi (`attrs["pe"]`),
  giữ số automaton bị chặn (§7).
- **`optional`** → không vào `required_mask` (không cần để pattern *accept*) nhưng vẫn cộng
  điểm khi khớp.
- **`block`** đánh dấu `block_at`; endpoint chỉ chặn khi accepting `&& score≥theta_block`
  `&&` đang ở đúng bit đó (§4.4). Đặt `theta_block` rất cao (vd `99`) ⇒ *không bao giờ*
  chặn, chỉ Alert/Suspect.
- Parser **validate** `prereq` phải trỏ bit có thật ([rules.rs:211](engine/src/rules.rs#L211));
  id TTP lạ trong scoring rơi về default staging thấp ([rules.rs:112](engine/src/rules.rs#L112)).

Rule file thật trong repo: [engine/rules/builtin.rules](engine/rules/builtin.rules) (dropper +
ransomware) · [engine/rules/lsass_dump.rules](engine/rules/lsass_dump.rules) — thêm mẫu
**hoàn toàn bằng data**, không build lại engine.

---

## 10. Kiểm thử & công cụ

- **Bin replay** [`edr-replay`](engine/src/main.rs): `cargo run --bin edr-replay --
  datasets/lsass_dump.evt [rules/lsass_dump.rules]`. In bảng verdict, storyline backend
  dựng tại mỗi block, log endpoint, và thống kê `ACTIVE/storylines/shipped/swept`.
- **Test hành vi** [engine/tests/eb.rs](engine/tests/eb.rs): các bất biến phát hiện —
  DENY tại write mã hoá đầu; dropper chỉ SUSPECT; "ghi X chạy Y" không false-positive;
  đảo thứ tự nhóm giữa vẫn chặn; LSASS chặn tại read.
- **Dataset** [.evt](engine/datasets/): `key=value`/dòng — xem
  [dataset.rs](engine/src/dataset.rs).

---

## 11. Ràng buộc & hạn chế đã biết

- **Không thread-safe**: một `Endpoint`/`Backend` phải dùng đơn luồng, tuần tự.
- **Backend `trace_chain` lấy *mọi* cạnh trong component** — sẽ nổ với dữ liệu thật; cần
  DEPIMPACT-style edge weighting / node versioning (xem [docs/todo.md](docs/todo.md)).
- **Backend chưa evict** (đúng thiết kế forensic) — cần CPR/NodeMerge/LogGC khi chạy quy mô.
- **Backend hiện thụ động**: chỉ dựng chuỗi khi endpoint chặn; tầng phát hiện chủ động
  trên graph (HOLMES/RapSheet/NoDoze…) là roadmap ([docs/todo.md](docs/todo.md)).
- **`≤ 64 step/pattern`** do `Mask = u64`.
- **Arm ngược có ký từ backend→endpoint** (§9 `ArmDirective`) và stitch xuyên host **chưa**
  hiện thực trong crate này.

---

## 12. Tham chiếu
- Thuật toán chi tiết: [engine.md](engine.md) · code map: [engine/README.md](engine/README.md)
- Contract wire: [proto/wire.proto](proto/wire.proto) · service:
  [endpoint_service/](endpoint_service/) · [backend_service/](backend_service/)
- Sensor kernel: [sensor/windows_driver/](sensor/windows_driver/) · Roadmap:
  [docs/todo.md](docs/todo.md)
- Bài báo nền: HOLMES (2019), POIROT (2019), RapSheet (Symantec 2020).
