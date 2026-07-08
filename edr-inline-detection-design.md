# Thiết kế: Inline Behavioral Prevention Engine (kernel telemetry + MITRE correlation)

> Mục tiêu: xây một engine chạy **trên endpoint**, thu telemetry ở **kernel**, lọc sẵn các
> event có giá trị theo **MITRE ATT&CK technique**, correlate nhiều event thành chuỗi tấn công,
> và **phát hiện inline để ngăn chặn (block)** — không chỉ cảnh báo.
>
> Triết lý: **bộ não correlation kiểu HOLMES** (event → TTP → kill-chain) + **cơ chế thực thi
> kiểu IOA** (state machine tăng dần, chặn ở điểm nghẽn). POIROT (offline, subgraph matching
> NP-hard) và RapSheet (lớp triage trên detector khác) **không** dùng làm lõi.

---

## 1. Nguyên tắc thiết kế

| Nguyên tắc | Lý do |
|---|---|
| **Kernel = cảm biến + điểm thực thi** | Chặn phải đồng bộ tại chỗ, latency micro/mili-giây |
| **Userland = bộ não correlation stateful** | Giữ trạng thái graph/automaton, không nhét vào kernel |
| **Inline path O(1), không subgraph matching** | NP-hard alignment bất khả thi trên đường nóng |
| **Chặn ở "điểm nghẽn"/hành động kế tiếp** | Correlation cần thời gian; không chặn được ở event đầu |
| **Ngưỡng bảo thủ hơn detection** | False positive giờ = chặn nhầm phần mềm hợp lệ |

### Mâu thuẫn cốt lõi phải giải
> **Correlation cần nhiều event theo thời gian, còn chặn phải quyết định NGAY.**

Giải pháp: duy trì trạng thái chuỗi tấn công; khi độ tin cậy vượt ngưỡng thì **gate hành động
enforcing kế tiếp** (mã hóa file thật, đọc LSASS, mở kết nối exfil...) — không hồi tố cái đã xảy ra.

---

## 2. Kiến trúc tổng thể

```
┌─────────────────────────── KERNEL SPACE ───────────────────────────┐
│                                                                     │
│  [Sensor hooks]            [Fast filter]         [Enforcement]      │
│  syscall / LSM / ─────►  lọc theo technique ──►  allow / DENY       │
│  file / net / proc        (map lookup O(1))       (-EPERM / block)  │
│        │                        │                      ▲            │
│        │ event thô              │ event-đã-gắn-TTP      │ verdict    │
│        ▼                        ▼                      │            │
│   ┌─────────────── ring buffer / eBPF map ─────────────┘            │
└────────────┬────────────────────────────────────────────┬─────────┘
             │ (up: events)                    (down: policy/verdict)
┌────────────▼────────────────────────────────────────────┴─────────┐
│                        USER SPACE (daemon)                          │
│                                                                     │
│  [Normalizer] ─► [TTP tagger] ─► [Storyline builder] ─► [Matcher]  │
│                                    (causality graph)   (automata)   │
│                                          │                 │        │
│                                          ▼                 ▼        │
│                                   [Scorer/kill-chain] ─► [Policy]   │
│                                                            │        │
│                                              verdict + prevention ──┘
└─────────────────────────────────────────────────────────────────────┘
```

### Phân chia trách nhiệm
- **Kernel**: thu event, lọc nhanh theo technique đã biết, tra trạng thái process/storyline
  gần nhất (cache trong eBPF map), thực thi allow/deny đồng bộ.
- **Userland**: normalize, gắn TTP đầy đủ, dựng causality graph (storyline), chạy automata
  matching, chấm điểm kill-chain, ra policy và đẩy verdict xuống kernel.

---

## 3. Thu thập telemetry ở kernel

### Linux
- **Sensor**: eBPF trên tracepoint/kprobe (`sys_enter_*`, `sched_process_exec`), `bpf_lsm`
  cho các hook bảo mật.
- **Enforcement**: **`bpf_lsm`** trả `-EPERM` để deny thao tác; hoặc kernel module với LSM hooks;
  seccomp cho subset syscall.
- **Truyền dữ liệu**: `BPF_MAP_TYPE_RINGBUF` (event lên userland), `BPF_MAP_TYPE_HASH`
  (verdict/trạng thái xuống kernel).

### Windows
- **Sensor**: ETW (kernel provider), minifilter (I/O file), callbacks.
- **Enforcement**:
  - **Minifilter** → chặn thao tác file (I/O).
  - **`ObRegisterCallbacks`** → chặn mở handle vào process khác (chống credential dumping).
  - **Pre-create process/thread callbacks** → chặn tạo tiến trình.
  - ⚠️ Nhiều callback chỉ *notify*, không deny — phải chọn đúng hook cho phép chặn.

### Lọc sẵn theo technique (ngay ở kernel)
Mỗi event được đối chiếu với một **bảng technique-of-interest** (nạp từ userland xuống eBPF map).
Chỉ event khớp mới:
- được đánh dấu `candidate_ttp_id` và đẩy lên userland, hoặc
- kích hoạt kiểm tra chặn tức thì (với technique single-event đủ độc hại).

→ Giảm khối lượng lên userland, tránh dependency explosion ngay từ gốc.

---

## 4. Mô hình dữ liệu

### 4.1 Node & Edge (causality graph / storyline)
```
Node:
  id, type (process|file|socket|registry|thread|module),
  key attrs (pid, path, hash, remote_ip, ...),
  storyline_id            # gán nhóm nhân-quả (ý tưởng Storyline)
  first_seen, last_seen

Edge (hành động):
  src_node, dst_node,
  action (exec|read|write|connect|inject|create|delete|load),
  ttp_id (nếu khớp), timestamp
```

Quan hệ nối vào graph **không chỉ cha-con**: process A inject B, A ghi file mà C thực thi... →
là **graph**, không phải tree.

### 4.2 TTP (đơn vị phát hiện)
```
TTP:
  id (vd T1003.001 LSASS dump),
  match_predicate,        # điều kiện trên 1 event để coi là "TTP này đã xảy ra"
  severity,
  tactic (kill-chain stage),
  enforceable: bool       # có phải điểm nghẽn chặn được không
```

---

## 5. Lõi phát hiện: State Machine tăng dần (thay cho graph matching inline)

Mỗi **storyline** mang một (hoặc nhiều) **automaton** biểu diễn một mẫu tấn công. Mỗi event
làm automaton chuyển trạng thái với chi phí **O(1)** — đây là điểm khác HOLMES gốc (correlate
trên đồ thị info-flow, chấp nhận độ trễ) và là lý do đủ nhanh cho inline.

### 5.1 Biểu diễn một mẫu tấn công
```yaml
pattern: ransomware_fast_encrypt
tactic_sequence:            # thứ tự kill-chain
  - stage: execution
    ttp: T1059            # command/script interpreter
  - stage: defense_evasion
    ttp: T1490            # inhibit system recovery (vssadmin delete shadows)
    enforceable: true
  - stage: impact
    ttp: T1486            # data encrypted for impact (ghi hàng loạt + đổi entropy)
    enforceable: true     # ← ĐIỂM CHẶN
window: 60s
scope: same_storyline     # các bước phải cùng chuỗi nhân-quả
block_at: T1486           # gate hành động enforcing cuối
```

### 5.2 Vòng đời automaton
```
[S0 idle]
   │  event khớp bước 1 (cùng storyline, trong window)
   ▼
[S1] ── event khớp bước 2 ──► [S2] ── event chạm bước enforceable ──► [DECISION]
   │                                                                     │
   │ hết window / event phá vỡ chuỗi                                     ▼
   ▼                                                          score ≥ ngưỡng?
[expire]                                                       ├─ có → DENY (chặn hành động)
                                                               └─ không → allow + nâng nghi ngờ
```

### 5.3 Hai tầng quyết định
- **Tầng single-event inline (nhanh, đồng bộ)**: technique đủ độc để chặn ngay với 1 event
  (đọc bộ nhớ LSASS, `vssadmin delete shadows`, tạo WMI persistence...). Kernel chặn thẳng,
  không cần đợi userland.
- **Tầng correlation nền (stateful)**: automata tiến theo từng TTP; khi state = độc hại,
  đẩy verdict xuống kernel để **gate hành động enforcing kế tiếp** của storyline đó.

---

## 6. Chấm điểm & policy (tư duy HOLMES/RapSheet)

- **Kill-chain scoring**: chuỗi TTP càng phủ nhiều tactic theo đúng thứ tự → điểm càng cao
  (giống HOLMES nối info-flow theo giai đoạn APT).
- **Neo vào signal hiếm** (ý tưởng RapSheet/POIROT): ưu tiên mở rộng quanh node/TTP hiếm để
  thu hẹp vùng cần đánh giá, tránh nổ tổ hợp.
- **Ngưỡng chặn > ngưỡng cảnh báo**: chỉ deny khi điểm rất cao và (ưu tiên) chạm đúng bước
  `enforceable`.

```
verdict = f(kill_chain_coverage, ttp_severity, rarity, storyline_confidence)
if verdict.block and event.enforceable:  DENY
elif verdict.alert:                       ALERT (log storyline + graph)
else:                                     ALLOW
```

---

## 7. Cảnh báo vận hành (inline khác hẳn detection)

| Rủi ro | Xử lý |
|---|---|
| **False positive = chặn nhầm** phần mềm hợp lệ, có thể treo hệ thống | Ngưỡng bảo thủ; whitelist; chế độ audit trước khi bật enforce |
| **Fail-open vs fail-closed** khi bộ não userland chết/chậm | Quyết định rõ chính sách; mặc định fail-open cho ổn định |
| **Latency là ngân sách cứng** trên đường inline | Mọi thao tác không bounded → đẩy sang tầng nền |
| **Correlation xuyên nhiều host** (lateral movement) | Không làm inline được — đẩy lên backend |
| **Kẻ tấn công né bằng chuỗi chậm** (dưới window) | Window thích ứng + trạng thái bền lâu cho technique nhạy cảm |

---

## 8. Vì sao không dùng nguyên POIROT / RapSheet làm lõi

- **POIROT**: graph alignment (subgraph isomorphism ~ NP-hard) + cần query graph từ CTI có sẵn +
  chạy offline. → Bất khả thi inline; chỉ bắt cái đã biết. Có thể dùng **offline** cho threat hunting.
- **RapSheet**: correlate trên **alert do EDR khác sinh ra**, là lớp triage/giảm false-alarm +
  nén log. → Không phải detector gốc, không tự chặn. Mượn ý tưởng **neo vào signal hiếm**.
- **HOLMES**: mô hình event→TTP→kill-chain đúng nhất với pipeline này, nhưng phải **tái cấu trúc**
  từ correlation graph (chậm) sang **automata tăng dần** để chạy inline.

---

## 9. Lộ trình prototype

1. **Sensor tối thiểu**: eBPF thu `exec`, `open/write` file, `connect` mạng, thread injection.
2. **Bảng technique-of-interest** nạp xuống kernel; gắn `candidate_ttp_id`.
3. **Userland daemon**: normalize + gán `storyline_id` (causality) + dựng graph in-memory.
4. **Một automaton mẫu** (ví dụ ransomware ở §5.1) + logic window/scope.
5. **Đường verdict**: userland → eBPF map → `bpf_lsm` deny ở bước `T1486`.
6. **Chế độ audit-only** trước, đo false positive, rồi mới bật enforce.
7. **Benchmark**: chạy trên **DARPA Transparent Computing dataset** (offline) + red-team thủ công.

---

## 10. Tham chiếu

- **HOLMES** (S&P 2019) — real-time APT detection qua correlate info-flow theo TTP/kill-chain.
- **POIROT** (CCS 2019) — threat hunting bằng inexact graph alignment với query graph từ CTI.
- **RapSheet** (S&P 2020) — Tactical Provenance Graph, triage & giảm false-alarm trên alert EDR.
- **Provenance IDS học sâu**: StreamSpot, Unicorn, ThreaTrace, Flash, Kairos (GNN) — lớp bổ sung
  bắt tấn công chưa biết.
- **MITRE ATT&CK** — khung tactic/technique để định nghĩa TTP và automata.
- **DARPA Transparent Computing dataset** — benchmark chuẩn cho provenance-based IDS.
- Cơ chế thực thi: **eBPF LSM (`bpf_lsm`)** (Linux); **minifilter / ObRegisterCallbacks** (Windows).
