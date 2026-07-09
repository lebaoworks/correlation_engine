# Session Context — EDR Inline Behavioral Prevention Engine

> **Mục đích file này:** lưu toàn bộ ngữ cảnh cuộc trao đổi để tiếp tục session trong VS Code
> extension mà không mất mạch. Đọc file này trước, rồi mở 2 file thiết kế bên dưới.
> Ngày: 2026-07-07. Ngôn ngữ làm việc: tiếng Việt.

---

## 0. Cách tiếp tục (đọc trước)

1. Đọc file này để nắm quyết định & trạng thái.
2. Mở `engine.md` — thuật toán lõi phát hiện (đã hoàn chỉnh, mới nhất).
3. Mở `edr-inline-detection-design.md` — thiết kế kiến trúc tổng thể.
4. Chọn một trong "Việc tiếp theo" (§6) để làm.

---

## 1. Bài toán người dùng đang xây

Một **engine EDR chạy trên endpoint** với các yêu cầu:
- Thu **telemetry ở kernel**, **lọc sẵn** event có giá trị theo **MITRE ATT&CK technique** người dùng muốn bắt.
- **Correlate nhiều event** thành chuỗi tấn công (nhiều TTP).
- **Phát hiện INLINE để NGĂN CHẶN (block/prevent)** — không chỉ cảnh báo.
- Chạy on-endpoint, real-time, chịu ràng buộc latency để chặn được syscall/thao tác.

## 2. Bối cảnh nghiên cứu đã thảo luận

So sánh 3 hệ provenance-based detection kinh điển:
- **HOLMES** (S&P 2019): real-time, map event→TTP→correlate theo kill-chain. **← mô hình tư duy được chọn.**
- **POIROT** (CCS 2019): threat hunting offline bằng inexact graph alignment (subgraph matching ~ NP-hard). **Loại khỏi lõi** (không inline được, chỉ bắt cái đã biết). Có thể dùng offline cho hunting.
- **RapSheet** (S&P 2020): correlate trên **alert do EDR sinh ra**, lớp triage/giảm false-alarm. **Không phải detector gốc**; mượn ý tưởng "neo vào signal hiếm".

Cũng nhắc: SentinelOne **Storyline** (causality graph on-agent + gán storyline-id), CrowdStrike **IOA** (stateful stream matching theo mẫu hành vi, correlate diện rộng đẩy lên Threat Graph cloud). Hệ học sâu bổ sung: Kairos/Flash/ThreaTrace (GNN).

## 3. Quyết định kiến trúc đã CHỐT

1. **Kernel = cảm biến + điểm thực thi; Userland = bộ não correlation stateful.** Không nhét correlation graph vào kernel.
2. **Mô hình phát hiện theo HOLMES** (event→TTP→kill-chain), **nhưng** thay correlation-graph (chậm) bằng **máy trạng thái tăng dần O(1)**.
3. **Mâu thuẫn lõi:** correlation cần thời gian, chặn phải quyết định ngay. **Giải:** chặn ở **"điểm nghẽn" / hành động enforcing kế tiếp** (không hồi tố) + trạng thái **"armed"** đẩy cờ xuống kernel để kernel tự deny khi event enforcing tới.
4. **Inline path KHÔNG được làm subgraph matching** (NP-hard). Dùng automata bitmask O(1).
5. **Hai tầng quyết định:** single-event nguy hiểm (LSASS read, `vssadmin delete shadows`) chặn thẳng trong kernel; chuỗi nhiều bước dùng correlation nền + armed.
6. **Enforcement cơ chế:** Linux = `bpf_lsm` trả `-EPERM`; Windows = minifilter / `ObRegisterCallbacks` / pre-create callbacks.
7. **Chống dependency explosion:** chỉ cạnh **causal** (exec/inject/write/create/dup) mới hợp nhất storyline; read/connect/open chỉ ghi cạnh.

## 4. Điểm mạnh nhất đã phát triển sâu — Partial-Order Matching (LÕI)

Người dùng hỏi sâu về việc **thứ tự bước KHÔNG cố định**. Kết luận & đã implement vào `engine.md` §5:

- Không dùng FSM tuyến tính (nổ n! hoán vị). Dùng **precedence-mask trên DAG**:
  - Tiến độ = **`completed_mask` (bitset)**, không phải `cur_stage`.
  - `prereq_mask[step]` mã hoá thứ tự bộ phận. Step enable ⟺ `(prereq_mask & completed_mask) == prereq_mask`.
  - Accept ⟺ `(completed_mask & required_mask) == required_mask`. **O(1)/event** (bitwise).
- Biểu diễn được: nhóm tự do thứ tự, mốc (milestone) giữa các nhóm, chuỗi tuỳ ý dài
  `G0 → A → G1 → E → G2 → …`. "x phải đầu/cuối" và "nhóm tự do" đều rơi ra từ `prereq_mask`.
- **OR-slot:** một step thoả bởi bất kỳ TTP nào trong tập (biến thể công cụ).
- **Window theo từng ĐOẠN** (`seg_window`), không dùng window toàn cục — để chuỗi dài không bị deadline quá chặt.
- **Thứ tự = THƯỞNG (`order_bonus`), không phải điều kiện.** `θ_block` đặt cao hơn cho mẫu partial-order.
- **Giới hạn thật:** độ phức tạp thứ tự (DAG bao nhiêu tầng) là miễn phí; thứ *đắt* là **variable binding + thứ tự tự do đồng thời** → tiệm cận subgraph matching. Giữ bounded bằng: neo TTP hiếm, `scope=same_storyline`, trần binding, binding mơ hồ thì giảm confidence (không vét cạn).

Ví dụ chuẩn đã đưa vào doc: `{P,Q} → A → {B,C,D} → E → {F,G,H}` (§5.7) và ransomware có nhóm giữa tự do `{T1490, T1083}` (§10).

## 5. Files đã tạo (trong /mnt/c/Users/baosa)

| File | Nội dung | Trạng thái |
|---|---|---|
| `engine.md` | **Thuật toán lõi phát hiện** chi tiết (pseudocode): §0 cấu trúc dữ liệu, §1 vòng lặp chính, §2 RESOLVE_NODE (**node key = FileId/(dev,inode), không phải path**), §3 UNIFY_STORYLINE (DSU), §4 TAG_TTP, **§5 partial-order matching (bitmask/precedence/OR-slot/seg_window/binding; §5.8 có ví dụ dropper write→exec chống FP "ghi X chạy Y")**, §6 kill-chain scoring, §7 chống nổ tài nguyên, §8 biên kernel + **§8.1 bảng hook Windows/Linux theo `op` (deny được hay chỉ notify)**, §9 độ phức tạp (O(1)/event), §10 ví dụ ransomware | **Hoàn chỉnh, nhất quán** |
| `edr-inline-detection-design.md` | Thiết kế kiến trúc tổng thể: nguyên tắc, sơ đồ kernel/userland, telemetry (eBPF/ETW), mô hình dữ liệu, state machine, scoring, cảnh báo vận hành, lộ trình prototype, tham chiếu | Hoàn chỉnh (viết trước §5 chi tiết; state-machine phần này là bản tóm cũ hơn engine.md) |

> Lưu ý: `engine.md` §5 là bản **mới nhất & chi tiết nhất** của lõi. `edr-inline-detection-design.md` §5 chỉ là bản tóm — nếu chỉnh sửa lấy `engine.md` làm chuẩn.

## 5b. Prototype Rust ĐÃ LÀM (thư mục `engine/`)

Triển khai **lõi phát hiện userland** bằng Rust (zero-dependency) trong `/mnt/e/Desktop/engine/engine/`:
- `src/event.rs` (node key = FileId/(pid,start), không path), `src/pattern.rs` (cấu trúc precedence DAG:
  bitmask/prereq/OR-slot/seg_window/binding — không hardcode mẫu), `src/rules.rs` (**loader bộ rule
  ngoài** + tagger closed-set + scoring meta), `src/lib.rs` (pipeline RESOLVE/UNIFY-DSU/ADVANCE/scoring/
  verdict + mô phỏng kernel ARM), `src/dataset.rs` (parser `.evt`), `src/main.rs` (replay audit-mode,
  nhận tùy chọn file rule). Chi tiết map code↔engine.md trong `engine/README.md`.
- **Bộ rule ĐÃ TÁCH RA** `rules/*.rules` (nạp runtime, thêm mẫu KHÔNG build lại): `rules/builtin.rules`
  (mặc định, nhúng sẵn) + `rules/lsass_dump.rules` (ví dụ mẫu T1003 thêm 100% bằng data → DENY).
  Ba directive: `ttp`/`tagger`/`pattern`+`step`. Cú pháp ở đầu `src/rules.rs`.
- **4 dataset** trong `engine/datasets/` + **4 test pass** (`cargo test`):
  - `ransomware.evt` → DENY tại write mã hoá đầu (armed sau vssadmin).
  - `ransomware_reordered.evt` → vẫn DENY dù đảo thứ tự nhóm giữa (partial-order).
  - `benign_installer_write_exec_same.evt` (ghi X chạy X) → chỉ SUSPECT, ALLOW (match ≠ chặn).
  - `benign_write_exec_different.evt` (ghi X chạy Y) → dropper KHÔNG match — trả lời câu hỏi FP:
    binding theo **file identity** chặn false positive.
- Chạy: `cd engine && cargo run --bin edr-replay -- datasets/<x>.evt` ; test: `cargo test`.

## 5c. Tài liệu bổ trợ

- `engine_state_optimization.md` — 6 hướng **giới hạn bộ nhớ mà vẫn bắt tối đa** (viết chi tiết):
  (1) tách detection-state/forensic-graph + collapse/rehydrate theo identity, (2) giữ-theo-nghi-ngờ
  thay LRU thuần, (3) ngân sách theo nguồn/hub chống evict-as-evasion, (4) sketch xác suất
  (HLL/CMS/Bloom) cho predicate, (5) spill sketch ra đĩa (sống qua reboot), (6) admission theo rarity.
  Kèm stack đề xuất (1+2+3), bảng đánh đổi, ánh xạ vào code prototype, cách kiểm chứng (flood /
  low-and-slow dataset). Liên kết từ engine.md §7.

## 6. Việc tiếp theo (chưa làm — người dùng có thể chọn)

- [x] **Schema khai báo pattern/TTP** — ĐÃ LÀM: tách ra `rules/*.rules` + loader runtime (định dạng
      tự viết, zero-dep; không dùng YAML để khỏi thêm crate). Còn: thêm nhiều mẫu ATT&CK thật hơn.
- [ ] **Prototype code** một lát cắt: eBPF sensor (exec/open/write/connect) → daemon userland → automaton → `bpf_lsm` deny. Ngôn ngữ chưa chốt (gợi ý: Rust/C cho daemon, C cho eBPF, hoặc Go + cilium/ebpf).
- [ ] Đồng bộ `edr-inline-detection-design.md` §5 với `engine.md` (hoặc gộp 1 file).
- [ ] Chi tiết cơ chế **PUSH_KERNEL_ARM** (định dạng eBPF map, vòng đời cờ armed, hết hạn).
- [ ] Kế hoạch **benchmark**: DARPA Transparent Computing dataset + red-team thủ công; đo false positive ở chế độ audit-only trước khi bật enforce.
- [ ] Lớp bổ sung learning-based (GNN: Kairos/Flash) cho tấn công chưa biết.

## 7. Ràng buộc & quy ước cần nhớ

- Trả lời bằng **tiếng Việt**.
- Thư mục làm việc: `/mnt/e/Desktop/engine` (KHÔNG phải git repo; đã chuyển từ `/mnt/c/Users/baosa`).
- **Mọi file (kể cả ghi chú/ngữ cảnh) ghi trong workspace này, không ghi ra ngoài.**
- Engine phải chạy **cả Windows và Linux**; giai đoạn thử nghiệm **Windows trước** (quyết định 2026-07-07) → ưu tiên minifilter / `PsSetCreateProcessNotifyRoutineEx` / `ObRegisterCallbacks`; chuẩn hoá node key kiểu Windows (path case-insensitive, FileId).
- Mọi thao tác trên đường inline phải **bounded / O(1)**; không NP-hard trên hot path.
- Prevention khác detection: false positive = **chặn nhầm** → ngưỡng bảo thủ, chạy audit-only trước, cân nhắc fail-open.
- Đừng dùng POIROT/RapSheet làm lõi; HOLMES là mô hình tư duy nhưng phải tái cấu trúc cho inline.
