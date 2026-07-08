# edr-engine — Detection core (Rust prototype)

Triển khai **lõi phát hiện userland** của engine EDR inline-prevention, đúng theo thuật toán
trong [`../engine.md`](../engine.md). Đây là "bộ não" độc lập nền tảng; kernel sensor
(Windows minifilter / `PsSetCreateProcessNotifyRoutineEx` / `ObRegisterCallbacks`; Linux
`bpf_lsm`) nằm ngoài phạm vi bản prototype này — ta kiểm chứng **thuật toán** bằng cách replay
một luồng event offline (chế độ audit).

**Zero dependency** — build offline, hot-path dễ audit.

## Chạy

```bash
cargo run --bin edr-replay -- datasets/ransomware.evt   # replay + verdict từng event
cargo test                                              # 4 test hành vi
```

## Bản đồ code ↔ engine.md

| File | Vai trò | Mục engine.md |
|---|---|---|
| `src/event.rs` | Model event; **node key = FileId/(pid,start), không phải path** | §0, §2 |
| `src/pattern.rs` | Cấu trúc mẫu = **precedence DAG** (bitmask/prereq/OR-slot/seg_window/binding) — chỉ struct, không hardcode mẫu | §5.1 |
| `src/rules.rs` | **Loader bộ rule ngoài**: metadata TTP, tagger (predicate closed-set), parser rule file; hàm `tag`/`meta` | §4, §6 |
| `src/lib.rs` | Pipeline: RESOLVE_NODE, UNIFY_STORYLINE (DSU), ADVANCE, scoring, verdict, **kernel ARM** | §1–§6, §8 |
| `src/dataset.rs` | Parser `.evt` (không serde) | — |
| `src/main.rs` | Công cụ replay audit-mode (nhận tùy chọn file rule) | §9 lộ trình |
| `rules/*.rules` | **Bộ rule khai báo ngoài** — thêm/sửa mẫu KHÔNG build lại | §5 |

## Bộ rule tách rời (không build lại khi thêm mẫu)

Rule sống trong `rules/*.rules` (cú pháp ở đầu `src/rules.rs`), nạp lúc chạy:
- `rules/builtin.rules` — bộ mặc định (nhúng sẵn, dùng khi không truyền file).
- `rules/lsass_dump.rules` — ví dụ **mẫu mới thêm 100% bằng data**: credential dumping (T1003)
  chặn thẳng khi đọc bộ nhớ LSASS. Chạy:
  `cargo run --bin edr-replay -- datasets/lsass_dump.evt rules/lsass_dump.rules` → **DENY** mà
  binary không hề build lại.

Ba directive: `ttp` (metadata tactic/severity/rarity), `tagger` (raw event → TTP, tập điều kiện
đóng), `pattern`+`step` (DAG: bit/prereq/seg_window/enforceable/bind/block). Tagger dùng **closed-set
predicate** (không phải ngôn ngữ biểu thức) — đủ diễn đạt technique mà vẫn bounded; thêm *dạng*
predicate mới vẫn cần code, đúng thiết kế vì tagger là lớp platform-specific (engine.md §4).

## Kịch bản dataset & kết quả kỳ vọng

| Dataset | Ý nghĩa | Kết quả |
|---|---|---|
| `ransomware.evt` | T1059 → {T1083, T1490} → T1486 | **DENY** ngay tại write mã hoá đầu tiên (storyline đã *armed* sau vssadmin) |
| `ransomware_reordered.evt` | Nhóm giữa đảo thứ tự (T1490 trước T1083) | **DENY** — partial-order, thứ tự chỉ là thưởng |
| `benign_installer_write_exec_same.evt` | Ghi X rồi chạy **đúng X** (installer/updater) | **ALLOW**, chỉ `SUSPECT` — match ≠ chặn |
| `benign_write_exec_different.evt` | Ghi X rồi chạy **Y khác** | **ALLOW**, dropper **không** match (binding theo FileId chặn FP) |

Hai dataset benign chính là câu trả lời cho câu hỏi false-positive: binding **theo identity file**
khiến "ghi X, chạy Y" không kích hoạt mẫu dropper, còn "ghi X, chạy X" tuy khớp mẫu nhưng điểm
thấp nên chỉ cảnh báo, không chặn nhầm.

## Chưa có (bước tiếp theo)

- Sensor thật (minifilter/eBPF) + đường verdict xuống kernel; hiện `kernel_arm` là mô phỏng.
- ~~Schema khai báo pattern động~~ ✅ đã tách ra `rules/*.rules` + loader runtime.
- Nhiều mẫu ATT&CK hơn (lateral movement, persistence…) — giờ chỉ cần thêm vào file rule.
- Tách tagger theo nền tảng (`platform/windows.rs`, `platform/linux.rs`) cho đa nền tảng.
- Benchmark trên DARPA TC + đo false-positive baseline trước khi bật enforce.
