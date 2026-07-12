# edr-engine — endpoint–backend split core

Prototype hiện thực thuật toán trong [`../engine.md`](../engine.md): **endpoint** nhanh/nhẹ/chính
xác chặn inline, **backend** giữ đồ thị forensic đầy đủ và dựng lại toàn bộ chuỗi khi có block.
Crate tự chứa, zero phụ thuộc ngoài; model event/pattern/rules/dataset là hạ tầng dùng chung mang
theo từ nguyên mẫu gốc (nay lưu ở [`../bak/engine.md`](../bak/engine.md)).

## Chạy

```bash
cargo run --bin edr-replay -- datasets/ransomware.evt
cargo run --bin edr-replay -- datasets/lsass_dump.evt rules/lsass_dump.rules
cargo test
```

Replay in: bảng verdict/quyết định từng event, **các storyline backend dựng lại tại mỗi block**
(bước bị chặn đánh dấu `*** BLOCKED ***`), log endpoint, và thống kê
`ACTIVE / storylines / shipped_events / shipped_blocks / swept`.

## Bản đồ code ↔ thiết kế (`../engine.md`)

| Thành phần | File | Mục trong doc |
|---|---|---|
| Model dùng chung: event / pattern / rules / dataset | `event.rs`, `pattern.rs`, `rules.rs`, `dataset.rs` | (bak/engine.md §0–§5) |
| Entity lean, storyline = tập nhỏ, không DSU | `endpoint.rs` (`Entity`, `Storyline`, `link/merge`) | §2, §5 |
| Bất biến working-set (refcount ∨ cửa sổ W) + sweep | `endpoint.rs` (`gc_and_sweep`) | §3 |
| Ship-and-forget (không giữ cạnh) | `endpoint.rs` (`on_event` → `outbox`) | §0, §4 |
| Định tuyến qua storyline + BINDING theo identity | `endpoint.rs` (`advance`, `try_commit` với `bound_ids: NodeKey`) | §5, §6 |
| GC theo `seg_window` (nhả refcount) | `endpoint.rs` (`automaton_dead`) | §6.4 |
| Arm cục bộ + DENY (arm theo identity) | `endpoint.rs` (`rescore_and_emit`, `kernel_arm`) | §7, §9 |
| Đồ thị forensic đầy đủ + dựng chuỗi khi block | `backend.rs` (`Backend`, `trace_chain`, `render_chain`) | §8 |
| Kênh ship endpoint→backend | `wire.rs` (`WireEvent`, `BlockReport`) | §2, §4 |
| Nối hai phía | `lib.rs` (`Pipeline::feed`) | §1 |

## Ghi chú phạm vi

- **Endpoint đứng một mình** cho lớp chặn hành-động-đầu-tiên trong cửa sổ (ransomware/LSASS ở đây
  đều chặn cục bộ, không round-trip). Backend là *phần cộng thêm*: nó truy vết và hiển thị chuỗi.
- **Chưa hiện thực** (đúng như doc ghi là hạng mục riêng): kênh backend→endpoint *arm ngược* có ký
  (§9 mô tả `ArmDirective` ký/seq/TTL), stitch xuyên host, và sensor kernel thật. Ở prototype này
  "wire" là hàng đợi trong tiến trình, "kernel" là bảng arm trong `Endpoint`.
- Hành vi phát hiện: DENY tại write mã hoá đầu tiên, dropper chỉ SUSPECT, "ghi X chạy Y" không
  false-positive, thứ tự nhóm giữa đảo vẫn chặn, LSASS chặn tại read — 7 test hành vi trong
  `tests/eb.rs`.
