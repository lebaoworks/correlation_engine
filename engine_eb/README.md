# edr-engine-eb — endpoint–backend split core

Prototype hiện thực thuật toán trong [`../engine_endpoint_backend.md`](../engine_endpoint_backend.md):
**endpoint** nhanh/nhẹ/chính xác chặn inline, **backend** giữ đồ thị forensic đầy đủ và dựng lại
toàn bộ chuỗi khi có block. Tái dùng model event/pattern/rules/dataset của crate gốc
[`../engine`](../engine) (path dependency `edr-engine`), không thêm phụ thuộc ngoài nào.

## Chạy

```bash
cargo run --bin edr-eb-replay -- ../engine/datasets/ransomware.evt
cargo run --bin edr-eb-replay -- ../engine/datasets/lsass_dump.evt ../engine/rules/lsass_dump.rules
cargo test
```

Replay in: bảng verdict/quyết định từng event, **các storyline backend dựng lại tại mỗi block**
(bước bị chặn đánh dấu `*** BLOCKED ***`), log endpoint, và thống kê
`ACTIVE / storylines / shipped_events / shipped_blocks / swept`.

## Bản đồ code ↔ thiết kế

| Thành phần | File | Mục trong doc |
|---|---|---|
| Entity lean, storyline = tập nhỏ, không DSU | `endpoint.rs` (`Entity`, `Storyline`, `link/merge`) | §2, §5 |
| Bất biến working-set (refcount ∨ cửa sổ W) + sweep | `endpoint.rs` (`gc_and_sweep`) | §3 |
| Ship-and-forget (không giữ cạnh) | `endpoint.rs` (`on_event` → `outbox`) | §0, §4 |
| Định tuyến qua storyline + BINDING theo identity | `endpoint.rs` (`advance`, `try_commit` với `bound_ids: NodeKey`) | §5, §6 |
| GC theo `seg_window` (nhả refcount) | `endpoint.rs` (`automaton_dead`) | §6(c) |
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
- Hành vi phát hiện khớp crate gốc: DENY tại write mã hoá đầu tiên, dropper chỉ SUSPECT,
  "ghi X chạy Y" không false-positive, thứ tự nhóm giữa đảo vẫn chặn.
