# edr-backend-service — backend forensic nhận event từ endpoint service

Console app: lắng nghe TCP, nhận **wire stream** theo contract `proto/wire.proto` (codec
`edr-proto`) từ `edr-endpoint-service`, dựng **full provenance graph** (`edr_engine::Backend`
— không evict), in từng event ingest.
Khi endpoint chặn, nó bắn kèm một **`BlockReport` (alert)**; backend rà soát graph, dựng lại
toàn bộ STORYLINE dẫn tới hành vi bị chặn và hiển thị cho SOC — việc endpoint không tự làm
được vì endpoint không giữ edge nào.

## Kiến trúc 2 thread (chế độ `--listen`)

- **Thread nhận**: accept + đọc socket + ingest vào graph + đẩy output vào hàng đợi
  bounded. **Không bao giờ chờ console** → console chậm không làm nghẽn vòng đọc socket
  (đó chính là nguyên nhân buffer đầy → loopback bị reset 10053/10054 dưới flood).
- **Thread in**: rút hàng đợi → ghi **stdout** có buffer, gộp flush theo cụm.
- Hàng đợi đầy (console không theo kịp) → **bỏ dòng console** (graph vẫn ingest đủ), không block.
- **stdout = chỉ luồng event** (thread in); **stderr = banner/kết nối/summary/lỗi** (thread nhận).
  Nhờ vậy có thể `> events.log` để bắt riêng event, xem trạng thái live trên stderr.

## Chạy

```bash
cargo run --bin edr-backend-service                      # lắng nghe 127.0.0.1:7171
cargo run --bin edr-backend-service -- --listen 0.0.0.0:7171
cargo run --bin edr-backend-service -- --file wire.bin   # replay wire stream đã bắt
cargo run --bin edr-backend-service -- --stdin
cargo test
```

Demo hai console (từ gốc repo, workspace):

```bash
# console 1
cargo run --bin edr-backend-service
# console 2 — kịch bản LSASS-dump dựng sẵn (endpoint mặc định ship 127.0.0.1:7171)
cargo run --bin edr-endpoint-service -- --demo
```

Console backend in:

```
  seq=1  sid=0  ts=2000  exec  proc 100.500  -> proc 800.2000
  seq=2  sid=0  ts=2100  read  proc 800.2000 -> proc 50.900   [T1003]

⚠ ALERT seq=3 — endpoint DENY  pattern=lsass_credential_dump  score=7.4 ... → rà soát graph...
=== STORYLINE (blocked) ...
  ts=2000  exec  proc 100.500            -> mimikatz.exe (800.2000)
  ts=2100  read  mimikatz.exe (800.2000) .. proc 50.900   [T1003]  *** BLOCKED ***
```

## Giao thức (contract: `proto/wire.proto`, codec: crate `edr-proto`)

- Payload là message protobuf `edr.wire.v1.Wire` (oneof `WireEvent` | `BlockReport`);
  frame trên TCP = `Len:u32le (chỉ payload) ++ payload` — xem `proto/README.md`.
- Graph **sống qua nhiều kết nối**: endpoint reconnect vẫn ghép tiếp vào lịch sử cũ.

## Kế tiếp

Xem `docs/todo.md` mục *Thiết kế backend*: tầng phát hiện chủ động trên graph (kill-chain
correlation kiểu HOLMES/RapSheet trên field `ttps`, NoDoze frequency scoring, DEPIMPACT
weighting cho truy vết, GNN giai đoạn sau) để backend tự cảnh báo ngoài rule của endpoint.
