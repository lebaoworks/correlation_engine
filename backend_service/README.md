# edr-backend-service — backend forensic nhận event từ endpoint service

Console app: lắng nghe TCP, nhận **wire stream** theo contract `proto/wire.proto` (codec
`edr-proto`) từ `edr-endpoint-service`, dựng **full provenance graph** (`edr_engine::Backend`
— không evict), in từng event ingest.
Khi endpoint chặn, nó bắn kèm một **`BlockReport` (alert)**; backend rà soát graph, dựng lại
toàn bộ STORYLINE dẫn tới hành vi bị chặn và hiển thị cho SOC — việc endpoint không tự làm
được vì endpoint không giữ edge nào.

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
# console 2 — kịch bản LSASS-dump dựng sẵn, ship qua TCP
cargo run --bin edr-endpoint-service -- --backend 127.0.0.1:7171
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
