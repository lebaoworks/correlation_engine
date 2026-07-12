# edr-proto — contract trao đổi endpoint-service ↔ backend-service

Nguồn sự thật của giao thức là **`wire.proto`** (Protocol Buffers, `package edr.wire.v1`):
`Wire = oneof { WireEvent | BlockReport }` — telemetry ship-and-forget và alert khi endpoint
chặn. Cả hai service đều phụ thuộc crate này, không service nào tự định nghĩa format.

Types Rust được **prost-build sinh lúc build** (`build.rs`; `protoc` đi kèm qua
`protoc-bin-vendored` — không phải cài gì). Crate này là nơi duy nhất trong workspace có
external dependency; engine core vẫn zero-dep vì lớp convert nằm ở đây:

```
edr_engine::wire::Wire  ⇄  pb::Wire (prost)  ⇄  bytes
```

Decode có validate những gì proto3 không tự ép được: oneof `Wire`/`NodeKey` phải được set,
`actor`/`object`/`event` phải có mặt, `Op` phải là giá trị hợp lệ khác `OP_UNSPECIFIED`.

Bytes trên socket là protobuf chuẩn, decode được bằng mọi toolchain:

```bash
# bỏ 4 byte frame prefix rồi decode payload
protoc --decode=edr.wire.v1.Wire proto/wire.proto < payload.bin
```

## Framing trên TCP

Message protobuf không tự phân định ranh giới trên stream, nên mỗi `Wire` được đóng khung
`Len:u32le (chỉ payload) ++ payload`. Prefix này nằm ngoài schema (ghi rõ trong wire.proto).

## API

```rust
edr_proto::encode_frame(&Wire) -> Vec<u8>                            // frame hoàn chỉnh cho stream
edr_proto::decode_frame(&[u8]) -> Result<Option<(Wire, usize)>, _>   // None = chờ thêm bytes
edr_proto::pb::*                                                      // types prost sinh, nếu cần trực tiếp
```

API công khai chỉ gồm cặp `frame` (payload protobuf + khung độ dài `u32le` cho TCP). Phần mã
hoá/giải mã payload trần là lớp trong, để private — mọi caller đều làm việc ở mức frame.

Map `attrs` được sinh thành `BTreeMap` (`build.rs`) để encoding **định danh** — cùng một
record luôn ra cùng bytes.

## Test

`tests/proto_codec.rs`: roundtrip mọi loại message/NodeKey, frame cắt vụn từng byte,
**golden-byte test** đối chiếu từng byte với wire-format protobuf tính tay, skip unknown
field (forward-compat), và từ chối payload sai (op ngoài enum, thiếu oneof). Đã
cross-check bằng chính `protoc --decode` (binary vendored).

## Quy tắc tiến hoá schema

- Chỉ **thêm field số mới**, không đổi nghĩa/kiểu field cũ, không tái sử dụng số đã xoá.
- Decoder hai phía skip unknown field, nên producer mới + consumer cũ vẫn chạy.
- Đổi ngữ nghĩa không tương thích → tăng package version (`edr.wire.v2`).
