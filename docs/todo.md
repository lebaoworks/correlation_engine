# TODO

## Thiết kế backend — provenance-graph analytics trên server

Hiện trạng: backend (`engine/src/backend.rs`) giữ **full provenance graph** (không evict) nhưng
hoàn toàn **thụ động** — chỉ truy vết và render chuỗi khi endpoint gửi `BlockReport`. Mục tiêu:
backend tự phát hiện bất thường **ngoài** những rule đã apply cho endpoint, theo các kỹ thuật
provenance-graph hiện đại, và cảnh báo độc lập.

Lợi thế sẵn có: endpoint đã ship kèm `ttps: Vec<String>` trong mỗi `WireEvent` (TTP đã xác nhận),
nên backend không phải chạy lại tagger; và chỉ server mới nhìn thấy **tần suất toàn fleet**.

### Giai đoạn 0 — tách backend thành service riêng (transport thật)

Bố cục workspace: `engine/` (lõi phát hiện) · `proto/` (contract) · `endpoint_service/` ·
`backend_service/` — 4 crate, build/test chung bằng `cargo test` ở gốc.

- [x] `proto/` — contract trao đổi giữa hai service: **`wire.proto`** (Protocol Buffers,
      `edr.wire.v1`, nguồn sự thật) + crate `edr-proto`: types do **prost-build** sinh lúc
      build (`protoc` vendored, không phải cài), lớp convert `pb ⇄ edr_engine::wire` giữ
      engine zero-dep; frame TCP = `Len:u32le ++ payload`. Golden-byte test + cross-check
      bằng `protoc --decode`.
- [x] `backend_service/` — console app riêng: lắng nghe TCP, nhận stream `Wire` từ endpoint
      service, dựng graph (`edr_engine::Backend`), in từng event ingest; khi nhận `BlockReport`
      (alert) thì rà soát graph và hiển thị toàn bộ STORYLINE.
- [x] `endpoint_service/` (đổi tên từ `service/`): `edr-endpoint-service --backend <addr>` —
      ship outbox qua TCP thay vì chạy backend in-process (không có cờ thì giữ in-process).
- [ ] Reconnect/retry + buffer khi backend offline (hiện tại lỗi ghi socket chỉ log rồi bỏ).
- [ ] Nhiều endpoint đồng thời: mỗi kết nối một `endpoint_id`, namespace node key theo endpoint
      (multi-thread accept; hiện tại xử lý tuần tự từng kết nối).
- [ ] Persist graph xuống đĩa (append-only log + snapshot) để retro-hunt sau restart.

### Giai đoạn 1 — phát hiện ngoài rule endpoint (TTP correlation, kiểu HOLMES / RapSheet)

Đây là tầng giá trị/công sức tốt nhất vì dùng thẳng field `ttps` đã ship:

- [ ] **RapSheet-style kill-chain scoring**: mỗi component (DSU) tích luỹ tập TTP → tactic;
      alert khi một component đạt ≥N tactic *theo đúng thứ tự thời gian* kill-chain
      (initial-access → execution → credential-access → exfil), **kể cả khi endpoint chưa chặn
      gì** (mỗi TTP đơn lẻ dưới ngưỡng block của rule).
- [ ] **HOLMES-style HSG**: ánh xạ TTP → APT stage, threat score nhân theo số stage khác nhau
      nối với nhau bằng information flow trong graph; ngưỡng alert riêng của backend.
- [ ] Alert của backend đi ngược xuống endpoint dưới dạng arm-hint (đẩy rule/arm mới xuống
      sensor cho identity đang nghi vấn — nối vào cơ chế `ArmCmd` §9 sẵn có).

### Giai đoạn 2 — anomaly detection không cần rule (unsupervised)

- [ ] **NoDoze-style frequency scoring**: server đếm tần suất `(actor-image, op, object-class)`
      trên toàn fleet; event hiếm cộng anomaly score, lan truyền dọc path trong graph; alert
      khi path score vượt ngưỡng. (Cần bảng đếm persistent — làm sau persist ở giai đoạn 0.)
- [ ] **ProvDetector-style rare path**: trích các đường đi hiếm của mỗi process, embedding
      (doc2vec hoặc đơn giản hơn: tần suất n-gram path), phát hiện outlier → bắt LOLBins.
- [ ] GNN thế hệ mới (chọn 1 sau khi có dữ liệu baseline sạch): **FLASH** / **MAGIC**
      (chi phí thấp, 2024) hoặc **KAIROS** (temporal GNN, tự dựng attack summary graph).
      Yêu cầu: pipeline train offline, backend chỉ chạy inference.

### Giai đoạn 3 — threat hunting theo CTI (kiểu POIROT)

- [ ] Query graph từ báo cáo CTI → **alignment score** với provenance graph lịch sử
      (retro-hunt trên full graph mà chỉ backend có).
- [ ] Tự động trích query graph từ văn bản CTI (AttacKG / EXTRACTOR) — giai đoạn xa.

### Hạ tầng đồ thị (bắt buộc trước khi chạy quy mô thật)

- [ ] **Giảm graph bảo toàn nhân quả** (CPR): gộp edge lặp giữa cùng cặp node khi không đổi
      ngữ nghĩa; **NodeMerge** cho file read-only lúc khởi động; **LogGC** xoá node chết.
- [ ] **Node versioning** (chống dependency explosion): tách phiên bản node theo thời gian để
      backward trace không kéo cả hệ thống vào chuỗi.
- [ ] **DEPIMPACT-style edge weighting** cho `trace_chain()`: hiện tại lấy *mọi* edge trong
      component — sẽ nổ với dữ liệu thật; đánh trọng số (thời gian, fan-out, lượng dữ liệu)
      và chỉ giữ nhánh quan trọng quanh điểm chặn.
- [ ] **Execution partitioning** cho process hub (explorer/services): một `inject` vào hub
      hiện hàn hai component vĩnh viễn qua DSU — cần chia unit hoặc version hoá hub.

## Việc khác

- [ ] Driver chặn đồng bộ thật (reply buffer hoặc bảng arm trong kernel — xem
      `service/README.md` phần ⚠️).
- [ ] `FileId` thật từ sensor thay cho path token (`translate.rs`).
