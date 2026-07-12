# Tài liệu Yêu cầu Nghiệp vụ (BRD)
## Giải pháp EDR phòng-ngừa hành vi tại chỗ (inline behavioral prevention)

| | |
|---|---|
| **Sản phẩm** | Lõi EDR phòng-ngừa hành vi tấn công tại chỗ trên endpoint, kiến trúc hai phía endpoint–backend |
| **Phiên bản tài liệu** | 1.0 |
| **Ngày** | 2026-07-12 |
| **Trạng thái** | Bản thảo cho giai đoạn prototype |
| **Đối tượng đọc** | Lãnh đạo an ninh (CISO), quản lý SOC, đội ứng cứu sự cố, kỹ sư phát hiện, vận hành CNTT, mua sắm |
| **Tài liệu liên quan** | [SRS.md](SRS.md) — đặc tả yêu cầu hệ thống (chi tiết chức năng/kiểm chứng); [todo.md](todo.md) — lộ trình |

Tài liệu này mô tả **nhu cầu và mục tiêu nghiệp vụ** mà giải pháp phải đáp ứng, cùng phạm vi, bên
liên quan, tiêu chí thành công và rủi ro ở góc độ kinh doanh. Tài liệu **không** mô tả cách hiện
thực; yêu cầu hệ thống chi tiết nằm ở [SRS.md](SRS.md), mỗi yêu cầu nghiệp vụ (BR) dưới đây truy vết
xuống các yêu cầu hệ thống tương ứng.

---

## 1. Tóm tắt điều hành

Phần lớn EDR truyền thống thiên về **phát hiện sau sự việc**: chúng ghi nhận và cảnh báo, nhưng thiệt
hại (mã hoá dữ liệu, đánh cắp thông tin đăng nhập) thường đã xảy ra trước khi đội an ninh kịp phản
ứng. Giải pháp này đặt trọng tâm vào **phòng ngừa tại chỗ (inline prevention)**: chặn *hành vi* tấn
công ngay tại thời điểm nó sắp gây hại, trong cửa sổ thời gian rất ngắn, thay vì chỉ báo động về sau.

Kiến trúc chia hai phía để dung hoà hai mục tiêu vốn xung đột — **chặn nhanh** và **điều tra sâu**:
một phía **endpoint** nhẹ, chạy tại máy người dùng, ra quyết định chặn tức thời với chi phí thấp; một
phía **backend** tập trung, giữ toàn bộ dữ liệu để dựng lại **chuỗi tấn công** phục vụ điều tra và
cảnh báo nâng cao. Việc phát hiện dựa trên **mô hình TTP của MITRE ATT&CK** và có nền tảng học thuật
(HOLMES, POIROT, RapSheet), cho phép mô tả các chuỗi tấn công nhiều bước thay vì chỉ dấu hiệu đơn lẻ.

Kết quả kỳ vọng: giảm thiệt hại thực tế từ các cuộc tấn công phổ biến (ransomware, đánh cắp credential),
giữ trải nghiệm người dùng mượt (chi phí chặn chỉ dồn vào đúng điểm nguy hiểm), rút ngắn thời gian
điều tra sự cố, và cho phép đội phát hiện phản ứng nhanh với mối đe doạ mới **mà không phải tái triển
khai agent**.

---

## 2. Bối cảnh và vấn đề nghiệp vụ

**Bối cảnh.** Trên một máy endpoint, dòng sự kiện hệ thống (tiến trình, file, mạng) tích luỹ không
giới hạn theo thời gian. Dữ liệu đầy đủ này **cần cho điều tra**, nhưng việc chặn tức thời **không cần**
toàn bộ nó. Nhiều giải pháp gộp cả hai vào một nơi, dẫn tới hoặc nặng nề trên endpoint, hoặc chậm khi
ra quyết định chặn.

**Vấn đề nghiệp vụ cần giải quyết:**

| # | Vấn đề | Hệ quả kinh doanh |
|---|---|---|
| P1 | Phát hiện đến sau khi thiệt hại đã xảy ra | Mất dữ liệu, gián đoạn kinh doanh, chi phí khôi phục và tiền chuộc |
| P2 | Bảo vệ thời gian thực làm chậm máy người dùng | Giảm năng suất, người dùng tìm cách vô hiệu hoá bảo vệ |
| P3 | Cảnh báo rời rạc, nhiều dương-tính-giả | SOC quá tải, bỏ sót cảnh báo thật (alert fatigue) |
| P4 | Điều tra sự cố thủ công, chậm | Thời gian ứng cứu (MTTR) dài, kẻ tấn công có thêm thời gian |
| P5 | Thêm luật phát hiện mới đòi cập nhật/triển khai lại agent | Chậm phản ứng với mối đe doạ mới, cửa sổ rủi ro kéo dài |
| P6 | Khó tin cậy/khó kiểm toán phần lõi bảo vệ | Rào cản phê duyệt triển khai trong môi trường nhạy cảm |

---

## 3. Mục tiêu nghiệp vụ

| ID | Mục tiêu | Chỉ số định hướng |
|---|---|---|
| **OBJ-1** | **Ngăn chặn** (không chỉ phát hiện) các chuỗi tấn công phổ biến trước khi gây hại | Tỷ lệ chặn thành công tại/điểm-trước "điểm nghẽn" của các kịch bản đã biết |
| **OBJ-2** | Giữ chi phí hiệu năng trên endpoint ở mức không đáng kể | Độ trễ chỉ phát sinh ở đúng thao tác nguy hiểm; phần còn lại không bị đánh thuế |
| **OBJ-3** | Giảm tải và tăng độ tin cậy cảnh báo cho SOC | Tỷ lệ dương-tính-giả trên phần mềm lành tính phổ biến ở mức thấp |
| **OBJ-4** | Rút ngắn thời gian điều tra khi có sự cố | Chuỗi tấn công được dựng lại **tự động** ngay khi chặn |
| **OBJ-5** | Cho phép đội phát hiện phản ứng nhanh với mối đe doạ mới | Thêm/sửa luật phát hiện **không cần** biên dịch lại hay tái triển khai agent |
| **OBJ-6** | Tạo niềm tin để triển khai trong môi trường nhạy cảm | Phần lõi bảo vệ **kiểm toán được** và dựng được offline |
| **OBJ-7** | Sẵn sàng mở rộng ra quy mô đội máy (fleet) | Dữ liệu điều tra tập trung về một nơi cho nhiều endpoint |

---

## 4. Phạm vi

### 4.1 Trong phạm vi (giai đoạn hiện tại)
- Bảo vệ endpoint **Windows**: giám sát và ngăn chặn hành vi tiến trình, file, tạo luồng từ xa, và
  truy cập bộ nhớ tiến trình nhạy cảm.
- **Phòng ngừa tại chỗ**: ra quyết định cho phép/chặn ngay tại thời điểm thao tác.
- **Điều tra tập trung**: một dịch vụ backend thu nhận dữ liệu từ endpoint, giữ bức tranh đầy đủ, và
  **dựng lại toàn bộ chuỗi tấn công** để hiển thị cho đội an ninh khi có chặn.
- **Phát hiện theo luật**: mô tả TTP và các mẫu chuỗi tấn công bằng luật nạp từ ngoài.
- Bộ kịch bản mẫu tối thiểu: ransomware mã hoá nhanh, dropper (ghi rồi chạy), và đánh cắp thông tin
  đăng nhập từ tiến trình hệ thống (LSASS).

### 4.2 Ngoài phạm vi (giai đoạn hiện tại)
- Cảm biến cho nền tảng khác Windows (ví dụ Linux).
- Bảng điều khiển quản trị đa máy (multi-host console) và tương quan tấn công **xuyên nhiều endpoint**.
- Kênh điều khiển ngược **có chữ ký** để đẩy lệnh chặn từ backend xuống endpoint một cách xác thực.
- Cập nhật luật từ xa và lưu trữ bền vững dữ liệu điều tra qua các lần khởi động lại.
- Phát hiện bất thường chủ động trên backend ngoài bộ luật của endpoint (nằm trong lộ trình — xem
  [todo.md](todo.md)).

---

## 5. Bên liên quan

| Bên liên quan | Quan tâm chính | Vai trò |
|---|---|---|
| **Lãnh đạo an ninh (CISO)** | Giảm rủi ro vi phạm, chứng minh giá trị đầu tư | Nhà tài trợ, phê duyệt |
| **Quản lý SOC** | Giảm khối lượng cảnh báo, tăng chất lượng | Người thụ hưởng chính |
| **Nhà phân tích SOC / Đội ứng cứu sự cố** | Cảnh báo rõ ràng, bằng chứng chuỗi tấn công đầy đủ | Người dùng đầu-cuối |
| **Kỹ sư phát hiện (detection engineer)** | Thêm/sửa luật nhanh, an toàn | Người vận hành nội dung phát hiện |
| **Vận hành CNTT / Endpoint** | Ổn định, chi phí hiệu năng thấp | Người triển khai và bảo trì |
| **Người dùng cuối** | Máy không bị chậm, ít gián đoạn | Đối tượng chịu tác động |
| **Kiểm toán / Tuân thủ** | Khả năng kiểm chứng, bằng chứng điều tra | Người rà soát |
| **Mua sắm / Tài chính** | Chi phí sở hữu, rủi ro nhà cung cấp | Người quyết định ngân sách |

---

## 6. Yêu cầu nghiệp vụ

Mỗi yêu cầu nghiệp vụ (BR) phát biểu **điều doanh nghiệp cần**, không phải cách hệ thống làm; cột cuối
truy vết xuống nhóm yêu cầu hệ thống ở [SRS.md](SRS.md).

| ID | Yêu cầu nghiệp vụ | Đáp ứng mục tiêu | Truy vết SRS |
|---|---|---|---|
| **BR-1** | Giải pháp PHẢI **ngăn chặn** hành vi tấn công gây hại ngay tại thời điểm nó sắp xảy ra, không chỉ ghi nhận sau đó. | OBJ-1 | FR-D*, FR-S4 |
| **BR-2** | Việc chặn PHẢI diễn ra **kịp thời** trong khi bằng chứng của chuỗi tấn công còn hiệu lực, để chặn được đúng bước quyết định. | OBJ-1 | FR-P*, NFR-A1 |
| **BR-3** | Chi phí bảo vệ PHẢI **không làm chậm đáng kể** máy người dùng; độ trễ chỉ được phép rơi vào đúng thao tác nguy hiểm. | OBJ-2 | NFR-P1, NFR-P2 |
| **BR-4** | Hành vi lành tính phổ biến (trình cài đặt, trình cập nhật) **KHÔNG được** bị chặn nhầm. | OBJ-3 | FR-D5, FR-D6, NFR-A2 |
| **BR-5** | Khi có chặn, giải pháp PHẢI **tự động dựng lại toàn bộ chuỗi tấn công** và trình bày rõ ràng cho đội an ninh. | OBJ-4 | FR-B*, FR-BS* |
| **BR-6** | Đội phát hiện PHẢI **thêm/sửa được luật phát hiện** (TTP, mẫu chuỗi) mà **không cần** biên dịch lại hay tái triển khai agent. | OBJ-5 | FR-P6, IR-5 |
| **BR-7** | Việc phát hiện PHẢI dựa trên **khung TTP chuẩn ngành (MITRE ATT&CK)** để dễ ánh xạ với tri thức mối đe doạ. | OBJ-5 | FR-T*, FR-P* |
| **BR-8** | Phần lõi bảo vệ PHẢI **kiểm toán được** và **dựng được offline** để tạo niềm tin triển khai. | OBJ-6 | NFR-M3, DR-1 |
| **BR-9** | Dữ liệu điều tra PHẢI được **tập trung** để phục vụ nhiều endpoint và điều tra sau này. | OBJ-7 | FR-BS1, FR-BS3 |
| **BR-10** | Giải pháp PHẢI **định danh thực thể ổn định**, chống nhầm lẫn khi định danh bị tái sử dụng, để quyết định chặn và bằng chứng luôn chính xác. | OBJ-1, OBJ-4 | FR-E2, FR-A2 |
| **BR-11** | Giải pháp PHẢI có **hành vi xác định khi gặp lỗi/quá hạn** (fail-open hoặc fail-closed theo chính sách) để không tự gây gián đoạn ngoài ý muốn. | OBJ-2 | NFR-R1, NFR-S1 |

---

## 7. Quy trình nghiệp vụ (hiện trạng ↔ đề xuất)

**Hiện trạng (phát hiện sau sự việc).** Kẻ tấn công thực thi hành vi độc hại → công cụ ghi nhận và
sinh cảnh báo → nhà phân tích SOC nhận cảnh báo (thường trong hàng đợi lớn, lẫn nhiều dương-tính-giả)
→ điều tra thủ công, ghép nối sự kiện → phản ứng. Thiệt hại thường **đã xảy ra** trước bước phản ứng.

**Đề xuất (phòng ngừa tại chỗ + điều tra tự động).**
1. Cảm biến trên endpoint quan sát hành vi hệ thống theo thời gian thực.
2. Khi một chuỗi hành vi tiến gần **điểm nghẽn** nguy hiểm và đạt đủ độ tin cậy, endpoint **chặn ngay
   thao tác** đó — trước khi gây hại.
3. Endpoint đồng thời gửi dữ liệu và một **cảnh báo** lên backend.
4. Backend **tự động dựng lại toàn bộ chuỗi tấn công** dẫn tới hành vi bị chặn và trình bày cho đội
   an ninh — không cần ghép nối thủ công.
5. Đội an ninh nhận được **cảnh báo đã có ngữ cảnh đầy đủ**, tập trung xử lý phần còn lại thay vì điều
   tra từ đầu.

Khác biệt cốt lõi: điểm ra quyết định dịch chuyển từ *sau khi thiệt hại* sang *ngay tại thời điểm
nguy hiểm*, và công việc điều tra thủ công được thay bằng dựng chuỗi tự động.

---

## 8. Tiêu chí thành công và chỉ số

| ID | Tiêu chí thành công | Cách đo |
|---|---|---|
| **KPI-1** | Các kịch bản tấn công đã biết bị chặn tại/điểm-trước điểm nghẽn | Tỷ lệ chặn trên bộ kịch bản kiểm thử (ransomware, dropper, đánh cắp credential) |
| **KPI-2** | Không chặn nhầm phần mềm lành tính phổ biến | Tỷ lệ dương-tính-giả trên tập hành vi lành tính chuẩn (cài đặt/cập nhật) |
| **KPI-3** | Chi phí hiệu năng thấp | Độ trễ chỉ xuất hiện ở đúng thao tác được "vũ trang", không phải mọi sự kiện |
| **KPI-4** | Điều tra nhanh | Chuỗi tấn công có sẵn ngay lúc chặn, không cần ghép nối thủ công |
| **KPI-5** | Nhanh đưa luật mới vào vận hành | Thời gian từ khi có luật mới tới khi hiệu lực, không qua tái triển khai agent |
| **KPI-6** | Niềm tin triển khai | Phần lõi được rà soát/kiểm toán và dựng lại được offline |

---

## 9. Giả định và ràng buộc

**Giả định**
- Có cảm biến ở tầng nhân (kernel) trên Windows cung cấp đủ tín hiệu hành vi cần thiết.
- Endpoint và backend có thể kết nối mạng với nhau để chuyển dữ liệu điều tra.
- Tri thức mối đe doạ được biểu diễn theo khung MITRE ATT&CK.

**Ràng buộc nghiệp vụ**
- **RB-1** — Phần lõi bảo vệ phải **kiểm toán được và dựng offline** (yêu cầu niềm tin cho sản phẩm
  an ninh).
- **RB-2** — Mọi quyết định chặn phải dựa trên **định danh ổn định**, không dựa trên dữ liệu dễ giả
  mạo, để tránh vừa bỏ sót vừa chặn nhầm.
- **RB-3** — Nội dung phát hiện (luật) phải **tách khỏi mã lõi**, do đội phát hiện quản lý.
- **RB-4** — Giải pháp phải **không tự gây gián đoạn** vận hành (chính sách xử lý lỗi/quá hạn rõ ràng,
  tự miễn trừ để không tự khoá).

---

## 10. Rủi ro

| ID | Rủi ro | Ảnh hưởng | Giảm thiểu |
|---|---|---|---|
| **RR-1** | Cơ chế chặn đồng bộ thật ở tầng nhân chưa hoàn thiện ở prototype | Phòng ngừa chưa hiệu lực đầy đủ trên thực địa | Hoàn thiện và load-test trên máy Windows thật trước khi đưa vào sản xuất |
| **RR-2** | Ngưỡng phát hiện chưa tinh chỉnh gây dương-tính-giả hoặc bỏ sót | Mất niềm tin của SOC/người dùng | Hiệu chỉnh trên dữ liệu thật; duy trì bộ kịch bản kiểm thử lành tính lẫn độc hại |
| **RR-3** | Backend chưa mở rộng cho quy mô đội máy lớn (giai đoạn này) | Hạn chế triển khai diện rộng | Đưa mở rộng đa-endpoint và lưu trữ bền vững vào lộ trình |
| **RR-4** | Kênh điều khiển ngược chưa có chữ ký | Rủi ro bị giả mạo lệnh nếu triển khai sớm | Ưu tiên kênh có chữ ký trước khi bật đẩy lệnh từ backend |
| **RR-5** | Phụ thuộc vào chất lượng tín hiệu từ cảm biến | Một số kịch bản chưa dựng được nếu thiếu thuộc tính | Bổ sung năng lực cảm biến theo nhu cầu kịch bản |

---

## 11. Truy vết Yêu cầu nghiệp vụ ↔ Yêu cầu hệ thống

Bảng ở [§6](#6-yêu-cầu-nghiệp-vụ) đã ánh xạ mỗi **BR** tới nhóm yêu cầu hệ thống tương ứng trong
[SRS.md](SRS.md). Nguyên tắc: mỗi yêu cầu nghiệp vụ phải phân rã được xuống ít nhất một yêu cầu hệ
thống kiểm chứng được; mọi yêu cầu hệ thống phải phục vụ ít nhất một yêu cầu nghiệp vụ.

---

## 12. Thuật ngữ

| Thuật ngữ | Nghĩa (theo góc độ nghiệp vụ) |
|---|---|
| **EDR** | Giải pháp phát hiện và phản ứng ở endpoint (Endpoint Detection and Response) |
| **Phòng ngừa tại chỗ (inline prevention)** | Chặn thao tác độc hại **ngay tại thời điểm** nó sắp xảy ra, thay vì cảnh báo sau |
| **Endpoint** | Máy người dùng/máy chủ được bảo vệ, nơi cảm biến và cơ chế chặn hoạt động |
| **Backend** | Dịch vụ tập trung thu nhận dữ liệu, giữ bức tranh đầy đủ và dựng lại chuỗi tấn công |
| **Chuỗi tấn công (attack chain / storyline)** | Trình tự các bước liên quan nhân-quả tạo nên một cuộc tấn công |
| **Điểm nghẽn (chokepoint)** | Bước quyết định mà nếu chặn được thì ngăn được thiệt hại |
| **TTP** | Chiến thuật/Kỹ thuật/Quy trình của kẻ tấn công theo khung MITRE ATT&CK |
| **Dương-tính-giả (false positive)** | Cảnh báo/chặn nhầm vào hành vi lành tính |
| **Ransomware** | Mã độc mã hoá dữ liệu để tống tiền |
| **Đánh cắp thông tin đăng nhập (credential dumping)** | Trích xuất mật khẩu/khoá từ tiến trình hệ thống nhạy cảm |
| **SOC** | Trung tâm điều hành an ninh, nơi giám sát và xử lý cảnh báo |
| **MTTR** | Thời gian trung bình để ứng cứu/khắc phục một sự cố |
