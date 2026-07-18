# replay — lịch sử event dùng chung cho các ví dụ minh hoạ engine

> Dùng cho [`engine_base.html`](engine_base.html) và các bản `engine_v*.html` về sau.

| # | timestamp | description |
|---|-----------|--------------|
| 1 | 1000 | `explorer.exe` (pid 1) khởi chạy `powershell.exe` (pid 200) với tham số ẩn cửa sổ, lệnh mã hoá base64. |
| 2 | 1500 | `powershell.exe` liệt kê (enum) thư mục Documents. |
| 3 | 1650 | `svchost.exe` (pid 50) khởi chạy `conhost.exe` (pid 80). |
| 4 | 2000 | `powershell.exe` khởi chạy `vssadmin.exe` để xoá Shadow Copy (`delete shadows /all /quiet`). |
| 5 | 2200 | `conhost.exe` đọc file `readme.txt`. |
| 6 | 2500 | `powershell.exe` ghi file `DOC1` trong Documents, entropy cao (0.96). |
| 7 | 2600 | `powershell.exe` ghi tiếp file `DOC2` trong Pictures, entropy 0.95. |
| 8 | 2750 | `svchost.exe` (pid 50) khởi chạy `notepad.exe` (pid 90). |

---

## Pattern

Một pattern mô tả một chuỗi hành vi tấn công nhiều bước, xảy ra theo đúng thứ tự.

### `ransomware_fast_encrypt_linear`

| # | step | action |
|---|------|--------|
| 0 | Chạy một công cụ dòng lệnh/thông dịch (LOLBin) một cách bất thường | Ghi nhận, theo dõi thêm — chưa đủ căn cứ để hành động. |
| 1 | Do thám, liệt kê thư mục/file | Tăng mức cảnh giác, ghi log chi tiết hơn về tiến trình này. |
| 2 | Vô hiệu hoá bản sao lưu/khôi phục (xoá Shadow Copy) | Cảnh báo SOC, khoanh vùng tiến trình — chuẩn bị sẵn sàng chặn. |
| 3 | Ghi đè hàng loạt file với nội dung có entropy cao | Chặn ngay lập tức, cô lập tiến trình khỏi hệ thống. |
