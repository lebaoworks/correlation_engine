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

---

## Kịch bản v0.0.2 — chuỗi tấn công đảo thứ tự

> Dùng cho [`engine_v0.0.2.html`](engine_v0.0.2.html). Cùng hình dạng kịch bản v0 (8 event, hai
> storyline song song) nhưng bước **xoá Shadow Copy (bit 2) tới TRƯỚC bước do thám (bit 1)** — thứ
> làm automaton tuyến tính của v0.0.1 kẹt vĩnh viễn, còn DAG của [`engine_v0.0.2.md`](engine_v0.0.2.md)
> khớp trọn. Đây là thay đổi **duy nhất** của bản này so với v0.0.1.

| # | timestamp | description |
|---|-----------|--------------|
| 1 | 1000 | `explorer.exe` khởi chạy `powershell.exe` ẩn cửa sổ, lệnh base64 (T1059) — seed A, commit bit 0. |
| 2 | 1500 | `svchost.exe` khởi chạy `conhost.exe` — không TTP, storyline S2 riêng. |
| 3 | 2000 | `powershell.exe` khởi chạy `vssadmin.exe` xoá Shadow Copy (T1490) — A commit **bit 2 TRƯỚC bit 1**. |
| 4 | 2200 | `conhost.exe` đọc `readme.txt` — không TTP (S2 lớn thêm). |
| 5 | 2500 | `powershell.exe` liệt kê thư mục Documents (T1083) — A commit bit 1; nhóm {1,2} đủ → mốc bit 3 mở. |
| 6 | 2800 | `powershell.exe` ghi `DOC1` trong Documents, entropy 0.96 (T1486) — A commit bit 3 → `disarm`. |
| 7 | 2900 | `powershell.exe` ghi `DOC2` — `write ∈ DISARMED(powershell)` → block thẳng. |
| 8 | 3000 | `svchost.exe` khởi chạy `notepad.exe` — không TTP (S2 lớn thêm). |

Ở v0.0.1, event #3 (T1490) tới lúc automaton đang chờ `steps[1]` (T1083) → bị bỏ qua không dấu vết
→ kẹt, bỏ lọt toàn chuỗi. Ở v0.0.2, bit 2 chỉ cần `prereq {0}` (đã có) nên commit ngay bất kể tới
trước bit 1; mốc bit 3 mở khi cả {1,2} đã bật. Không đổi thứ tự viết rule, không hoán vị.

### `ransomware_dag` (viết lại mẫu trên thành DAG — engine_v0.0.2.md §6)

| bit | match | prereq | action |
|---|------|--------|--------|
| 0 | T1059 — chạy LOLBin bất thường | ∅ (gốc) | ∅ (báo hiệu) |
| 1 | T1083 — liệt kê thư mục/file | {0} | ∅ |
| 2 | T1490 — xoá Shadow Copy | {0} | ∅ |
| 3 | T1486 — ghi hàng loạt entropy cao | {1, 2} | `disarm(write, exec)` |

Rule v0.0.2 không mang tham số nào ngoài `prereq`; việc đặt trần bộ nhớ automaton là một bước riêng
của lộ trình (bước 5 — bounded working-set — của [`todo.md`](todo.md)), ngoài phạm vi bản này.

Verdict kỳ vọng theo event: `inspect, ignore, inspect, ignore, inspect, disarm, block, ignore`.
