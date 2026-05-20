# Báo cáo khoá luận — CobA

> Ứng dụng LLM trong phân tích lỗ hổng an toàn mã nguồn

## Cấu trúc (3 chương + phụ lục)

| Chương | Tệp | Trạng thái |
|---|---|---|
| 1 | `Chuong_1_Tong_quan.md` | Bản đầy đủ |
| 2 | `Chuong_2_Thiet_ke_va_Trien_khai.md` | Bản đầy đủ (gộp Thiết kế + Triển khai) |
| 3 | `Chuong_3_Danh_gia_va_Ket_luan.md` | Khung đầy đủ — bảng số M4 điền sau |
| Phụ lục | `Phu_luc.md` + `Appendix_A_Co_so_ly_thuyet.md` + `Appendix_B_Khao_sat.md` | Bản đầy đủ (A, B); C–H đầy đủ — D điền sau M4 |
| Bìa | `Loi_cam_doan.md`, `Loi_cam_on.md`, `Tom_tat.md` | Skeleton |

> **Lưu ý**: Báo cáo trước đây có 7 chương; đã rút lại còn 3 chương theo định dạng khoá luận chuẩn. *Cơ sở lý thuyết* (cũ Ch2) và *Khảo sát công trình liên quan* (cũ Ch3) được chuyển xuống Phụ lục A và B. *Thiết kế* (cũ Ch4) + *Triển khai* (cũ Ch5) gộp thành Chương 2. *Đánh giá* (cũ Ch6) + *Kết luận* (cũ Ch7) gộp thành Chương 3.

## Quy tắc viết

1. **Ngôn ngữ**: Tiếng Việt; thuật ngữ đặc thù song ngữ (xem `docs/10_GLOSSARY.md`).
2. **Trích dẫn**: Mỗi citation dùng key BibTeX trong `docs/references.bib`, vd. `[ding2024primevul]`.
3. **Hình & bảng**: Đánh số theo chương (Hình 1.1, Bảng 2.3, …). Phụ lục: Hình A.1, Bảng B.2, …
4. **Code/log**: Đặt trong khối ` ``` ` với chú thích ngắn.
5. **Chương 1** ~ 8–10 trang A4; **Chương 2** ~ 30–35 trang; **Chương 3** ~ 10–12 trang; **Phụ lục** ~ 20+ trang.

## Build PDF (tuỳ chọn — sau M4)

```bash
make report
# → output/report.pdf
```

Lệnh `make report` (sẽ thêm khi build PDF) sẽ pandoc theo thứ tự:
`Loi_cam_doan.md` → `Loi_cam_on.md` → `Tom_tat.md` →
`Chuong_1_Tong_quan.md` → `Chuong_2_Thiet_ke_va_Trien_khai.md` → `Chuong_3_Danh_gia_va_Ket_luan.md` →
`Phu_luc.md` → `Appendix_A_Co_so_ly_thuyet.md` → `Appendix_B_Khao_sat.md`.

Yêu cầu `pandoc` + `xelatex` (cài thêm khi cần in nộp).
