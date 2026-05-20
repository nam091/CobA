# Báo cáo khoá luận — CobA

> Ứng dụng LLM trong phân tích lỗ hổng an toàn mã nguồn

## Cấu trúc

| Chương | Tệp | Trạng thái |
|---|---|---|
| 1 | `Chuong_1_Tong_quan.md` | Bản đầy đủ |
| 2 | `Chuong_2_Co_so_ly_thuyet.md` | Bản đầy đủ |
| 3 | `Chuong_3_Khao_sat_lien_quan.md` | Bản đầy đủ |
| 4 | `Chuong_4_Thiet_ke_he_thong.md` | Bản đầy đủ |
| 5 | `Chuong_5_Trien_khai.md` | Bản đầy đủ |
| 6 | `Chuong_6_Danh_gia.md` | Skeleton (TODO M4) |
| 7 | `Chuong_7_Ket_luan.md` | Skeleton (TODO M5) |
| - | `Loi_cam_doan.md`, `Loi_cam_on.md`, `Tom_tat.md`, `Phu_luc.md` | Skeleton |

## Quy tắc viết

1. **Ngôn ngữ**: Tiếng Việt; thuật ngữ đặc thù song ngữ (xem `docs/10_GLOSSARY.md`).
2. **Trích dẫn**: Mỗi citation dùng key BibTeX trong `docs/references.bib`, vd. `[ding2024primevul]`.
3. **Hình & bảng**: Đánh số theo chương (Hình 1.1, Bảng 3.2, …).
4. **Code/log**: Đặt trong khối ` ``` ` với chú thích ngắn.
5. **Mỗi chương ~ 12–15 trang** A4 (tương đương ~ 4000–5000 từ).

## Build PDF (tuỳ chọn — sau M3)

```bash
make report
# → output/report.pdf
```

Yêu cầu `pandoc` + `xelatex` (cài thêm khi cần in nộp).
