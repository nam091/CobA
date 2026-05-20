# 09 — RISK & ETHICS

## 1. Rủi ro kỹ thuật

(Đã chi tiết ở `01_PLAN.md` § 7. Tóm tắt + mở rộng ethics.)

## 2. Rủi ro về dữ liệu

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Dataset chứa code chứa CVE thực, có thể bị abuse | High | Med | Không công khai vuln location chưa fix; chỉ dùng CVE đã patch ≥ 1 năm |
| Code mẫu chứa PII / secret | Low | High | Gitleaks chạy tự động trên `examples/`; CI fail nếu detect |
| Data leakage: LLM đã train trên test data | High | Med | Compare model cutoff date; có sub-experiment với CVE 2024 mới |
| Redistribution dataset | Med | Med | Chỉ redistribute subset có license cho phép (PrimeVul MIT); CVE từ NVD public |

## 3. Rủi ro pháp lý

| Risk | Mitigation |
|---|---|
| Quét code không được phép (third-party repo) | CLI có `--consent` flag yêu cầu khẳng định quyền quét |
| GDPR / data protection | Local-only mode (`--no-cloud`) không gửi code ra ngoài |
| License Joern (Apache-2.0) require attribution | NOTICE file trong release |

## 4. Đạo đức nghiên cứu

### 4.1. Trách nhiệm phát hiện lỗ hổng (Responsible Disclosure)

Nếu CobA phát hiện lỗ hổng zero-day trong OSS thật (case study), tuân thủ:
1. **Không công khai** PoC trong báo cáo trước khi maintainer fix.
2. Gửi private disclosure tới maintainer (email, GitHub Security Advisory).
3. Đợi 90 ngày trước khi disclose chi tiết.
4. Nếu là CVE đã public, OK để bàn luận.

### 4.2. Misuse potential

- CobA có thể bị attacker dùng để **tìm lỗ hổng cho mục đích xấu**.
- Mitigate: tài liệu giới hạn ở "audit phòng thủ"; không cung cấp module sinh exploit/PoC.
- Trong báo cáo Ch.1 § "Statement of Ethical Use" sẽ nêu rõ.

### 4.3. LLM bias & hallucination

- LLM có thể fabricate vuln (false positive) → developer waste time.
- Mitigate: Verifier + grounding filter (xem `02_ARCHITECTURE.md` § 7).
- Báo cáo Ch.6 sẽ công khai FP rate cụ thể, không che giấu.

### 4.4. Plagiarism

- Code mẫu vuln trong `examples/` viết by hand từ pattern CWE, không copy từ repo bên thứ 3 trừ khi license cho phép (Juliet/SARD public domain).
- Citation đầy đủ trong `references.bib`.

## 5. Tài nguyên & môi trường

- Chạy LLM local trên GPU tiêu thụ điện. Eval scope < 50 h GPU trên RTX 4090 (300 W) → ~ 15 kWh ≈ 6 kg CO₂eq. Acceptable.
- Cloud LLM: cost rõ ràng, không "burn" quota.

## 6. Privacy

- CobA mặc định **không thu thập telemetry**.
- `.coba_data/` lưu local; không upload.
- `--upload-anonymous-feedback` optional cho dev (mặc định off).

## 7. Compliance khi triển khai doanh nghiệp

| Yêu cầu | CobA support |
|---|---|
| On-premise / air-gap | ✓ `--no-cloud` + local Qwen + local embedding |
| GDPR right to erasure | ✓ Tất cả lưu trong `.coba_data/` — xóa thư mục là sạch |
| Audit log | ✓ structlog JSON log có thể ship sang SIEM |
| SBOM | ✓ `pip list` + Dockerfile reproducible |

## 8. Open source compliance

- Tất cả dependency check qua `pip-licenses` (Apache, MIT, BSD).
- Không deps GPL/AGPL (avoid copyleft conflict với MIT của CobA).

## 9. Câu hỏi đạo đức trong báo cáo

Chương 1 § 1.6 và Phụ lục A.3 sẽ trả lời:

1. Lợi ích vs rủi ro của một tool tự động phát hiện lỗ hổng?
2. Làm sao đảm bảo CobA không bị dùng cho mục đích offensive?
3. Trách nhiệm của tác giả nếu CobA tạo false positive gây thiệt hại?

Trả lời tóm tắt:
- Lợi ích defensive > rủi ro offensive (vì attacker đã có các tool tương tự sẵn).
- License + tài liệu ghi rõ defensive use.
- Tác giả không chịu trách nhiệm pháp lý (MIT clause); khuyến nghị review thủ công trước khi action.
