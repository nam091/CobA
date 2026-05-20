# Chương 1 — Tổng quan đề tài

## 1.1. Bối cảnh và động lực

### 1.1.1. Tình hình an toàn phần mềm hiện nay

Trong những năm gần đây, số lượng lỗ hổng phần mềm được công bố trong cơ sở
dữ liệu NVD (National Vulnerability Database) tăng nhanh chóng — hơn 28 000
CVE năm 2023 và dự kiến vượt 30 000 năm 2024. Hệ quả là chi phí khắc phục
một sự cố bảo mật trung bình lên tới hàng triệu USD, đặc biệt đối với các
hệ thống tài chính, y tế và hạ tầng quan trọng.

Theo báo cáo OWASP Top 10:2021 [@owasp_top10] và MITRE 2024 CWE Top 25
[@mitre_topcwe], các họ lỗ hổng phổ biến nhất bao gồm:

- **Injection** (CWE-79, CWE-89, CWE-78, CWE-94) — XSS, SQL Injection,
  OS Command Injection, Code Injection.
- **Broken Access Control** (CWE-862, CWE-863, CWE-285) — Kiểm soát truy
  cập sai/thiếu.
- **Cryptographic Failures** (CWE-327, CWE-328, CWE-330) — Mật mã yếu hoặc
  cài đặt sai.
- **Memory Safety** (CWE-787, CWE-125, CWE-416, CWE-476) — Buffer overflow,
  use-after-free, NULL dereference (chủ yếu C/C++).
- **Authentication & Sessions** (CWE-287, CWE-798) — Xác thực kém,
  hard-coded credential.

Mặc dù đã có nhiều công cụ phát hiện lỗ hổng tự động (SAST/DAST/IAST), tỉ
lệ phát hiện thực tế vẫn thấp và **false positive rate cao** vẫn là vấn đề
nhức nhối: các nghiên cứu chỉ ra rằng > 40 % cảnh báo từ SAST commercial bị
developer bỏ qua hoặc xác định là báo động giả.

### 1.1.2. Bước tiến của Mô hình ngôn ngữ lớn

Sự xuất hiện của các LLM mạnh như GPT-4o [@openai_gpt4o], Claude 3.5 Sonnet
[@anthropic_claude35], Gemini 1.5 [@google_gemini15] và các *code-LLM*
chuyên dụng như Qwen2.5-Coder [@hui2024qwen25coder], DeepSeek-Coder
[@guo2024deepseekcoder] mở ra hướng tiếp cận mới. LLM có khả năng:

- Hiểu **ngữ nghĩa** code (không chỉ pattern bề mặt).
- Truy vết **data flow** qua nhiều bước.
- Sinh **giải thích** dễ hiểu cho người phát triển.
- Đề xuất **bản vá** cụ thể.

Tuy nhiên, các nghiên cứu gần đây như SeCoRA, Vul-RAG [@du2024vulrag], LATTE
[@liu2024latte], GPTScan [@sun2024gptscan], IRIS [@lin2024iris] cũng cho
thấy hạn chế:

1. **Hallucination**: LLM tự bịa ra lỗ hổng không tồn tại, hoặc đặt sai
   CWE id.
2. **Context window**: Code base lớn không vừa cửa sổ ngữ cảnh.
3. **Chi phí**: Quét toàn bộ một repo lớn bằng GPT-4 có thể tốn hàng chục
   USD.
4. **Quyền riêng tư**: Code thương mại không thể đẩy lên cloud LLM.
5. **Khả năng tái lập**: LLM có yếu tố ngẫu nhiên; cùng input có thể ra
   output khác nhau.

### 1.1.3. Động lực — Tại sao cần CobA?

Khoá luận đặt câu hỏi: **liệu có thể kết hợp ưu điểm của SAST (rule-based,
nhanh, deterministic) với LLM (semantic, suy luận) trong một *agent* thống
nhất, đồng thời kiểm soát hallucination và chi phí?**

CobA là câu trả lời: một *hybrid agent* phối hợp **5 kỹ thuật** chính —
SAST pre-scan, CPG-based chunking, RAG ngữ cảnh CWE/CVE, LLM Detector,
LLM Verifier — với hai cấu hình mô hình (cloud + local) cho phép trade-off
giữa chi phí, tốc độ và quyền riêng tư.

## 1.2. Phát biểu bài toán

Cho:
- Đầu vào: một mã nguồn (file, repository, hoặc git URL) viết bằng một
  trong các ngôn ngữ Python, Java, C/C++, JavaScript/TypeScript.
- Tài nguyên: API LLM (cloud), GPU (local), thư viện SAST mã nguồn mở,
  cơ sở tri thức CWE/CVE.

Đầu ra mong muốn:
- Một danh sách *finding* (`(file, line_start, line_end, cwe, severity,
  description, fix_suggestion)`) với độ tin cậy cao và có **dẫn chứng dòng
  code cụ thể** cho từng cảnh báo.

Ràng buộc:
- Thời gian quét < 10 phút cho repo 50K LOC.
- Chi phí LLM < 0.5 USD/repo trung bình.
- Hỗ trợ chế độ **offline** (không gọi cloud).
- Hệ thống có thể tái lập (cùng input → cùng output).

## 1.3. Mục tiêu nghiên cứu (SMART)

| ID | Mục tiêu (Specific) | Measurable | Achievable | Relevant | Time |
|---|---|---|---|---|---|
| O1 | Đạt F1 ≥ 0.55 trên PrimeVul-1K | ✓ | ✓ | ✓ | M4 |
| O2 | FP ≤ 25 % trên OWASP Benchmark | ✓ | ✓ | ✓ | M4 |
| O3 | Quét xong repo 50K LOC < 10 phút | ✓ | ✓ | ✓ | M4 |
| O4 | Bao phủ ≥ 20 CWE phổ biến | ✓ | ✓ | ✓ | M3 |
| O5 | Mã nguồn tái lập (CLI + Docker) | ✓ | ✓ | ✓ | M2 |
| O6 | Báo cáo ≥ 60 trang + slide bảo vệ | ✓ | ✓ | ✓ | M5 |

## 1.4. Câu hỏi nghiên cứu (RQ)

- **RQ1** — Hybrid SAST + LLM có vượt SAST đơn thuần và LLM đơn thuần về F1
  trên PrimeVul không? Bao nhiêu điểm phần trăm?
- **RQ2** — Bước Verifier có làm giảm FP rate ≥ 40 % mà chỉ làm giảm Recall
  ≤ 10 % không?
- **RQ3** — RAG ngữ cảnh CWE/CVE có cải thiện tỉ lệ "valid finding" (cite
  CWE đúng) hay không?
- **RQ4** — Chiến lược chunking theo function so với chunking theo dòng có
  cải thiện Recall hay không?
- **RQ5** — LLM local (Qwen 7B / 32B) có thể đạt bao nhiêu phần trăm chất
  lượng so với GPT-4o-mini ở cùng pipeline?
- **RQ6** — Pareto frontier giữa chi phí (USD) và F1 trông như thế nào với
  các cấu hình LLM khác nhau?

## 1.5. Phạm vi đề tài

### 1.5.1. Trong phạm vi

- Phát hiện lỗ hổng *tĩnh* (không thực thi code).
- 4 ngôn ngữ: Python, Java, C/C++, JavaScript/TypeScript.
- ~ 20 CWE thuộc OWASP Top 10 và CWE Top 25.
- Đánh giá trên PrimeVul, OWASP Benchmark, và 3 OSS case study.

### 1.5.2. Ngoài phạm vi

- DAST (dynamic), IAST (interactive).
- Fine-tune LLM riêng (chỉ dùng prompt engineering + RAG).
- Phát hiện lỗ hổng logic nghiệp vụ (business logic vulnerabilities).
- Sinh exploit / PoC tự động (lý do đạo đức).
- Quét binary / phân tích mã máy (chỉ source code).
- Realtime IDE plugin (để dành cho future work).

## 1.6. Ý nghĩa khoa học và thực tiễn

### 1.6.1. Ý nghĩa khoa học

- Cung cấp **bằng chứng thực nghiệm** về hiệu quả của hybrid SAST + LLM
  trên benchmark đa ngôn ngữ.
- Đề xuất kiến trúc *Verifier* lai dùng LLM khác provider — chống
  *confirmation bias* — chưa được công trình trước đó nghiên cứu hệ thống.
- Cung cấp dataset **so sánh chéo 8 cấu hình LLM** trên cùng pipeline →
  có thể tái dùng cho nghiên cứu tiếp theo.

### 1.6.2. Ý nghĩa thực tiễn

- Cung cấp công cụ **mã nguồn mở** (MIT) có thể tích hợp vào pipeline CI/CD.
- Hỗ trợ chế độ **offline** giúp doanh nghiệp có code nhạy cảm vẫn dùng
  được LLM.
- Cost projection thực tế (~ 0.30 USD/repo 50K LOC) giúp team đánh giá ROI.

## 1.7. Đóng góp chính

1. **Kiến trúc CobA** — *agent* lai SAST + LLM với 3 lớp chống hallucination
   (schema/grounding/verifier).
2. **Thư viện Python `coba`** — CLI + REST API + multi-language analyzers,
   ~ 4000 LOC code Python.
3. **Bộ benchmark** so sánh 8 cấu hình LLM trên cùng pipeline + scripts
   tái lập.
4. **Tài liệu kỹ thuật** — 12 file thiết kế (`docs/`) + báo cáo tiếng Việt
   60+ trang.

## 1.8. Cấu trúc khoá luận

- **Chương 1 — Tổng quan**: Bối cảnh, bài toán, mục tiêu, đóng góp.
- **Chương 2 — Cơ sở lý thuyết**: LLM, RAG, AST/CPG, CWE, prompt
  engineering.
- **Chương 3 — Khảo sát công trình liên quan**: GPTScan, Vul-RAG, LATTE,
  IRIS, … (12+ công trình).
- **Chương 4 — Thiết kế hệ thống**: Kiến trúc CobA — 5 view C4 + ADR.
- **Chương 5 — Triển khai**: LLM router, tool wrappers, agent loop, RAG,
  CLI/API.
- **Chương 6 — Đánh giá thực nghiệm**: 6 thí nghiệm (E1–E6) + thảo luận.
- **Chương 7 — Kết luận & hướng phát triển**: Tổng kết, hạn chế,
  future work.
- **Phụ lục**: Cấu hình chi tiết, bảng kết quả đầy đủ, ethics statement.

## 1.9. Tuyên bố về sử dụng có đạo đức

CobA được xây dựng cho mục đích **phòng thủ** (defensive security). Tác giả
không cung cấp module sinh exploit hay PoC. Khi sử dụng CobA để quét OSS
thật, người dùng có trách nhiệm tuân thủ *Responsible Disclosure*: thông báo
riêng cho maintainer và đợi 90 ngày trước khi công bố chi tiết lỗ hổng.
Người dùng cũng có trách nhiệm chỉ quét những mã nguồn mình được phép quét.

Mọi nội dung trong khoá luận này, bao gồm các bảng kết quả, được tạo ra với
nguyên tắc trung thực — bao gồm cả các trường hợp CobA dự đoán sai (báo cáo
trong Chương 6 § 6.8 *Failure Analysis*).

---

> **TODO** trước khi nộp:
> - Cập nhật con số CVE NVD 2024 chính xác.
> - Thêm hình *thống kê CVE theo năm* (matplotlib từ NVD).
> - Bổ sung 1 hình *kiến trúc tổng quan CobA* (1 trang).
> - Rà soát citation BibTeX key.
