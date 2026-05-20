# Chương 3 — Đánh giá thực nghiệm và Kết luận

> Chương này gộp hai phần. **Phần I (§ 3.1 – § 3.8)** trình bày khung đánh giá thực nghiệm CobA: phương pháp, dataset, baseline, sáu thí nghiệm E1–E6 ứng với sáu câu hỏi nghiên cứu RQ1–RQ6 đã nêu trong Chương 1, kết quả, thảo luận và phân tích thất bại. **Phần II (§ 3.9 – § 3.13)** kết luận khoá luận: đối chiếu mức độ đạt các mục tiêu O1–O6, đóng góp chính, hạn chế, hướng phát triển và bài học rút ra. Các con số định lượng được điền vào tại milestone M4 (đánh giá); ở thời điểm nộp khung này, vị trí và cấu trúc bảng / biểu đã được khoá để bảo đảm việc cập nhật chỉ là điền số chứ không phải thiết kế lại.

---

## PHẦN I — ĐÁNH GIÁ THỰC NGHIỆM

## 3.1. Phương pháp đánh giá

### 3.1.1. Khung tổng thể

Khung đánh giá CobA tuân theo bốn nguyên tắc cốt lõi:

1. **Tách rõ tập tinh chỉnh và tập đánh giá.** Mọi *prompt template*, *threshold*, *budget cap* được cố định trước khi mở tập đánh giá. Không có khâu *hyperparameter tuning* trực tiếp trên test set.
2. **So sánh trên cùng pipeline.** Mọi cấu hình CobA và baseline đều chạy trên cùng một runner (`coba.eval.runner`) với cùng matcher (`coba.eval.matching`) và cùng metric (`coba.eval.metrics`) — loại bỏ sai khác do hậu xử lý.
3. **Tính tái lập.** Một *receipt* JSON ghi lại đầy đủ commit SHA, dataset hash, cấu hình LLM và seed; lưu cạnh báo cáo (`coba.eval.report.write_receipt`).
4. **Ý nghĩa thống kê.** Khoảng tin cậy bootstrap 95 % cho P / R / F1; kiểm định McNemar khi so sánh hai hệ thống trên cùng instance.

Triển khai chi tiết các nguyên tắc trên đã trình bày trong Chương 2 § 2.x của báo cáo này (mục evaluation framework) và `docs/08_EVALUATION.md`.

### 3.1.2. Tiêu chí khớp (matching)

Một dự đoán `(file, line_start, line_end, cwe)` được coi là *true positive* nếu thoả ba điều kiện:

- Cùng file (đối chiếu sau khi canonical hoá path — xem § 2.6.2).
- Khoảng dòng overlap với ground-truth ≥ 50 %.
- `cwe` trùng *family* với ground-truth (tổng quát CWE-89 ↔ CWE-564, CWE-787 ↔ CWE-121/122 theo bảng `cwe_family_map`).

Tiêu chí mềm này tránh phạt CobA khi báo cáo lỗi *liền kề* dòng đúng — một sai số quen thuộc khi LLM cite line.

### 3.1.3. Bộ tiêu chí và RQ phụ trách

| RQ  | Câu hỏi | Thí nghiệm | Metric chính |
|-----|---------|-----------|--------------|
| RQ1 | Hybrid SAST + LLM vs SAST đơn / LLM đơn | E1 | Precision, Recall, F1 |
| RQ2 | Verifier giảm FP bao nhiêu? | E2 | FP rate, Recall drop |
| RQ3 | RAG cải thiện chất lượng CWE id? | E3 | "valid finding" rate |
| RQ4 | Chunking theo function vs theo dòng? | E4 | Recall, latency |
| RQ5 | LLM local đạt bao nhiêu % cloud? | E5 | F1 ratio, cost |
| RQ6 | Pareto chi phí ↔ F1 | E6 | $/F1, plot |

## 3.2. Bộ dữ liệu

### 3.2.1. PrimeVul-1K

PrimeVul [@ding2024primevul] là tập "primed" thủ công gồm các CVE thực tế kèm patch, ground-truth `(file, line, CWE)`. Em sử dụng *subset 1K* được nhóm tác giả công bố, cân bằng giữa các ngôn ngữ chính:

| Ngôn ngữ | # mẫu | Tỉ lệ |
|---|---|---|
| C/C++ | ~ 480 | 48 % |
| Java | ~ 220 | 22 % |
| Python | ~ 180 | 18 % |
| JavaScript | ~ 120 | 12 % |

Đối với mỗi mẫu, em trích đoạn code chứa lỗi cộng tối thiểu 100 dòng context để mô phỏng kịch bản scan thực.

### 3.2.2. OWASP Benchmark v1.2

OWASP Benchmark [@owasp_benchmark] là bộ test Java, ~ 2740 test cases với cả mẫu *vulnerable* lẫn *safe* (cùng cấu trúc), dùng để đo trực tiếp **false positive rate**.

### 3.2.3. OSS Case-study (3 dự án)

Để đo CobA trên codebase thực, em chọn ba dự án mã nguồn mở chưa tham gia tập huấn của LLM (snapshot < tháng cut-off):

- `juice-shop` (Node.js, ~ 50 KLOC) — OWASP intentionally-vulnerable webapp.
- `dvwa` (PHP/JS, ~ 20 KLOC) — Damn Vulnerable Web Application (subset JS module).
- `webgoat` (Java, ~ 40 KLOC) — OWASP teaching app.

Em không công bố exploit; chỉ báo cáo *finding count*, lớp CWE và đối chiếu với danh sách "intended vulnerabilities" do dự án công bố sẵn.

## 3.3. Baselines

| ID | Tên | Stack |
|---|---|---|
| B0 | Random | Sample dòng + CWE ngẫu nhiên (sanity check). |
| B1 | Semgrep-only | Semgrep `--config p/owasp-top-ten`. |
| B2 | Bandit-only (Python) | `bandit -r`. |
| B3 | LLM-only (GPT-4o-mini) | Detector duy nhất, không SAST / Verifier. |
| B4 | LLM-only (Claude 3.5 Sonnet) | Như B3, khác provider. |
| C1 | **CobA-fast** | Cấu hình mặc định (GPT-4o-mini detector + Claude verifier + few-shot + Joern). |
| C2 | **CobA-acc** | C1 + verifier 2-pass + RAG đầy đủ. |
| C3 | **CobA-local** | C1 nhưng provider local (Qwen2.5-Coder 7B + 32B). |

Mỗi baseline có YAML config riêng trong `benchmarks/configs/*.yaml`; CLI `coba.eval.cli` chọn config bằng cờ `--config`.

## 3.4. E1 — So sánh chính (RQ1)

### 3.4.1. Thiết lập

Mỗi baseline + 3 cấu hình CobA chạy trên PrimeVul-1K + OWASP Benchmark. Kết quả gộp report bằng `coba.eval.report.MarkdownWriter`.

### 3.4.2. Bảng kết quả (TODO — điền tại M4)

| Cấu hình | Dataset | P | R | F1 | MCC | FP rate |
|---|---|---|---|---|---|---|
| B1 Semgrep | PrimeVul | TODO | TODO | TODO | TODO | TODO |
| B3 LLM-only | PrimeVul | TODO | TODO | TODO | TODO | TODO |
| C1 CobA-fast | PrimeVul | TODO | TODO | TODO | TODO | TODO |
| C2 CobA-acc | PrimeVul | TODO | TODO | TODO | TODO | TODO |
| C3 CobA-local | PrimeVul | TODO | TODO | TODO | TODO | TODO |
| (lặp tương tự cho OWASP Benchmark) | … | … | … | … | … | … |

### 3.4.3. Kiểm định thống kê

Bootstrap 1000 lần (matched-pairs) cho khoảng tin cậy 95 %. So sánh từng cặp CobA vs baseline tốt nhất bằng kiểm định McNemar (`scipy.stats.mcnemar`); báo cáo p-value điều chỉnh Bonferroni cho 8 so sánh.

## 3.5. E2 – E6 — Ablation và Pareto

### 3.5.1. E2 — Ablation Verifier (RQ2)

- C1 vs C1-no-verifier: kỳ vọng FP rate giảm ≥ 40 %, Recall giảm ≤ 10 %.
- Lưu ý: kết quả từng cặp `(detector_finding, verifier_verdict)` lưu trong file `verdicts.jsonl` để vẽ confusion matrix.

### 3.5.2. E3 — Ablation RAG (RQ3)

- C1 vs C1-no-rag (Detector không nhận few-shot ví dụ vuln/safe).
- Metric phụ: tỉ lệ "valid CWE id" (CWE trả ra có tồn tại trong MITRE), độ chệch của CWE family.

### 3.5.3. E4 — Ablation chunking (RQ4)

- C1 với chunking *theo function + callgraph* (mặc định) vs *theo dòng cố định 60 LOC*.
- So sánh Recall trên các CWE *interprocedural* (CWE-89 sourced từ user input qua nhiều hàm).

### 3.5.4. E5 — Local vs Cloud LLM (RQ5)

- C3 (Qwen2.5-Coder 7B / 32B local) vs C1 (GPT-4o-mini + Claude 3.5 Sonnet cloud).
- Báo cáo F1 ratio (C3 / C1), $ saved, latency tăng / giảm.

### 3.5.5. E6 — Cost vs Accuracy Pareto (RQ6)

- Plot điểm `(USD per scan, F1)` cho 8 cấu hình + đường Pareto.
- Bài học triển khai: chọn điểm Pareto nào cho team với ngân sách $X / repo.

## 3.6. Phân tích thất bại (Failure analysis)

Theo nguyên tắc *trung thực dữ liệu* (Chương 1 § 1.9), em báo cáo:

- **Top 10 False Positive**: liệt kê 10 finding mà CobA báo nhưng không có CVE / Semgrep / Bandit. Em sẽ phân loại theo lớp nguyên nhân (over-tagging, sanitizer-blind, taint phantom, …).
- **Top 10 False Negative**: 10 CVE mà CobA bỏ sót. Phân loại theo lớp lý do (chunk thiếu context, RAG miss CWE id, verifier giảm confidence quá mức, …).
- **Case-study 2 lỗ hổng**: chọn 1 ca CobA đúng, 1 ca CobA sai; trình bày đoạn code, dấu vết SAST hint, prompt detector + verifier, verdict, lý do.

## 3.7. Mối đe doạ tới hiệu lực (Threats to validity)

- **Selection bias**: PrimeVul subset 1K không đại diện cho mọi CWE; mức độ phân bố CWE / ngôn ngữ đã trình bày § 3.2.1.
- **Data leakage**: GPT-4 / Claude đã train trên một phần PrimeVul không? Em chạy thêm 3 OSS case-study với snapshot < cut-off để giảm tác động này.
- **Evaluator bias**: matcher overlap ≥ 50 % có thể quá lỏng / quá chặt. Em báo cáo thêm chỉ số "exact-line match" để người đọc đánh giá.
- **Stochasticity**: LLM stochastic; mỗi cấu hình chạy 3 lần, báo cáo trung bình ± SD.

## 3.8. Tóm tắt Phần I

Phần I đã trình bày khung đánh giá hoàn chỉnh — phương pháp, dataset, baseline, sáu thí nghiệm E1 – E6 — cùng kế hoạch phân tích thất bại và đánh giá tính hiệu lực. Khung này được hiện thực bằng package `coba.eval.*` đã giao trong PR #4 (Evaluation skeleton): runner, matcher, metrics, report writer, datasets manifest đều sẵn sàng; M4 chỉ thay `_zero_predict` bằng predictor gọi `Orchestrator` để bắt đầu chạy thực.

---

## PHẦN II — KẾT LUẬN VÀ HƯỚNG PHÁT TRIỂN

## 3.9. Đối chiếu mục tiêu

Trở lại bảng mục tiêu SMART trong Chương 1 § 1.3:

| ID | Mục tiêu | Thời hạn | Trạng thái dự kiến |
|---|---|---|---|
| O1 | F1 ≥ 0.55 trên PrimeVul-1K | M4 | Sẽ ghi nhận sau E1. |
| O2 | FP ≤ 25 % trên OWASP Benchmark | M4 | Sẽ ghi nhận sau E1 + E2. |
| O3 | Quét xong repo 50 KLOC < 10 phút | M4 | Test trên 3 OSS case-study. |
| O4 | Bao phủ ≥ 20 CWE phổ biến | **M3 — đã đạt** | KB CWE Top 25 đã bundle, few-shot bank phủ ≥ 20 CWE. |
| O5 | Mã nguồn tái lập (CLI + Docker) | **M2 — đã đạt** | CLI `coba`, Docker image, blueprint Devin sẵn sàng. |
| O6 | Báo cáo ≥ 60 trang + slide bảo vệ | M5 | Ba chương chính đang viết — bản này. |

Em sẽ điền các ô **M4** sau khi hoàn tất E1 – E6, dùng `coba.eval.cli` chạy và `MarkdownWriter` xuất thẳng bảng. Mọi thay đổi sẽ commit cùng *receipt* để bảo đảm tái lập.

## 3.10. Đóng góp chính

Khi M5 hoàn tất, đóng góp khoá luận được hệ thống lại như sau:

1. **Kiến trúc CobA — agent kiểm toán mã hybrid.** Tách *điều phối* khỏi *thực thi*, gắn ba lớp chống ảo giác (schema / grounding / verifier) và mười ADR có lập luận đối ngẫu (xem Chương 2 § 2.7). Đặc biệt mô hình *Verifier khác provider* trong ADR-009 chống *confirmation bias* — chưa được nghiên cứu hệ thống ở các công trình liên quan (Phụ lục B).
2. **Thư viện Python `coba`.** ~ 4000 LOC Python 3.11+, kiểm thử 130+ test xanh, CI 3 phiên bản Python. CLI `coba scan / serve / doctor / models`, FastAPI app, Docker image, Devin blueprint. Code có sẵn skip-cache + priority queue + budget cap (M3c) → ổn định thời gian quét.
3. **Khung đánh giá tái lập.** Package `coba.eval` + 5 YAML config + receipt JSON cho phép tái chạy E1 – E6 trên một máy mới; tệp `benchmarks/datasets/` tự tải bằng `scripts/download_datasets.sh`.
4. **Tài liệu thiết kế đầy đủ.** `docs/` 12 file tiếng Anh + báo cáo tiếng Việt (Chương 1 – 3 + Phụ lục). Đặc biệt `docs/06_LLM_INTEGRATION.md` ghi rõ ma trận cost / context / latency của 8 cấu hình LLM — giúp người đọc tiếp tục thí nghiệm với LLM khác.

## 3.11. Hạn chế

- **Phạm vi ngôn ngữ.** MVP hỗ trợ Python, Java, C/C++, JavaScript. Go, Rust, PHP, Solidity còn để mở.
- **Phạm vi CWE.** Ưu tiên ~ 20 CWE Top 25; các CWE *business-logic* (ví dụ CWE-840 *Business Logic Errors*) chưa nằm trong scope.
- **Stochasticity của LLM.** Ngay cả với `temperature = 0` và verifier khác provider, vẫn có sai số nhỏ giữa các lần chạy (đo và báo cáo trong § 3.7).
- **Phụ thuộc data cut-off của LLM.** Với LLM cloud, không thể loại trừ hoàn toàn data leakage; chỉ giảm bằng OSS case-study mới và đo bằng C3 LLM local.
- **Chi phí thực tế.** Mức trung bình em đạt ở M3 là ~ 0.30 USD / repo 50 KLOC ở C1; nhưng repo lớn (> 200 KLOC) có thể vượt ngân sách — cần điều chỉnh `budget_cap` thủ công.
- **Production deployment.** CobA hiện vận hành ở chế độ batch / API; chưa có IDE plugin, chưa có cơ chế update KB tự động khi MITRE phát hành CWE mới.

## 3.12. Hướng phát triển

Ngắn hạn (≤ 6 tháng sau bảo vệ):

1. **IDE plugin (VS Code)**: chạy CobA-fast trên file đang mở, hiển thị finding bằng *squiggle* gần dòng.
2. **PR bot**: tích hợp `coba` vào GitHub Actions; comment finding lên PR; xếp hạng theo severity + confidence.
3. **Sinh patch tự động (Patch-LLM)**: thử nghiệm Patch agent đề xuất diff khắc phục dựa trên finding; ưu tiên CWE-89 / CWE-22 / CWE-78 vì pattern fix tương đối ổn.
4. **Tích hợp DAST**: dùng output Burp Suite / OWASP ZAP làm input chéo để xác nhận finding (tăng confidence).

Dài hạn:

5. **Fine-tune Qwen2.5-Coder** trên tập (vuln, safe) đã có để tăng C3 (LLM local) đến mức ngang C1.
6. **Mở rộng sang Smart Contracts (Solidity / Move)**: kết hợp Slither / Mythril làm SAST tier; viết CWE family riêng cho contract vulnerabilities (re-entrancy, integer overflow on-chain).
7. **Continuous KB updater**: cron job download CWE XML / NVD JSON mới hàng tuần và rebuild ChromaDB.

## 3.13. Bài học rút ra

- **Hybrid trước, replace sau.** Cố thay SAST bằng LLM một bước thường bại; hybrid giữ deterministic baseline + để LLM giảm FP / mở rộng coverage là chiến lược thực dụng nhất ở 2024 – 2025.
- **Verifier khác provider rất đáng giá.** Hai LLM cùng nhà thường mắc cùng kiểu sai (confirmation bias); chéo nhà mở ra một mặt phẳng kiểm tra khác và giảm FP rõ.
- **Khung đánh giá phải có từ M1.** Việc thiết kế `coba.eval` trước khi có "thuật toán đúng" tránh chuyện viết xong code mới đo — khi đó dễ unconsciously chọn metric thuận lợi cho mình.
- **Tài liệu là phép kiểm tra của thiết kế.** Buộc bản thân viết Chương 2 (Thiết kế + Triển khai) làm lộ rõ ADR-009 (Verifier confidence) và ADR-010 (file-aware StaticHint) — hai cải tiến này có lẽ sẽ không được nghĩ ra nếu chỉ code.

## 3.14. Lời kết

CobA không tham vọng "đánh bại" mọi SAST hay mọi LLM. Đóng góp khoá luận nằm ở việc đề xuất một *kiến trúc* và một *thư viện mở* để cộng đồng có thể tiếp tục thử nghiệm các phối hợp khác — tuner một bộ LLM khác, thêm SAST khác, thêm CWE khác, thay đổi chiến lược chunking khác — mà không phải dựng lại cả pipeline. Em hy vọng các bảng E1 – E6 (M4) và bộ mã nguồn đi kèm sẽ là một điểm xuất phát hữu ích cho các nghiên cứu LLM + an toàn mã nguồn tiếp theo, tại HUST và rộng hơn.

---

> **TODO trước khi bảo vệ:**
> - Chạy E1 – E6 và điền số.
> - Vẽ Pareto plot cho E6 (matplotlib `coba.eval.report.write_pareto_plot`).
> - Bổ sung 2 case-study (1 đúng, 1 sai) trong § 3.6.
> - Đồng bộ con số "F1 đạt được" trong § 3.9 với O1.
