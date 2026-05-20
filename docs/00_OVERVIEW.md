# 00 — OVERVIEW: Tóm tắt 1 trang + FAQ

> **File này dùng để**: trả lời các câu hỏi "1 phút" của thầy hướng dẫn / hội đồng phản biện.
> Nếu chỉ đọc 1 file, đọc file này.

## Tóm tắt 1 trang

**Tên đề tài**: Nghiên cứu ứng dụng LLM trong phân tích lỗ hổng an toàn mã nguồn.

**Đầu ra (deliverables)**:

1. Hệ thống `CobA` — AI agent phát hiện lỗ hổng mã nguồn, hỗ trợ Python/Java/C/C++/JavaScript.
2. Báo cáo khoá luận (~70 trang) trình bày phương pháp, thực nghiệm, đánh giá.
3. Bộ benchmark có thể reproduce trên PrimeVul + OWASP Benchmark.

**Đóng góp chính**:

| # | Đóng góp | So với gì hơn? |
|---|---|---|
| C1 | Pipeline **hybrid SAST + LLM Detector + LLM Verifier + RAG** | SeCoRA chỉ có LLM detector; CobA giảm FP 2–3× qua verifier |
| C2 | **CPG-aware chunking** (multi-language) | Chunking theo dòng/token làm mất ngữ cảnh inter-procedural |
| C3 | **Cost-aware LLM routing** (cloud + local fallback) | Cho phép chạy offline khi mất API; predictable cost |
| C4 | Bộ eval reproduce được trên PrimeVul subset 1K | Nhiều paper không công khai dataset/seed/prompt |

**Phương pháp đánh giá**:

- Tập chính: PrimeVul v0.1 subset 1K (pair-level, ground truth từ commit fix).
- Tập phụ: OWASP Benchmark v1.2 (Java, biết FP rate).
- Case study: 2 repo open-source Việt (CVE đã công bố).
- Metric: Precision, Recall, F1, MCC, FP rate, wall-clock per repo.

**Kết quả kỳ vọng** (target, không phải đã đạt):

| Metric | Target | Threshold "đỗ" |
|---|---|---|
| F1 trên PrimeVul-1K | ≥ 0.55 | ≥ 0.45 |
| FP rate trên OWASP-Benchmark | ≤ 25 % | ≤ 35 % |
| Time/repo (50K LOC) | < 10 phút | < 20 phút |
| Cost/repo | < 0.5 USD | < 1.5 USD |

## FAQ — 10 câu thầy hay hỏi

### Q1. Đề tài này đã có người làm chưa? Đóng góp mới ở đâu?

Đã có nhiều: SeCoRA, GPTScan, Vul-RAG, LATTE, IRIS, GPTLens, GRACE… Nhưng:

- Hầu hết chỉ 1 ngôn ngữ (Python hoặc Solidity hoặc C).
- Rất ít hệ thống kết hợp đầy đủ **SAST + Detector LLM + Verifier LLM + RAG** đồng thời. Cụ thể:
  - SeCoRA: chỉ LLM detector.
  - Vul-RAG: LLM + RAG (không có verifier).
  - GPTLens: Detector + Critic (không có SAST).
  - LATTE: chuyên LLM-based taint analysis.

CobA kết hợp **cả 4** và benchmark *cùng một dataset* — chứng minh từng thành phần đóng góp bao nhiêu (ablation study trong Chương 6).

### Q2. Vì sao chọn hybrid (cloud + local) thay vì chỉ một?

- **Chi phí**: GPT-4o-mini chỉ 0.15 USD / 1M input token, đủ rẻ cho detector. Claude 3.5 Sonnet đắt hơn nhưng độ chính xác cao → dùng cho verifier (số lượng call ít).
- **Offline & privacy**: Sinh viên/doanh nghiệp Việt thường cần chạy on-prem, không gửi code ra ngoài → local LLM (Qwen2.5-Coder 7B/32B) là bắt buộc.
- **Reproducibility**: Local LLM với seed cố định cho output ổn định hơn API.

Chi tiết justification: `docs/06_LLM_INTEGRATION.md` § 3.

### Q3. Tại sao chọn Joern thay vì CodeQL / Semgrep cho graph analysis?

| Tool | Multi-lang | Open-source | Có CPG | Học khó |
|---|---|---|---|---|
| **Joern** | ✓ (C/C++/Java/Python/JS/Go/PHP) | ✓ Apache-2.0 | ✓ Code Property Graph | Medium |
| CodeQL | ✓ | × (license hạn chế research/educ) | ✓ (proprietary IR) | Hard |
| Semgrep | ✓ | ✓ LGPL | × (chỉ AST/pattern) | Easy |

Joern là lựa chọn duy nhất vừa **open-source thực sự**, vừa có **CPG (AST+CFG+PDG)** cho phép truy vấn taint flow. Semgrep được dùng song song như "rules layer" để bắt các pattern dễ.

### Q4. Dữ liệu lấy ở đâu? Có trust được không?

| Dataset | Trust | Lý do |
|---|---|---|
| **PrimeVul** (Ding et al., 2024) | **Cao** | Ground truth từ commit fix, đã verify thủ công, tách rõ pair (vuln/fixed) |
| **OWASP Benchmark v1.2** | Cao | Synthetic test cases, biết trước số TP/FP → đo FP rate tốt |
| **BigVul** (Fan et al., 2020) | Medium | Có noise (~30 % mis-label theo PrimeVul) |
| **DiverseVul** | Medium-high | Dedup tốt, nhưng vẫn từ commit message |
| **Juliet/SARD** (NIST) | Cao | Synthetic, có ground truth, license public domain |
| Devign | Medium | 4 dự án C, có thể bias |

→ CobA dùng PrimeVul làm primary, OWASP Benchmark làm secondary. Chi tiết: `docs/04_DATA_SOURCES.md`.

### Q5. Hệ thống đọc code theo cách nào? Đọc toàn bộ hay từng phần?

**Không đọc toàn bộ** (sẽ vượt context window và đắt). Quy trình:

1. **Pre-scan SAST** (Semgrep + Bandit + Gitleaks) → danh sách "hot spots" (file/line khả nghi).
2. **CPG-aware chunking** (Joern AST + Tree-sitter): cắt code thành chunk theo **function boundary**, gộp các function liên quan qua call graph trong cùng chunk.
3. **LLM Detector** đọc từng chunk + tóm tắt context từ chunk gọi nó.
4. **RAG retrieve** CWE description + similar known vuln (from PrimeVul KB) cho mỗi chunk.
5. **LLM Verifier** đọc lại finding với expanded context (file đầy đủ + call sites).

Chi tiết: `docs/05_CODE_UNDERSTANDING.md`.

### Q6. Tốc độ chậm không? Bao lâu cho repo 50K LOC?

| Bước | Time (50K LOC, sequential) | Sau optimize |
|---|---|---|
| SAST (Semgrep + Bandit) | 30–60 s | 30 s (đã song song nội bộ) |
| Joern CPG build | 120–300 s | 60–120 s (incremental + cache) |
| LLM Detector | 300 s (100 chunks × 3 s) | **75 s** (parallel × 4) |
| RAG retrieve | 30 s | 10 s (batch embeddings) |
| LLM Verifier | 200 s | **50 s** (parallel × 4, chỉ verify top-K) |
| Aggregate + report | 5 s | 5 s |
| **Tổng** | ~ 12 phút | **~ 3–4 phút** |

15+ tối ưu chi tiết: `docs/07_PERFORMANCE.md`.

### Q7. Làm sao biết LLM không "bịa" lỗ hổng (hallucinate)?

3 lớp chống hallucination:
1. **Grounded prompt**: LLM phải cite đoạn code (line range) và CWE id; nếu không cite được → reject.
2. **RAG**: gắn snippet CWE/CVE chính thức vào prompt; LLM phải khớp pattern với KB.
3. **Verifier critic**: LLM thứ 2 (model khác) review từng finding; reject nếu không re-derive được.

Đo lường: trong eval, mọi finding không có *line-range hợp lệ* hoặc *cite CWE không tồn tại* → coi là FP. Chi tiết: `docs/02_ARCHITECTURE.md` § Anti-hallucination.

### Q8. So sánh với GPT-4 chạy thẳng (zero-shot) thế nào?

Trong eval, có baseline:
- **B0**: GPT-4o zero-shot, đưa cả file.
- **B1**: GPT-4o + few-shot (5 examples).
- **B2**: Semgrep alone.
- **B3**: Semgrep + GPT-4o (parallel union).
- **CobA-full**.

CobA-full kỳ vọng vượt B0 về **F1** (do giảm FP), vượt B2 về **Recall** (do bắt được semantic), vượt B3 về **cost** (do chỉ verify subset). Báo cáo Chương 6.

### Q9. Có rủi ro gì? Plan B?

| Rủi ro | Khả năng | Plan B |
|---|---|---|
| API quota / budget cạn | Trung bình | Switch local fallback Qwen 7B |
| Joern crash trên repo lớn | Trung bình | Fallback chỉ Semgrep + LLM (skip CPG) |
| PrimeVul license / takedown | Thấp | Backup OWASP Benchmark + DiverseVul |
| LLM model deprecate (GPT-4o-mini → GPT-5) | Cao | Provider-abstracted router → swap 1 dòng config |
| Kết quả F1 dưới target | Trung bình | Báo cáo *failure analysis*, vẫn là contribution khoa học |

Risk matrix đầy đủ: `docs/01_PLAN.md` § Risks.

### Q10. Thời gian 16 tuần đủ không?

Có buffer 2 tuần. Lịch chi tiết:

- Tuần 1–3: Setup + design docs + prototype (đang làm).
- Tuần 4–6: Eval pipeline + dataset PrimeVul subset.
- Tuần 7–9: Verifier + RAG + multi-language full.
- Tuần 10–12: Optimization + benchmark.
- Tuần 13–14: Viết báo cáo Chương 4–6.
- Tuần 15–16: Polish + bảo vệ thử.

Nếu trễ: cắt scope multi-language → chỉ Python + Java (vẫn đủ độ phức tạp).

## Map FAQ → chương báo cáo

| FAQ | Trả lời chi tiết ở | Chương báo cáo |
|---|---|---|
| Q1, Q4 | `docs/01_PLAN.md`, `04_DATA_SOURCES.md` | Mở đầu, Ch.3 |
| Q2 | `docs/06_LLM_INTEGRATION.md` | Ch.4 § 4.3 |
| Q3 | `docs/03_TOOLS.md` | Ch.4 § 4.4 |
| Q5 | `docs/05_CODE_UNDERSTANDING.md` | Ch.4 § 4.5 |
| Q6 | `docs/07_PERFORMANCE.md` | Ch.6 § 6.4 |
| Q7 | `docs/02_ARCHITECTURE.md` | Ch.4 § 4.6 |
| Q8 | `docs/08_EVALUATION.md` | Ch.6 § 6.2 |
| Q9 | `docs/09_RISK_ETHICS.md` | Phụ lục A |
| Q10 | `docs/01_PLAN.md` | Mở đầu |
