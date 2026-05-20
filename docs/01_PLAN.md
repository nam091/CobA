# 01 — PLAN: Mục tiêu SMART, RQ, Timeline, Risk

## 1. Mục tiêu nghiên cứu

### 1.1. Mục tiêu tổng quát

Xây dựng và đánh giá một **AI agent đa ngôn ngữ** phân tích lỗ hổng an toàn mã nguồn, kết hợp công cụ phân tích tĩnh truyền thống với LLM, đạt độ chính xác cao hơn các baseline thuần SAST hoặc thuần LLM, có chi phí hợp lý và có khả năng triển khai offline.

### 1.2. Mục tiêu SMART

| Mã | Mô tả | Specific | Measurable | Achievable | Relevant | Time-bound |
|---|---|---|---|---|---|---|
| **O1** | Phát hiện lỗ hổng | F1 ≥ 0.55 trên PrimeVul subset 1000 mẫu | F1 score | Đã có paper đạt > 0.5 | Mục tiêu chính | Tuần 12 |
| **O2** | Hạn chế false positive | FP rate ≤ 25 % trên OWASP Benchmark v1.2 | FP rate | Verifier giảm FP 50–70 % | Khả thi cao | Tuần 14 |
| **O3** | Tốc độ | < 10 phút cho repo 50K LOC (16 vCPU + 1×RTX 4090) | Wall-clock | Parallel + cache | Quan trọng | Tuần 12 |
| **O4** | CWE coverage | ≥ 20 CWE trong Top 25 CWE 2024 | Coverage matrix | Joern + Semgrep đã cover | Khả thi | Tuần 9 |
| **O5** | Reproducibility | Toàn bộ eval reproduce qua `make eval` | Script run thành công | Yêu cầu config + seed | Bắt buộc | Tuần 14 |
| **O6** | Báo cáo | Khoá luận đầy đủ ≥ 60 trang, 6 chương | Số trang + nội dung | Khả thi | Bắt buộc | Tuần 16 |

## 2. Câu hỏi nghiên cứu (Research Questions)

| RQ | Câu hỏi | Đo bằng thí nghiệm | Chương báo cáo |
|---|---|---|---|
| **RQ1** | Pipeline hybrid (SAST + LLM Detector + Verifier + RAG) có outperform các baseline đơn lẻ về F1 không? | E1 ablation | Ch.6 § 6.2 |
| **RQ2** | LLM Verifier giảm bao nhiêu % FP so với chỉ Detector? | E2 | Ch.6 § 6.3 |
| **RQ3** | RAG có giúp giảm hallucination (đo qua tỷ lệ finding hợp lệ về line/CWE) không? | E3 | Ch.6 § 6.4 |
| **RQ4** | CPG-aware chunking outperform line-based chunking về Recall không? | E4 | Ch.6 § 6.5 |
| **RQ5** | LLM local (Qwen 7B) đạt được % nào của hiệu năng GPT-4o-mini? | E5 | Ch.6 § 6.6 |
| **RQ6** | Trade-off cost vs F1 khi thay đổi LLM detector? | E6 | Ch.6 § 6.7 |

## 3. Phạm vi

### 3.1. Trong phạm vi

- 4 ngôn ngữ: Python, Java, C/C++, JavaScript/TypeScript.
- Vulnerability categories: ≥ 20 CWE trong Top 25 (CWE 2024), tập trung vào:
  - Injection (CWE-89 SQLi, CWE-78 OS Cmd, CWE-94 Code Injection, CWE-79 XSS).
  - Memory safety (CWE-119, CWE-787, CWE-416 UAF, CWE-125 OOB read).
  - Authentication/Authorization (CWE-287, CWE-862, CWE-863).
  - Cryptographic (CWE-327, CWE-330, CWE-798 hard-coded credentials).
  - Path traversal (CWE-22), SSRF (CWE-918), XXE (CWE-611).
  - Deserialization (CWE-502), Race condition (CWE-362).
- Đầu vào: file đơn, thư mục, git URL.
- Đầu ra: JSON báo cáo có schema chuẩn + HTML report (optional).

### 3.2. Ngoài phạm vi

- Binary analysis / decompilation (vd. Ghidra, IDA).
- Smart contract Solidity (mặc dù LLM rất phù hợp; cắt vì scope).
- Web UI hoàn chỉnh (chỉ API + CLI).
- Tự động fix patch (chỉ phát hiện + giải thích).
- Lỗ hổng infrastructure/IaC (Terraform, K8s) — chỉ source code thuần.

## 4. Deliverables

| # | Deliverable | Tuần | Tiêu chí "done" |
|---|---|---|---|
| D1 | Repo + design docs (12 file) + prototype skeleton | 3 | `make test` pass |
| D2 | LLM router + tool wrappers (Semgrep/Bandit/Gitleaks/Joern) | 6 | Unit test cover ≥ 80 % wrapper |
| D3 | Agent loop: Planner + Detector + Verifier + RAG | 9 | E2E pipeline trên 5 mẫu pass |
| D4 | Eval scripts + PrimeVul subset 1K | 12 | Có report Markdown F1/P/R/FP |
| D5 | Báo cáo Ch.1–3 (Tổng quan + Lý thuyết + Liên quan) | 6 | Hoàn thành review nháp |
| D6 | Báo cáo Ch.4–6 (Đề xuất + Triển khai + Đánh giá) | 14 | Hoàn thành review nháp |
| D7 | Slide bảo vệ (~25 slide) | 16 | Trình bày thử thành công |

## 5. Timeline 16 tuần & 5 milestone

```
Tuần:  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16
        ├─ M1 ─┤  ├──── M2 ─────┤  ├── M3 ──┤  ├── M4 ──┤  ├ M5 ┤
       D1,D5     D2                D3,D4         D6,D7
```

### M1 — Design + Skeleton (Tuần 1–3)

- [x] Phân tích đề tài, khảo sát paper sơ bộ.
- [x] Viết 12 file docs/.
- [x] Khởi tạo repo, CI, pre-commit.
- [x] Code skeleton: pyproject.toml, FastAPI, CLI, LLM router base, tool base.
- [x] Viết báo cáo Chương 1.

### M2 — Tool Integration (Tuần 4–6)

- [ ] Hoàn thiện wrapper cho Semgrep, Bandit, Gitleaks.
- [ ] Hoàn thiện Joern wrapper (CPG build + query).
- [ ] Tree-sitter chunker cho 4 ngôn ngữ.
- [ ] LLM Router: OpenAI, Anthropic, Gemini, Ollama.
- [ ] Báo cáo Chương 2 (Cơ sở lý thuyết).
- [ ] Báo cáo Chương 3 (Khảo sát công trình liên quan).

### M3 — Agent loop + RAG (Tuần 7–9)

- [ ] Planner: chia repo thành task.
- [ ] LLM Detector: prompt engineering + few-shot từ PrimeVul.
- [ ] LLM Verifier: critique + reject mechanism.
- [ ] RAG: ChromaDB + CWE KB + few-shot retrieval.
- [ ] CPG-aware chunking + call graph context.

### M4 — Eval + Optimization (Tuần 10–12)

- [ ] Download + clean PrimeVul subset 1K.
- [ ] Eval script: P/R/F1/MCC/FP rate.
- [ ] Optimization: parallel LLM, batch embedding, CPG cache.
- [ ] Ablation studies (E1–E6).
- [ ] Báo cáo Chương 4 (Đề xuất hệ thống).

### M5 — Báo cáo + Bảo vệ (Tuần 13–16)

- [ ] Báo cáo Chương 5 (Triển khai), Chương 6 (Đánh giá), Kết luận.
- [ ] Format LaTeX, kiểm tra trích dẫn (BibTeX), kiểm tra hình.
- [ ] Slide bảo vệ (15–20 phút).
- [ ] Dry-run bảo vệ với GVHD.

## 6. Budget

| Mục | Đơn vị | Số lượng | Tổng (USD) |
|---|---|---|---|
| OpenAI API (GPT-4o-mini) | 0.15 / 1M input + 0.6 / 1M output | ~40 M token | 25–35 |
| Anthropic API (Claude 3.5 Sonnet) | 3 / 1M input + 15 / 1M output | ~5 M token | 30–50 |
| Google Gemini API (Flash) | gần như free tier | - | 0–5 |
| GPU cloud (local LLM eval, ~10 h) | Vast.ai 4090 = $0.4/h | 10 h | 4 |
| Dataset storage (S3-like) | - | - | 0–5 |
| **Tổng** | | | **60–100** |

Có buffer +30 USD cho rebuild eval. **Tổng max = $130**.

## 7. Risk matrix (10 mục)

| # | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| R1 | API budget cạn giữa eval | Med | High | Set hard budget cap, log cost từng call, fallback local |
| R2 | Joern crash trên file lớn | High | Med | Timeout 5 phút, skip file → continue, log warning |
| R3 | PrimeVul không download được | Low | High | Mirror lên Google Drive private; backup DiverseVul |
| R4 | LLM model deprecated | Med | Med | Provider-abstracted router, đổi config |
| R5 | Tốc độ không đạt < 10 phút | Med | Med | Cắt scope verify chỉ top-K, async batching |
| R6 | F1 dưới 0.45 (failure) | Med | High | Báo cáo failure analysis, vẫn là contribution |
| R7 | Tài liệu thầy yêu cầu format khác | High | Low | Markdown → LaTeX/Word via pandoc, 1 ngày work |
| R8 | Hardware (RTX 4090) không có lúc cần | Med | Med | Thuê Vast.ai/Lambda Labs theo giờ |
| R9 | Conflict giữa Semgrep & Bandit | Low | Low | Merge findings, dedup theo (file, line, CWE) |
| R10 | Plagiarism/Ethics (LLM viết code mẫu) | High | Med | Citation rõ ràng, viết lại code by hand cho `examples/` |

## 8. Success criteria — Tiêu chí "đỗ"

| Yêu cầu | Tối thiểu | Mục tiêu |
|---|---|---|
| F1 PrimeVul-1K | 0.45 | 0.55 |
| FP rate OWASP-Bench | 35 % | 25 % |
| Wall-clock 50K LOC | 20 phút | 10 phút |
| CWE coverage | 15 | 20 |
| Test coverage (code) | 60 % | 80 % |
| Báo cáo | 60 trang | 70–80 trang |
| Dataset reproduce | Manual run | `make eval` 1-click |

## 9. Glossary thuật ngữ

| Term | Định nghĩa |
|---|---|
| **SAST** | Static Application Security Testing |
| **CPG** | Code Property Graph — graph kết hợp AST + CFG + PDG |
| **CFG** | Control Flow Graph |
| **PDG** | Program Dependence Graph |
| **CWE** | Common Weakness Enumeration — danh mục lỗ hổng |
| **CVE** | Common Vulnerabilities and Exposures — lỗ hổng cụ thể |
| **RAG** | Retrieval-Augmented Generation |
| **LLM** | Large Language Model |
| **FP** | False Positive |
| **FN** | False Negative |
| **MCC** | Matthews Correlation Coefficient |
| **OWASP** | Open Worldwide Application Security Project |
| **PrimeVul** | Bộ dataset vuln/non-vuln pair, ground truth từ commit fix |
| **Taint analysis** | Phân tích luồng dữ liệu từ source (input) tới sink (nguy hiểm) |
| **Critic/Verifier** | LLM thứ 2 review output LLM thứ 1 |
