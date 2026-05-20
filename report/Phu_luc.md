# Phụ lục

> Phụ lục bao gồm các phần được tách khỏi ba chương chính: **(A) cơ sở lý thuyết**, **(B) khảo sát công trình liên quan**, và **(C–H) các phụ lục thực nghiệm** (cấu hình, bảng kết quả đầy đủ, ethics statement, hướng dẫn tái lập, FAQ, glossary). Phần A và B trước đây là Chương 2 và Chương 3 trong bản 7-chương — được đưa xuống phụ lục theo định dạng khoá luận ba chương để giữ ba chương chính tập trung vào *vấn đề*, *thiết kế-triển khai* và *đánh giá-kết luận*.

## Mục lục phụ lục

| Mã | Tệp | Nội dung |
|---|---|---|
| A | [`Appendix_A_Co_so_ly_thuyet.md`](Appendix_A_Co_so_ly_thuyet.md) | Cơ sở lý thuyết — lỗ hổng, SAST, LLM, RAG, chunking, anti-hallucination. |
| B | [`Appendix_B_Khao_sat.md`](Appendix_B_Khao_sat.md) | Khảo sát công trình liên quan — SAST cổ điển, DL detection, LLM-based, benchmark, định vị CobA. |
| C | (trong tệp này) | Cấu hình thực nghiệm chi tiết. |
| D | (trong tệp này) | Bảng kết quả đầy đủ (sinh tự động ở M4). |
| E | (trong tệp này) | Ethics statement (mở rộng). |
| F | (trong tệp này) | Hướng dẫn cài đặt & tái lập. |
| G | (trong tệp này) | FAQ. |
| H | (trong tệp này) | Glossary. |

Để biên tập PDF cuối cùng (`pandoc`), người biên tập có thể merge ba tệp `Phu_luc.md` + `Appendix_A_*.md` + `Appendix_B_*.md` theo thứ tự trên. Trong bản Markdown này, ba tệp được giữ riêng để dễ đọc và dễ chỉnh.

---

## Phụ lục C — Cấu hình thực nghiệm chi tiết

Tham chiếu `benchmarks/configs/*.yaml`. Năm cấu hình hiện hành:

| File | Cấu hình | Mục đích |
|---|---|---|
| `baseline_semgrep.yaml` | B1 Semgrep-only | Baseline SAST cổ điển. |
| `baseline_llm_only.yaml` | B3/B4 LLM-only | Baseline LLM không SAST. |
| `coba_fast.yaml` | C1 CobA-fast | Cấu hình mặc định (rẻ + nhanh). |
| `coba_acc.yaml` | C2 CobA-acc | Cấu hình chính xác (verifier 2-pass + RAG đầy đủ). |
| `owasp_benchmark.yaml` | C1/C2 trên OWASP | Tinh chỉnh OWASP Benchmark v1.2. |

## Phụ lục D — Bảng kết quả đầy đủ

TODO (M4): bảng từng cấu hình × dataset × CWE — sẽ được sinh trực tiếp từ `coba.eval.report.MarkdownWriter` và paste vào đây sau khi chạy E1 – E6.

## Phụ lục E — Ethics statement (mở rộng)

Tham chiếu `docs/09_RISK_ETHICS.md` § 4. Tóm tắt:

- **Defensive only.** CobA không sinh exploit / PoC.
- **Responsible disclosure.** Người dùng CobA trên repo OSS phải thông báo riêng cho maintainer và đợi 90 ngày trước khi công bố chi tiết.
- **Quyền truy cập.** Người dùng có trách nhiệm bảo đảm có quyền quét mã nguồn liên quan.
- **Quyền riêng tư.** Chế độ `--no-cloud` cung cấp cho tổ chức không thể gửi code lên LLM cloud.

## Phụ lục F — Hướng dẫn cài đặt & tái lập

```bash
git clone https://github.com/nam091/CobA.git
cd CobA
make install-dev          # cài deps + setup pre-commit
make install-tools        # Semgrep / Bandit / Gitleaks / Joern
cp .env.example .env      # điền API key nếu có
make download-datasets    # tải PrimeVul / OWASP Benchmark
make eval                 # chạy E1 – E6
```

Chạy unit test (không cần LLM hay Joern):

```bash
make test                 # 130+ test, runtime < 30s
```

## Phụ lục G — FAQ

Tham chiếu `docs/00_OVERVIEW.md` § FAQ. Câu hỏi thường gặp khi bảo vệ:

- *Tại sao chọn Verifier khác provider thay vì same provider 2-pass?* → ADR-009 (xem Chương 2 § 2.7.1).
- *Tại sao Tree-sitter chứ không phải LSP server?* → ADR-005 (xem Chương 2 § 2.7).
- *Tại sao Joern chứ không tree-sitter-graph cho callgraph?* → Chương 2 § 2.21 (M3a).

## Phụ lục H — Glossary

Tham chiếu `docs/10_GLOSSARY.md`. Thuật ngữ chính:

- **SAST** — Static Application Security Testing.
- **CWE** — Common Weakness Enumeration.
- **CVE** — Common Vulnerabilities and Exposures.
- **CPG** — Code Property Graph.
- **RAG** — Retrieval-Augmented Generation.
- **ADR** — Architecture Decision Record.
- **MCC** — Matthews Correlation Coefficient.
- **OWASP Top 10** — Top 10 web application security risks.
