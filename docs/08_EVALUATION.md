# 08 — EVALUATION: Metric, baselines, experiment plan

## 1. Phương pháp đánh giá

### 1.1. Dataset

| Dataset | Vai trò | Số mẫu |
|---|---|---|
| **PrimeVul-1K** | Primary (đo F1/P/R/MCC) | 1,000 (50/50 vuln/non-vuln) |
| **OWASP Benchmark v1.2** | Secondary (đo FP rate, Java) | 2,740 |
| **Juliet v1.3** | CWE coverage (synthetic) | sample 500 |
| **Case study repos** | Real-world validation | 3 OSS repos có CVE |

### 1.2. Metric

| Metric | Formula | Lý do |
|---|---|---|
| **Precision** | TP / (TP + FP) | Quan trọng với SAST (giảm fatigue) |
| **Recall** | TP / (TP + FN) | Đo độ phủ |
| **F1** | 2·P·R / (P+R) | Tổng hợp |
| **MCC** | (TP·TN-FP·FN)/sqrt((TP+FP)(TP+FN)(TN+FP)(TN+FN)) | Robust với imbalance |
| **FP rate** | FP / (FP + TN) | Yêu cầu OWASP Benchmark |
| **CWE coverage** | #CWE phát hiện / 25 Top CWE | Breadth |
| **Wall-clock** | seconds per scan | Performance |
| **Cost** | USD per scan | Economy |

### 1.3. Matching criteria (TP definition)

Một finding được tính TP nếu:
- File path khớp ground truth.
- Line range giao nhau với `[fix_line_start - 5, fix_line_end + 5]` (cho phép ±5 dòng tolerance).
- CWE id khớp (top-level CWE, vd. CWE-89 == CWE-89, CWE-89 ≠ CWE-79).

## 2. Baselines

| ID | Mô tả | Mục đích |
|---|---|---|
| **B0** | Semgrep alone (default ruleset) | SAST pure |
| **B1** | Bandit alone (Python only) | Single-tool baseline |
| **B2** | GPT-4o zero-shot (whole-file prompt) | LLM pure |
| **B3** | GPT-4o + few-shot (5 examples) | LLM + few-shot |
| **B4** | Semgrep ∪ GPT-4o (union, no verifier) | SAST + LLM no critique |
| **CobA-fast** | Default pipeline | Main system, fast profile |
| **CobA-acc** | Default pipeline (accuracy profile, no skip) | Main system, max accuracy |
| **CobA-local** | Local Qwen 7B detector + verifier | Offline scenario |

## 3. Experiment plan — 6 thí nghiệm

### E1 — Main comparison (RQ1)

- **Setup**: 4 baselines + CobA-fast + CobA-acc trên PrimeVul-1K.
- **Report**: bảng P/R/F1/MCC + 95 % CI bootstrap.
- **Hypothesis**: CobA-acc > tất cả baseline về F1.

### E2 — Verifier ablation (RQ2)

- **Setup**: CobA-acc với/không Verifier (4 model verifier khác nhau).
- **Report**: P/R/F1 và FP rate trước/sau verifier.
- **Hypothesis**: Verifier giảm FP ≥ 40 % giữ Recall giảm ≤ 10 %.

### E3 — RAG ablation (RQ3)

- **Setup**: CobA-acc với/không RAG.
- **Report**: F1 + tỷ lệ "valid finding" (cite CWE đúng).
- **Hypothesis**: RAG tăng `valid_finding_rate` ≥ 15 pp.

### E4 — Chunking ablation (RQ4)

- **Setup**: function-based vs line-based (200 lines) vs file-based.
- **Report**: Recall + token cost.
- **Hypothesis**: Function-based > line-based về Recall ≥ 5 pp.

### E5 — Local vs cloud LLM (RQ5)

- **Setup**: Qwen-7B vs Qwen-32B vs GPT-4o-mini vs Claude Haiku, cùng pipeline.
- **Report**: F1 + latency + cost.
- **Hypothesis**: Qwen-32B đạt ≥ 80 % F1 của GPT-4o-mini.

### E6 — Cost vs accuracy frontier (RQ6)

- **Setup**: 4 cấu hình LLM khác nhau (Detector/Verifier).
- **Report**: Pareto front (F1 vs USD/scan).
- **Output**: bảng + scatter plot.

## 4. CWE Coverage matrix

Bảng kỳ vọng (sẽ điền sau khi eval):

| CWE | Severity | Có rule Semgrep | Joern có taint | LLM detect tốt | E2E |
|---|---|---|---|---|---|
| CWE-79 XSS | High | ✓ | ✓ | ✓ | TBD |
| CWE-89 SQLi | Critical | ✓ | ✓ | ✓ | TBD |
| CWE-78 OS Cmd | Critical | ✓ | ✓ | ✓ | TBD |
| CWE-22 Path Traversal | High | ✓ | ✓ | ✓ | TBD |
| CWE-918 SSRF | High | ✓ | partial | ✓ | TBD |
| CWE-94 Code Injection | Critical | ✓ | ✓ | ✓ | TBD |
| CWE-502 Deserialization | High | ✓ | partial | ✓ | TBD |
| CWE-611 XXE | High | ✓ | × | ✓ | TBD |
| CWE-787 OOB Write | Critical | partial | ✓ | partial | TBD |
| CWE-125 OOB Read | High | partial | ✓ | partial | TBD |
| CWE-416 UAF | Critical | × | ✓ | partial | TBD |
| CWE-476 NPD | Medium | partial | ✓ | ✓ | TBD |
| CWE-862 Missing Authz | High | partial | × | ✓ | TBD |
| CWE-863 Incorrect Authz | High | × | × | ✓ | TBD |
| CWE-287 Improper Authn | High | partial | × | ✓ | TBD |
| CWE-327 Broken Crypto | High | ✓ | × | ✓ | TBD |
| CWE-330 Weak Random | Medium | ✓ | × | ✓ | TBD |
| CWE-798 Hardcoded Cred | High | ✓ (Gitleaks) | × | ✓ | TBD |
| CWE-352 CSRF | High | partial | × | ✓ | TBD |
| CWE-434 Unrestricted Upload | High | partial | × | ✓ | TBD |
| CWE-639 Auth Bypass IDOR | High | × | partial | ✓ | TBD |

## 5. Case study repos

| Repo | LOC | CVE | Lý do chọn |
|---|---|---|---|
| **Flask 1.0** | ~ 5K Python | CVE-2018-... | OSS phổ biến, lỗi đã fix, có thể compare |
| **Apache Struts subset** | ~ 50K Java | CVE-2017-5638 (RCE) | Famous vuln, Java |
| **DVWA** | ~ 2K PHP/JS/SQL | Multiple | Synthetic vuln catalog (chỉ JS/SQL parts) |
| **OpenSSL old** | ~ 100K C | Heartbleed | C/C++ flagship case |

## 6. Reproducibility

```bash
bash scripts/download_datasets.sh   # primevul + owasp_benchmark + juliet
coba eval                           # chạy mọi config trong benchmarks/configs/
coba eval --config coba_fast        # hoặc chọn lẻ
# → benchmarks/results/eval_report.{json,md,html,csv}
```

`coba eval` chạy:
1. Đọc YAML config từ `benchmarks/configs/*.yaml`.
2. Load dataset từ `benchmarks/datasets/<name>/labels.jsonl` (skeleton ở M2 PR; M4 sẽ wire predictor thật vào `Orchestrator`).
3. Tính TP/FP/FN/TN qua `coba.eval.matching` (tolerance ±5 dòng + CWE match top-level).
4. Sinh `eval_report.{json,md,html,csv}` qua `coba.eval.report`.

Mọi config eval lưu trong `benchmarks/configs/*.yaml`. Mặc định seed = 42.

## 7. Statistical test

- **McNemar's test** cho so sánh CobA vs baseline (paired binary).
- **Bootstrap 1000 resamples** cho 95 % CI của F1.
- Significance level p < 0.05.

## 8. Failure analysis

Trong báo cáo Ch.6 § 6.8, phân tích:
- Top 10 false positive (loại nào CobA hay sai).
- Top 10 false negative (loại nào CobA bỏ sót).
- 1 case study sâu cho mỗi loại lỗi → đề xuất cải thiện.

## 9. Output report format

```
benchmarks/results/2026-04-15/
├── report.md
├── primevul_1k/
│   ├── coba_fast.json          # raw findings
│   ├── coba_acc.json
│   ├── baseline_semgrep.json
│   ├── ... 
│   └── confusion_matrix.png
├── owasp_benchmark/
│   └── fp_rate_per_cwe.png
├── cwe_coverage.csv
└── cost_breakdown.json
```

## 10. Threats to validity

| Threat | Mitigation |
|---|---|
| Selection bias (PrimeVul tự chọn 1K random) | Repeat 3 seed, report mean ± std |
| Data leakage (LLM đã thấy PrimeVul) | Compare model cutoff date; có thí nghiệm với CVE 2024 mới hơn |
| Evaluator bias (LLM-as-judge) | Human spot-check 50 findings random |
| Construct validity (matching criteria) | Sensitivity analysis với tolerance khác nhau (±5, ±10, ±20 lines) |
