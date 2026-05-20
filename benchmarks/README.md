# `benchmarks/`

Tài liệu hướng dẫn chạy đánh giá CobA trên các bộ dataset học thuật.

## 1. Cấu trúc

```
benchmarks/
├── configs/             # YAML config cho từng run (CobA-fast, CobA-acc, baseline…)
├── datasets/            # Dữ liệu thô — download riêng, không commit
│   ├── primevul/
│   │   └── labels.jsonl
│   ├── owasp_benchmark/
│   │   └── labels.jsonl
│   └── juliet/
│       └── labels.jsonl
└── results/             # Output: eval_report.{json,md,html,csv}
```

## 2. Cài đặt dataset

```bash
bash scripts/download_datasets.sh             # cả ba bộ
bash scripts/download_datasets.sh primevul    # chỉ PrimeVul
```

Script chỉ tải dataset; không cần token. Mỗi dataset có header license riêng — đọc trước khi sử dụng cho mục đích thương mại.

## 3. Chạy evaluation

```bash
# Chạy mọi config trong benchmarks/configs/
coba eval

# Chạy config cụ thể
coba eval --config coba_fast --config baseline_semgrep

# Đổi output dir
coba eval --output benchmarks/results/2026-04-15
```

## 4. Định nghĩa True Positive

Một finding được tính TP khi đồng thời:
1. `file` khớp ground-truth (sau khi normalize path).
2. `[line_start, line_end]` giao nhau với `[gt.line_start - tol, gt.line_end + tol]`. Mặc định `tol = 5` (config được).
3. `cwe` khớp top-level (vd. `CWE-89 == CWE-89`, `CWE-89 ≠ CWE-79`). Tắt qua `require_cwe_match: false`.

Chi tiết code: `src/coba/eval/matching.py`.

## 5. Metric output

Mỗi run sinh ra:
- `eval_report.json` — toàn bộ `EvalReport` (machine-readable).
- `eval_report.md` — bảng leaderboard tóm tắt.
- `eval_report.html` — bảng tĩnh, mở trực tiếp trên browser.
- `eval_report.csv` — friendly cho `pandas` / `gnuplot`.
- `_receipt.json` — số run + danh sách config (để CI assert).

Metric: `precision`, `recall`, `f1`, `mcc`, `fp_rate`, `accuracy` + raw `tp/fp/fn/tn`. Định nghĩa: `docs/08_EVALUATION.md` § 1.2.

## 6. Cấu trúc một dataset JSONL

Mỗi dòng là một `GroundTruth`:

```json
{
  "sample_id": "primevul_00001",
  "file": "examples/vuln_sql.py",
  "line_start": 12,
  "line_end": 14,
  "cwe": "CWE-89",
  "vulnerable": true,
  "language": "python",
  "severity": "high"
}
```

Negative sample: `"vulnerable": false`, `"cwe": null`. Loader tự đặt `dataset` field nếu thiếu.

## 7. Lưu ý cho người chạy thử

Skeleton hiện tại (M2 PR) cài sẵn:
- Schema, matcher, metric, report writer — đã unit-test 100 %.
- Wiring `coba eval` CLI → đọc config, chạy runner, ghi report.
- Predictor mặc định trả 0 finding (vì chưa wire vào `Orchestrator`).

Phần "predictor thực" gọi `Orchestrator` sẽ được wire ở M4 (xem `docs/01_PLAN.md` § 4.3). Mục tiêu của skeleton này là đảm bảo (i) bài toán metric đã rõ ràng, (ii) khi data + LLM credentials có sẵn, chỉ cần thay `_zero_predict` bằng `_orchestrator_predict` là chạy được end-to-end.
