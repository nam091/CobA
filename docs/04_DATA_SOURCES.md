# 04 — DATA SOURCES: Dataset, KB, trust score, license

> Bảng tổng hợp **nguồn dữ liệu** dùng để (a) train/few-shot/RAG knowledge và (b) đánh giá. Mỗi nguồn có **link**, **kích thước**, **license**, **trust score**, **cách dùng trong CobA**.

## 1. Bảng tổng hợp

| # | Dataset | Quy mô | License | Trust | Dùng cho | Link |
|---|---|---|---|---|---|---|
| 1 | **PrimeVul** | ~6,800 vuln/fixed pairs, 750 verified | MIT | ⭐⭐⭐⭐⭐ | Eval primary + few-shot | [GitHub](https://github.com/DLVulDet/PrimeVul) |
| 2 | **OWASP Benchmark v1.2** | 2,740 test cases Java | Apache-2.0 | ⭐⭐⭐⭐⭐ | Eval FP rate | [owasp-benchmark](https://owasp.org/www-project-benchmark/) |
| 3 | **DiverseVul** | ~18K vuln + 330K non-vuln (C/C++) | MIT | ⭐⭐⭐⭐ | Eval secondary | [DiverseVul](https://github.com/wagner-group/diversevul) |
| 4 | **BigVul** | ~10K vuln (C/C++) | MIT | ⭐⭐⭐ | Few-shot (sau khi clean) | [bigvul](https://github.com/ZeoVan/MSR_20_Code_vulnerability_CSV_Dataset) |
| 5 | **Juliet/SARD** | 100K+ test cases | Public Domain (NIST) | ⭐⭐⭐⭐⭐ | Eval CWE coverage | [NIST SARD](https://samate.nist.gov/SARD/) |
| 6 | **CVEfixes** | 5,300+ CVE-fix commits | CC-BY-4.0 | ⭐⭐⭐⭐ | RAG corpus | [CVEfixes](https://github.com/secureIT-project/CVEfixes) |
| 7 | **Devign** | ~22K (4 dự án C) | MIT | ⭐⭐⭐ | Eval comparison | [devign](https://sites.google.com/view/devign) |
| 8 | **D2A** | ~1.3M (Infer-based) | CDLA-Sharing-1.0 | ⭐⭐ | Không dùng (noise cao) | [IBM D2A](https://developer.ibm.com/exchanges/data/all/d2a/) |
| 9 | **Vul4J** | 79 reproducible Java vuln | MIT | ⭐⭐⭐⭐ | Eval Java specific | [vul4j](https://github.com/tuhh-softsec/vul4j) |
| 10 | **MITRE CWE** | ~1,400 entries | None (public) | ⭐⭐⭐⭐⭐ | RAG `cwe_kb` collection | [cwe.mitre.org](https://cwe.mitre.org/) |
| 11 | **NVD CVE feed** | 200K+ CVE | Public | ⭐⭐⭐⭐ | RAG `cve_corpus` | [nvd.nist.gov](https://nvd.nist.gov/) |
| 12 | **OWASP Top 10 2021** | 10 categories | CC-BY-SA-4.0 | ⭐⭐⭐⭐⭐ | Categorization | [owasp.org](https://owasp.org/Top10/) |

## 2. Chi tiết primary dataset — PrimeVul

### 2.1. Vì sao chọn

- Ground truth **chính xác**: chỉ giữ commit fix mà tác giả paper đã verify thủ công.
- Tránh **data leakage**: PrimeVul dedup vs BigVul/Devign nên có thể là test set "sạch".
- Có **pair (vuln, fixed)**: lý tưởng cho ablation "model có phân biệt được 2 phiên bản không?".
- **License MIT**, có thể redistribute subset.

### 2.2. Cách CobA dùng

| Use | Subset | Mục đích |
|---|---|---|
| **Eval primary** | `primevul-1k` (random sample 1000 với seed=42) | Đo F1/P/R |
| **Few-shot pool** | `primevul-50` (50 representative examples) | Inject vào Detector prompt |
| **RAG examples** | `primevul-200` (200 với high diversity) | ChromaDB `primevul_examples` |

3 tập **không giao nhau**.

### 2.3. Download script

`scripts/download_datasets.sh`:
```bash
# PrimeVul
git clone --depth=1 https://github.com/DLVulDet/PrimeVul.git benchmarks/data/PrimeVul
python scripts/prepare_primevul.py \
    --input  benchmarks/data/PrimeVul/dataset \
    --output benchmarks/data/primevul_subsets/ \
    --seed 42
```

### 2.4. License & ethics

- MIT → có thể redistribute subset (kèm citation).
- Không có PII trong dataset (chỉ source code).
- Ethics statement trong báo cáo Chương 6 § 6.1.

## 3. Eval secondary — OWASP Benchmark v1.2

### 3.1. Vì sao chọn

- **Synthetic, biết trước** số TP/FN/TN/FP → đo **FP rate** tốt.
- Tập trung Java + chuẩn industry.
- License Apache-2.0.

### 3.2. CWE phủ

| CWE | Số test case | Mô tả |
|---|---|---|
| CWE-22 | 268 | Path Traversal |
| CWE-78 | 251 | OS Command Injection |
| CWE-79 | 455 | XSS |
| CWE-89 | 504 | SQL Injection |
| CWE-90 | 27 | LDAP Injection |
| CWE-327 | 246 | Broken/Risky Crypto |
| CWE-328 | 236 | Reversible One-Way Hash |
| CWE-330 | 493 | Weak Random |
| CWE-501 | 49 | Trust Boundary |
| CWE-614 | 67 | Sensitive Cookie no HTTPS |
| CWE-643 | 35 | XPath Injection |

→ Bao phủ tốt **injection family** + **crypto**.

## 4. RAG knowledge base

### 4.1. `cwe_kb`

- **Nguồn chính**: <https://cwe.mitre.org/data/downloads/cwec_v4.14.xml.zip>
- **Bundled fallback (offline)**: `src/coba/data/cwe_top25.json` — ~25 CWE đã chọn lọc kèm description + language coverage + OWASP mapping. Script `scripts/build_cwe_kb.py` mặc định đọc file này, giúp prototype chạy được hoàn toàn offline.
- **Process** (`scripts/build_cwe_kb.py`):
  1. Đọc nguồn: `--source` (JSON, default = bundled corpus) hoặc `--mitre-xml` (full XML).
  2. Parse → list entry. Với XML, lấy `id`, `name`, `Description`, `Extended_Description`.
  3. Embed bằng `all-MiniLM-L6-v2`.
  4. `upsert` vào ChromaDB collection `coba_cwe` (idempotent).
- **Runtime**: `coba.agent.rag.load_rag_index()` ưu tiên Chroma collection nếu tồn tại; fallback về bảng built-in (~20 CWE) khi chưa build KB.

### 4.2. `cve_corpus`

- **Nguồn**: NVD JSON feed + GitHub Security Advisories.
- Lọc các CVE có **code snippet** (qua link patch commit hoặc PoC).
- Mỗi entry: `cve_id`, `cwe_id`, `description`, `affected_product`, `code_snippet`, `severity`.

### 4.3. `primevul_examples`

- 200 pairs từ PrimeVul.
- Mỗi entry: `language`, `cwe_id`, `code_before` (vuln), `code_after` (fixed), `diff`, `description`.

## 5. Trust score — cách chấm

| Tiêu chí | Trọng số |
|---|---|
| Ground truth do người verify | 30 % |
| Provenance rõ (paper peer-reviewed + repo) | 20 % |
| Recent (≤ 2 năm) | 15 % |
| Dedup tốt | 15 % |
| License rõ ràng | 10 % |
| Có balanced classes | 10 % |

Áp dụng cho 12 dataset:

| Dataset | Tổng điểm |
|---|---|
| PrimeVul | 95 |
| OWASP Benchmark | 90 |
| Juliet/SARD | 85 |
| DiverseVul | 78 |
| CVEfixes | 75 |
| Vul4J | 75 |
| BigVul | 60 |
| Devign | 55 |
| D2A | 40 |

→ CobA chỉ dùng dataset điểm ≥ 75 cho **eval primary**, các tập khác chỉ cho RAG/few-shot.

## 6. Data leakage — cách phòng

| Risk | Mitigation |
|---|---|
| LLM đã train trên PrimeVul | Báo cáo "training cutoff date" của model. Compare với LLM khác có cutoff khác |
| Few-shot và eval trùng | Tách 3 split (test/few-shot/RAG) không giao |
| Hash leak qua tool | Semgrep rules không reference CVE id; LLM prompt redact CVE id |

## 7. Cách tải

```bash
make download-datasets
```

Sẽ tải về `benchmarks/data/`:
```
data/
├── PrimeVul/
├── primevul_subsets/
│   ├── primevul_1k.jsonl
│   ├── primevul_50_fewshot.jsonl
│   └── primevul_200_rag.jsonl
├── owasp_benchmark/
├── juliet/  (optional, lớn)
└── cwe/
    └── cwec_v4.14.xml
```

Tổng dung lượng: ~ 2.5 GB (PrimeVul + OWASP Benchmark + CWE XML, không Juliet).
Với Juliet: ~ 8 GB.

## 8. Verification — kiểm tra tính toàn vẹn

`scripts/verify_datasets.py` so checksum + đếm số mẫu/CWE. Phải pass trước khi chạy eval.
