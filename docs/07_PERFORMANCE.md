# 07 — PERFORMANCE: Bottleneck + 15+ tối ưu

> Phân tích bottleneck đo được trên **repo 100 file, 50K LOC** và **15 + biện pháp tối ưu**.

## 1. Bottleneck baseline (sequential, no optimization)

| Stage | Time | % | Note |
|---|---|---|---|
| SAST pre-scan (Semgrep + Bandit + Gitleaks) | 30–60 s | 8 % | I/O + subprocess |
| Joern CPG build | 120–300 s | 30 % | **Bottleneck #2** |
| Tree-sitter chunking | 5 s | 1 % | Fast |
| RAG retrieve (per chunk) | 30 s (100 × 0.3 s) | 4 % | Có thể batch |
| **LLM Detector (sequential)** | 300 s (100 × 3 s) | **30 %** | **Bottleneck #1** |
| Schema/grounding filters | 2 s | < 1 % | Fast |
| **LLM Verifier (sequential)** | 200 s (40 × 5 s) | **20 %** | **Bottleneck #3** |
| Aggregate + report | 5 s | 1 % | Fast |
| **TOTAL** | **~ 10–12 phút** | 100 % | |

→ **3 bottleneck chính**: LLM Detector, Joern CPG, LLM Verifier.

## 2. Mục tiêu tối ưu

| Target | Hiện tại | Sau optimize |
|---|---|---|
| Tổng | 12 phút | **< 4 phút** |
| LLM Detector | 300 s | 75 s (4× parallel) |
| LLM Verifier | 200 s | 50 s (4× parallel + chỉ top-K) |
| Joern CPG | 200 s | 60 s (incremental + cache) |

## 3. Danh sách 18 tối ưu cụ thể

### 3.1. Parallelism (×4 speed-up cho LLM)

**[O1] Async parallel LLM calls** — `asyncio.gather` với semaphore = 4 (avoid rate limit).
```python
sem = asyncio.Semaphore(settings.parallel_llm_calls)  # default 4
async def detect(c): async with sem: return await detector(c)
findings = await asyncio.gather(*[detect(c) for c in chunks])
```

**[O2] Batched embeddings** — gửi 32 chunk text 1 batch tới `SentenceTransformer.encode(..., batch_size=32)`.

**[O3] Pipeline overlap** — bắt đầu LLM Detector ngay khi Joern xong file đầu, không chờ build CPG xong toàn bộ.

### 3.2. Caching (giảm I/O & recompute)

**[O4] CPG cache theo Merkle hash** — hash từng file `.py/.java/.c/.js`, nếu hash cũ → reuse `cpg.bin` cached trong `.coba_cache/joern/<hash>/`.

**[O5] LLM response cache** — key = `sha256(model + prompt + temperature)`. Lưu trong `.coba_cache/llm/`. Tiết kiệm ~ 60 % khi rerun cùng repo.

**[O6] RAG retrieval cache** — key = `sha256(query)`. ChromaDB có in-memory cache nhưng vẫn nên thêm 1 lớp persistent.

**[O7] Semgrep cache** — `semgrep --cache --cache-dir .coba_cache/semgrep/`.

### 3.3. Smart filtering (giảm số call)

**[O7.1] Skip-cache theo SHA-256 nội dung file** (M3c, đã ship) — `coba.agent.skip_cache.SkipCache` lưu `(sha256 → list[Finding])` dưới `.coba_cache/skip/<aa>/<sha>.json`. Khi rerun cùng repo, file không đổi → tái dùng findings, bỏ cả Detector + Verifier; clean file vẫn cache (empty record) để không re-scan. Trên CI khi PR chỉ sửa 2–3 file, cache hit ≈ 95 %, tiết kiệm ≈ 90 % cost.

**[O7.2] Priority queue theo SAST hits** (M3c, đã ship) — `Planner.prioritize(chunks, hints_by_file)` sort chunks theo số hits Semgrep/Bandit/Gitleaks/Joern rơi vào line range. Khi gặp budget cap, ta đã quét xong những chunks "nóng" trước → recall ổn định.

**[O7.3] Per-scan budget cap** (M3c, đã ship) — `COBA_SCAN_BUDGET_USD` (default $2) khoá hard cap. Khi `router.cost.spent ≥ budget`, Orchestrator dừng nhận chunk mới, log `n_chunks_budget_skipped` vào `ScanStats`. Bảo vệ chi phí khi quét repo cực lớn / loop bug.

**[O8] Skip non-vulnerable file types** — pre-filter `.md`, `.json`, `.yaml`, `.lock`, … không quét.

**[O9] Verifier chỉ chạy trên Top-K finding** — sort theo `(confidence × severity_weight)` desc, verify K=20 đầu (≈ 20 % findings).

**[O10] Static-LLM agreement boost** — nếu Semgrep & Detector cùng flag (cùng line, cùng CWE family) → confidence × 1.5, skip verifier (đã có 2 vote).

**[O11] Cheap pre-filter trước LLM** — nếu chunk không chứa keyword nguy hiểm (`exec`, `system`, `query`, `SELECT`, ...) → confidence prior thấp, skip LLM cho 70 % chunk an toàn (sampling 10 % để giữ recall).

### 3.4. Token-level (giảm input size)

**[O12] Aggressive prompt minify** — xoá whitespace dư, đổi indent từ 4 sang 2 space, không gửi comment >100 chars.

**[O13] Function signature collapse cho callers/callees** — không gửi cả body, chỉ signature + 1 line summary.

**[O14] Few-shot dynamic selection** — chọn 2 example phù hợp nhất (cùng ngôn ngữ + CWE family) thay vì gửi 5 example luôn.

### 3.5. Joern-specific

**[O15] Joern incremental** — chỉ rebuild CPG cho file đã đổi (so với git diff).

**[O16] Joern parallel parse** — `joern-parse --jobs 4` (multi-thread).

**[O17] Joern query batching** — chạy nhiều query trong 1 Scala script (giữ JVM warm).

### 3.6. LLM-specific

**[O18] Stop token tight** — set `stop=["```", "\n\n\n"]` để LLM không sinh dư.

**[O19] Reduce max_tokens output** — limit 1000 tokens output (đủ JSON findings).

**[O20] Use streaming nhưng parse partial** — bắt đầu schema check khi nhận đủ JSON header.

## 4. Đo lường — biểu đồ kỳ vọng

```
                Time per stage (seconds) — 50K LOC, 100 files

  300│              ████████ Detector seq
     │              ░░░░░░░░ Detector parallel×4
  200│  ███████     ██████████ Joern seq
     │  ░░░░░░░     ░░░░░░░░░░ Joern incremental+cache
     │  ████ Joern  ██████████████ Verifier seq
  100│  ░░░░ inc.   ░░░░░░░░ Verifier parallel+top-K
     │  ██ SAST     ██████ Detector
     │  ░░ SAST     ░░░░░░ Verifier
    0└──────────────────────────────
       BEFORE         AFTER
       12 phút        3.5 phút
```

## 5. Trade-off

| Optimization | Cost (chất lượng) |
|---|---|
| O9 Top-K verifier | Có thể bỏ sót TP nếu detector confidence sai. Mitigate: tăng K khi findings ít. |
| O11 Pre-filter keyword | Bỏ sót semantic vuln không có keyword (hiếm). Mitigate: 10 % sampling. |
| O13 Collapse callers | Verifier có thể không hiểu context phức tạp. Mitigate: expand on demand. |
| O14 Dynamic few-shot | Cần index nhỏ → batch tra cứu thêm 0.1 s. Acceptable. |

## 6. Profiling

```bash
coba scan ./repo --profile

# Output:
# Stage Timing:
#   sast_prescan:    25.3 s
#   joern_build:     65.1 s (cache miss)
#   chunking:         4.2 s
#   rag_index:        8.0 s
#   detector:        78.4 s (par=4, n=98)
#   filters:          1.8 s
#   verifier:        51.2 s (par=4, n=22)
#   aggregate:        2.1 s
# Total:           236.1 s (3 min 56 s)
```

Implement bằng `time.perf_counter()` + `structlog.bind(stage=...).debug("done")`.

## 7. Scalability — repo lớn hơn

| LOC | Default time | Strategy |
|---|---|---|
| 10K | ~ 60 s | Default |
| 50K | ~ 4 phút | Default + cache |
| 200K | ~ 15 phút | + Pre-filter aggressive + Top-K verifier strict |
| 1M+ | ~ 1 h | Chunk by package, sample files, distributed (out of scope đề tài) |

## 8. Bảng nhanh ROI từng tối ưu

| Opt | Effort | Time saved | Phase |
|---|---|---|---|
| O1 Parallel LLM | Low | -225 s | M3 |
| O4 CPG cache | Low | -180 s (rerun) | M2 |
| O9 Top-K verifier | Low | -150 s | M3 |
| O5 LLM cache | Low | -200 s (rerun) | M2 |
| O15 Joern incremental | Med | -120 s | M4 |
| O11 Keyword pre-filter | Med | -120 s | M4 |
| O2 Batch embed | Low | -25 s | M2 |
| O3 Pipeline overlap | High | -60 s | M4 |
| Others | varies | ~ -100 s | M2-M4 |

Tổng tiềm năng: từ 12 phút → 3–4 phút (target).

## 9. Câu hỏi hay được hỏi

- **Q**: "Tối ưu nhiều thế sẽ giảm chất lượng không?"
  **A**: Có nguy cơ. CobA giữ `--profile=accuracy` (không skip, no Top-K, no keyword pre-filter) để so sánh trong eval. Sẽ báo cáo Precision/Recall cho cả `accuracy` và `fast` mode (Ch.6 § 6.4).

- **Q**: "Có dùng GPU không?"
  **A**: Có khi dùng local LLM (Qwen). Embedding (MiniLM) chạy CPU nhanh. Joern và Semgrep chạy CPU. RTX 4090 đủ cho Qwen 7B q4 + embedding song song.
