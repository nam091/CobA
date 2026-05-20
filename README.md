# CobA — Code-base Audit Agent

> **LLM-powered Source Code Vulnerability Analysis Agent**
> Đồ án nghiên cứu: *"Nghiên cứu ứng dụng LLM trong phân tích lỗ hổng an toàn mã nguồn"*

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/nam091/CobA/actions/workflows/ci.yml/badge.svg)](https://github.com/nam091/CobA/actions/workflows/ci.yml)

## 1. Giới thiệu

**CobA** (đọc là "co-ba", viết tắt của *Code-base Audit*) là một AI agent phân tích lỗ hổng an toàn mã nguồn, kết hợp giữa:

- **SAST truyền thống** (Semgrep, CodeQL, Joern, Bandit, Gitleaks) — đảm bảo độ phủ rules đã chuẩn hoá theo OWASP/CWE.
- **LLM hybrid** (cloud + local) — phát hiện các lỗ hổng *semantic* mà SAST bỏ sót (taint flow phức tạp, logic flaw, business logic bypass).
- **RAG (Retrieval-Augmented Generation)** trên knowledge base lỗ hổng (CWE, CVE, PrimeVul, DiverseVul, OWASP Top 10) — giảm hallucination, neo câu trả lời vào fact.
- **Verifier agent** — chấm lại từng phát hiện bằng LLM khác để loại false positive trước khi báo cáo.

Hệ thống hỗ trợ **multi-language**: Python, Java, C/C++, JavaScript/TypeScript.

## 2. Mục tiêu nghiên cứu (SMART)

| # | Mục tiêu | Đo bằng |
|---|---|---|
| O1 | Phát hiện ≥ **70 %** lỗ hổng trong tập PrimeVul (subset 1K) với **F1 ≥ 0.55** | F1, Precision, Recall trên PrimeVul v0.1 |
| O2 | Tỷ lệ **false positive ≤ 25 %** trên OWASP Benchmark v1.2 | FP rate sau verifier |
| O3 | Phân tích repo **50K LOC < 10 phút** trên 1 máy 16 vCPU + 1×4090 | Wall-clock time |
| O4 | Hỗ trợ ≥ **20 CWE** thường gặp (Top 25 CWE 2024) | Coverage matrix |
| O5 | Báo cáo có thể **reproduce** (dataset + seed + config) | Quy trình eval script `make eval` |

Chi tiết: <a href="docs/01_PLAN.md">`docs/01_PLAN.md`</a>.

## 3. Kiến trúc tổng quan (Context view)

```
┌─────────────────────────────────────────────────────────────────────┐
│                          Người dùng (CLI / Web UI)                  │
└───────────────────────────────────┬─────────────────────────────────┘
                                    │
┌───────────────────────────────────▼─────────────────────────────────┐
│                       CobA Orchestrator (FastAPI)                   │
│   ┌──────────┐  ┌──────────────┐  ┌─────────────┐  ┌─────────────┐  │
│   │ Planner  │→│  Static-tool  │→│ LLM Analyzer│→│ LLM Verifier│  │
│   │ (chunker)│  │  Runner       │  │ (Detector)  │  │ (Critic)    │  │
│   └──────────┘  └──────────────┘  └─────────────┘  └─────────────┘  │
│                         │                  ▲                ▲       │
│                         ▼                  │                │       │
│                    ┌─────────┐         ┌───┴────┐      ┌────┴───┐  │
│                    │  Joern  │         │  RAG   │      │ CWE/CVE│  │
│                    │  CPG    │         │ Vector │      │ Knowl. │  │
│                    └─────────┘         └────────┘      └────────┘  │
└─────────────────────────────────────────────────────────────────────┘
                                    │
┌───────────────────────────────────▼─────────────────────────────────┐
│           LLM Router (Hybrid)                                       │
│   Cloud: GPT-4o-mini · Claude 3.5 Haiku/Sonnet · Gemini 1.5 Flash   │
│   Local: Qwen2.5-Coder 7B/32B · Llama 3.1 8B · DeepSeek-Coder V2    │
└─────────────────────────────────────────────────────────────────────┘
```

Chi tiết 5 view (C4): <a href="docs/02_ARCHITECTURE.md">`docs/02_ARCHITECTURE.md`</a>.

## 4. Quick start

```bash
git clone https://github.com/nam091/CobA.git
cd CobA
make install            # cài Python deps + tải Semgrep rules

cp .env.example .env    # điền API keys (OPENAI_API_KEY, ANTHROPIC_API_KEY, ...)

# Quét một file đơn
coba scan examples/vulnerable_samples/python/sql_injection.py

# Quét cả thư mục (multi-language)
coba scan /path/to/repo --languages python,java,c,javascript --report report.json

# Chạy API server
coba serve --host 0.0.0.0 --port 8000
# → POST /scan {"path": "..."}  curl http://localhost:8000/scan
```

## 5. Cấu trúc repo

```
CobA/
├── docs/                # 12 file thiết kế chi tiết (PLAN, ARCH, TOOLS, ...)
├── src/coba/            # Source code Python
│   ├── api/             # FastAPI app
│   ├── agent/           # Agent loop: planner, analyzer, verifier
│   ├── llm/             # LLM router (OpenAI / Anthropic / Gemini / Ollama)
│   ├── tools/           # Wrappers: Semgrep, Joern, Bandit, Gitleaks, Tree-sitter
│   ├── config/          # Settings (pydantic-settings)
│   ├── prompts/         # Prompt templates (Jinja2)
│   ├── cli/             # Typer CLI
│   └── utils/           # Chunking, logging, schemas
├── tests/               # pytest
├── examples/            # Mẫu code có lỗ hổng để test
│   └── vulnerable_samples/{python,java,c,javascript}
├── benchmarks/          # PrimeVul/OWASP eval scripts
├── report/              # Báo cáo khoá luận (Markdown → LaTeX)
│   ├── Chuong_1_Tong_quan.md
│   ├── Chuong_2_Co_so_ly_thuyet.md
│   └── Chuong_3_Khao_sat_lien_quan.md
├── scripts/             # Helper scripts (download datasets, build CPG, ...)
└── .github/workflows/   # CI: lint, type-check, test
```

## 6. Tiến độ (Roadmap 16 tuần)

| Milestone | Tuần | Trạng thái |
|---|---|---|
| M1 — Design docs + repo skeleton + prototype | 1–3 | **In progress** |
| M2 — Eval pipeline + PrimeVul subset 1K | 4–6 | Planned |
| M3 — Verifier + RAG + multi-language full | 7–9 | Planned |
| M4 — Performance optimization (parallel, cache) | 10–12 | Planned |
| M5 — Báo cáo hoàn chỉnh + bảo vệ | 13–16 | Planned |

Chi tiết: <a href="docs/01_PLAN.md">`docs/01_PLAN.md`</a> § Timeline.

## 7. Đóng góp khoa học có thể claim

1. **Pipeline hybrid SAST + LLM detector + LLM verifier + RAG** — kết hợp 4 thành phần, mỗi thành phần giảm điểm yếu của thành phần kia (xem `docs/02_ARCHITECTURE.md` § Justification).
2. **Multi-language CPG-aware chunking** — chunking dựa trên Joern CPG để giữ ngữ cảnh function-level và inter-procedural, không cắt giữa hàm (xem `docs/05_CODE_UNDERSTANDING.md`).
3. **Cost-aware LLM routing** — chọn model theo độ khó & cost budget; có local fallback khi offline (xem `docs/06_LLM_INTEGRATION.md`).
4. **Bộ benchmark Vietnamese-friendly** — đánh giá trên PrimeVul + OWASP Benchmark + case study repo Việt (xem `docs/08_EVALUATION.md`).

## 8. Tham khảo nhanh

- 📄 [docs/00_OVERVIEW.md](docs/00_OVERVIEW.md) — Tóm tắt + FAQ
- 🛠️ [docs/03_TOOLS.md](docs/03_TOOLS.md) — Mỗi tool dùng ở đâu, dùng như thế nào
- 📚 [docs/04_DATA_SOURCES.md](docs/04_DATA_SOURCES.md) — Dataset, trust score, license
- 🧠 [docs/06_LLM_INTEGRATION.md](docs/06_LLM_INTEGRATION.md) — Các LLM đã tích hợp
- ⚡ [docs/07_PERFORMANCE.md](docs/07_PERFORMANCE.md) — Bottleneck + tối ưu tốc độ
- 📖 [report/Chuong_1_Tong_quan.md](report/Chuong_1_Tong_quan.md) — Báo cáo Chương 1

## 9. Citation

Nếu bạn dùng CobA cho nghiên cứu, vui lòng cite:

```bibtex
@misc{coba2026,
  author = {Lã Phương Nam},
  title  = {CobA: An LLM-powered Source Code Vulnerability Analysis Agent},
  year   = {2026},
  url    = {https://github.com/nam091/CobA}
}
```

## 10. License

MIT — xem [LICENSE](LICENSE).
