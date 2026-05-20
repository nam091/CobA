# 02 — ARCHITECTURE: 5 view + ADR

> Mô tả kiến trúc hệ thống CobA theo 5 view của C4 (Context, Container, Component, Sequence, Deployment) + Architecture Decision Records (ADR).

## 1. View 1 — System Context

```
┌──────────────────────────────────────────────────────────────────────────┐
│                                                                          │
│   ┌────────────┐                                                         │
│   │  Developer │───── code path / git URL ──────┐                        │
│   └────────────┘                                ▼                        │
│                                       ┌──────────────────┐               │
│                                       │       CobA       │               │
│                                       │  (Audit Agent)   │               │
│                                       └────────┬─────────┘               │
│                                                │                         │
│         ┌──────────────────┬────────────┬──────┴──────────┬────────────┐ │
│         │                  │            │                 │            │ │
│         ▼                  ▼            ▼                 ▼            ▼ │
│   ┌──────────┐     ┌──────────────┐  ┌─────────┐    ┌──────────┐ ┌──────┐│
│   │  LLM     │     │  Static      │  │  Joern  │    │  CWE/CVE │ │ Git  ││
│   │  APIs    │     │  SAST tools  │  │  CPG    │    │  KB      │ │ host ││
│   │ (Cloud + │     │ (Semgrep,    │  │ (local) │    │ (RAG)    │ │      ││
│   │  Local)  │     │  Bandit, …)  │  │         │    │          │ │      ││
│   └──────────┘     └──────────────┘  └─────────┘    └──────────┘ └──────┘│
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

**External actors / systems**:

| # | Actor / System | Vai trò | Protocol |
|---|---|---|---|
| 1 | Developer | Submit code, đọc report | CLI / HTTP |
| 2 | LLM APIs (OpenAI, Anthropic, Google) | Detector + Verifier | HTTPS REST |
| 3 | Local LLM (Ollama / vLLM) | Offline fallback | HTTP localhost |
| 4 | Static SAST tools | Pre-scan | Subprocess (CLI binary) |
| 5 | Joern | CPG build & query | Subprocess + JSON output |
| 6 | CWE/CVE knowledge base | RAG retrieval | Local Chroma vector DB |
| 7 | Git host | Clone repo nếu input là URL | HTTPS git |

## 2. View 2 — Container

```
┌─────────────────────────────────────── CobA process ───────────────────────────────────────┐
│                                                                                            │
│  ┌─────────────────┐    ┌─────────────────────────────────────────────────────────────┐   │
│  │   FastAPI       │    │                      Orchestrator                            │   │
│  │   (api/)        │───▶│  (agent/loop.py — coordinator)                              │   │
│  │   POST /scan    │    │                                                              │   │
│  └─────────────────┘    └──────┬──────────┬─────────────┬──────────────┬──────────────┘   │
│                                │          │             │              │                  │
│  ┌─────────────────┐    ┌──────▼──────┐  ┌▼─────────┐  ┌▼──────────┐  ┌▼─────────────┐  │
│  │   Typer CLI     │    │  Planner    │  │  Static  │  │  Detector │  │  Verifier    │  │
│  │   (cli/)        │    │  (agent/    │  │  Runner  │  │  (agent/  │  │  (agent/     │  │
│  │   coba scan ... │───▶│  planner)   │  │  (tools/)│  │  detector)│  │  verifier)   │  │
│  └─────────────────┘    └─────────────┘  └──────────┘  └─────┬─────┘  └──────┬───────┘  │
│                                                              │                │          │
│                                            ┌─────────────────▼──┐    ┌────────▼───────┐  │
│                                            │   LLM Router       │    │   RAG          │  │
│                                            │   (llm/router)     │    │   (agent/rag)  │  │
│                                            │   ── openai        │    │   ── chroma    │  │
│                                            │   ── anthropic     │    │   ── embedder  │  │
│                                            │   ── gemini        │    └────────────────┘  │
│                                            │   ── ollama        │                        │
│                                            └────────────────────┘                        │
│                                                                                            │
└────────────────────────────────────────────────────────────────────────────────────────────┘
```

**Containers (logical, all in 1 OS process for prototype)**:

| Container | Trách nhiệm | Module |
|---|---|---|
| API | HTTP endpoint (POST /scan, /health, /models) | `coba.api` |
| CLI | Local invocation, hiển thị progress | `coba.cli` |
| Orchestrator | Coordinator: chia task, gọi tool, gọi LLM | `coba.agent.loop` |
| Planner | Chia repo → chunks, ưu tiên file nghi vấn | `coba.agent.planner` |
| Static Runner | Wrap & merge output từ Semgrep/Bandit/Gitleaks | `coba.tools` |
| Joern CPG | Build CPG, query taint/call graph | `coba.tools.joern` |
| LLM Router | Provider-abstract, retry, cost tracking | `coba.llm.router` |
| Detector | Prompt LLM tìm vuln trong chunk | `coba.agent.detector` |
| Verifier | Critique từng finding, reject FP | `coba.agent.verifier` |
| RAG | ChromaDB CWE/CVE/PrimeVul KB | `coba.agent.rag` |

## 3. View 3 — Component

### 3.1. Orchestrator (`agent/loop.py`)

```
ScanRequest
    │
    ▼
┌─────────────────────┐
│  resolve_target()   │  (path or git URL → local dir)
└──────────┬──────────┘
           ▼
┌─────────────────────┐
│  planner.plan()     │  → ScanPlan { files, chunks, priorities }
└──────────┬──────────┘
           ▼
┌─────────────────────────┐
│  parallel: static_runner│  → StaticFindings
│         joern.build_cpg │  → CPG handle
└──────────┬──────────────┘
           ▼
┌─────────────────────────┐
│  for chunk in priority: │
│    rag = retrieve(chunk)│
│    raw = detector(chunk,│
│              rag)       │ → RawFindings
└──────────┬──────────────┘
           ▼
┌─────────────────────────┐
│  for f in raw:          │
│    if cheap_filters(f): │  ← dedup vs static, line-range valid
│      v = verifier(f)    │
│      keep if v.confirm  │
└──────────┬──────────────┘
           ▼
       Aggregate → ScanReport (JSON)
```

### 3.2. LLM Router (`llm/router.py`)

```
                           ┌──────────────────┐
LLMRequest(task, prompt) → │      Router      │
                           │  - policy.yaml   │
                           │  - cost tracker  │
                           │  - rate limit    │
                           └────┬──────┬──────┘
                                │      │ (fallback if error/budget)
                  ┌─────────────┘      └────────────┐
                  ▼                                 ▼
            ┌──────────────┐                  ┌──────────────┐
            │ Cloud Provid.│                  │  Local       │
            │  - openai    │                  │  - ollama    │
            │  - anthropic │                  │  - vllm      │
            │  - gemini    │                  └──────────────┘
            └──────────────┘
```

### 3.3. RAG (`agent/rag.py`)

```
chunk + finding_hypothesis
        │
        ▼
  embedder (sentence-transformers MiniLM)
        │
        ▼
 ChromaDB (.coba_data/chroma)
   ├─ collection: cwe_kb         (~ 250 entries, CWE description + examples)
   ├─ collection: cve_corpus     (~ 5K curated CVEs với code snippet)
   └─ collection: primevul_examples (few-shot vuln/fixed pairs)
        │
        ▼
 top-k snippets → inject into Detector prompt
```

## 4. View 4 — Sequence (POST /scan happy path)

```
Client    API    Orchestrator   Planner   StaticRunner   Joern    LLM-Router   RAG    Verifier
  │ POST   │       │              │           │             │           │         │        │
  │──────▶│       │              │           │             │           │         │        │
  │       │ scan()│              │           │             │           │         │        │
  │       │─────▶│              │           │             │           │         │        │
  │       │       │ plan()       │           │             │           │         │        │
  │       │       │─────────────▶│           │             │           │         │        │
  │       │       │◀─── ScanPlan ┤           │             │           │         │        │
  │       │       │                                                                       │
  │       │       │  ┌──────────────────────────────────┐                                  │
  │       │       │  │ parallel:                         │                                 │
  │       │       │  │   static_runner.run() ───────────▶│                                 │
  │       │       │  │   joern.build_cpg() ─────────────────────▶│                         │
  │       │       │  │◀─ findings, cpg                   │                                 │
  │       │       │  └──────────────────────────────────┘                                  │
  │       │       │                                                                        │
  │       │       │  for each chunk (priority order):                                      │
  │       │       │     ctx = rag.retrieve(chunk) ───────────────────────────▶             │
  │       │       │     ◀─ snippets                                                        │
  │       │       │     raw = detector(chunk, ctx) ──────────────────▶ Router              │
  │       │       │     ◀─ raw findings                                                    │
  │       │       │                                                                        │
  │       │       │  for f in raw:                                                         │
  │       │       │     if pass_filters(f):                                                │
  │       │       │        v = verifier.verify(f) ─────────────────────────────▶           │
  │       │       │        ◀─ verdict                                                      │
  │       │       │                                                                        │
  │       │       │ aggregate → ScanReport                                                 │
  │       │◀──────│                                                                        │
  │◀──────│ 200 OK                                                                         │
```

## 5. View 5 — Deployment

### 5.1. Dev / single-machine

```
┌─────────────────── Developer machine ──────────────────────┐
│                                                            │
│  ┌──────────────┐   subprocess  ┌──────────┐               │
│  │  coba (CLI)  │──────────────▶│ Semgrep  │               │
│  └──────────────┘               └──────────┘               │
│         │                                                  │
│         │ subprocess          ┌──────────────┐             │
│         ├────────────────────▶│  Joern CLI   │             │
│         │                     └──────────────┘             │
│         │                                                  │
│         │ HTTP localhost      ┌──────────────┐             │
│         ├────────────────────▶│  Ollama      │             │
│         │ :11434              │  + GPU model │             │
│         │                     └──────────────┘             │
│         │                                                  │
│         │ HTTPS              (Internet)                    │
│         ├────────────────────▶ OpenAI / Anthropic / Google │
│         │                                                  │
│         │ file r/w           ┌──────────────┐              │
│         └────────────────────▶│  ChromaDB   │              │
│                              │ (.coba_data/)│              │
│                              └──────────────┘              │
└────────────────────────────────────────────────────────────┘
```

### 5.2. Server / CI deployment

```
┌─── Docker container `coba:latest` ───┐    ┌─── Sidecar (optional) ───┐
│  - FastAPI + Uvicorn on :8000        │◀───│  Ollama with Qwen2.5     │
│  - Semgrep, Bandit, Gitleaks bundled │    │  Coder 7B on :11434      │
│  - Joern installed                   │    └──────────────────────────┘
│  - Mounted volume:                   │
│      /workspace ← code to scan       │
│      /data       ← ChromaDB persist  │
└──────────────────────────────────────┘
                │
                ▼ HTTPS (egress)
        OpenAI / Anthropic / Gemini
```

## 6. Architecture Decision Records (ADR)

### ADR-001: Sử dụng Python 3.11+ làm ngôn ngữ chính

- **Status**: Accepted
- **Context**: Cần ngôn ngữ có hệ sinh thái LLM, AST tốt, dễ dạy/hiểu cho sinh viên.
- **Decision**: Python 3.11+ (cho `Self`, `TypedDict.NotRequired`, asyncio cải tiến).
- **Alternatives**: Go (deploy nhỏ, ít ML), Rust (an toàn nhưng curve dốc), Node (LLM SDK kém phong phú).
- **Consequences**: Có thể chậm hơn Go/Rust khi xử lý CPU-bound; mitigate bằng cách offload sang subprocess (Joern, Semgrep) và async I/O.

### ADR-002: Hybrid LLM (cloud + local) thay vì chỉ cloud

- **Status**: Accepted
- **Context**: Budget hạn chế, yêu cầu offline, reproducibility.
- **Decision**: Detector = cloud (GPT-4o-mini, default), Verifier = cloud premium (Claude 3.5 Sonnet); local Qwen2.5-Coder-7B làm fallback. Có thể switch policy qua config.
- **Consequences**: Phức tạp router; bù lại linh hoạt và tiết kiệm.

### ADR-003: Joern là CPG engine chính, không phải CodeQL

- **Status**: Accepted
- **Context**: Cần graph kết hợp AST + CFG + PDG, hỗ trợ nhiều ngôn ngữ, open source.
- **Decision**: Joern (Apache-2.0).
- **Alternatives**: CodeQL (license hạn chế research/educational, không thoải mái); Tree-sitter (chỉ AST, thiếu CFG/PDG).
- **Consequences**: Học curve cao; chuyển script Scala/Python.

### ADR-004: Semgrep làm "first pass", LLM làm "second pass"

- **Status**: Accepted
- **Context**: Đa số CWE pattern đã có rules; chạy LLM hết file rất tốn.
- **Decision**: Semgrep + Bandit + Gitleaks chạy trước, lọc ra hot files; LLM chỉ scan hot files + 1 vài random files để giữ recall.
- **Consequences**: Có nguy cơ bỏ sót lỗ hổng pattern không có rule. Mitigate: thêm sampling 10 % file ngẫu nhiên cho LLM.

### ADR-005: ChromaDB cho RAG (không Qdrant/Weaviate)

- **Status**: Accepted
- **Context**: Cần vector DB nhỏ gọn, embed trong process, không cần server.
- **Decision**: ChromaDB persistent client.
- **Alternatives**: Qdrant (cần server), pgvector (cần Postgres), FAISS (không có persistence built-in).
- **Consequences**: Performance OK cho < 1M vector; nếu scale lớn → switch sang Qdrant.

### ADR-006: Tree-sitter cho cross-language chunking

- **Status**: Accepted
- **Context**: Cần parse AST cho 4 ngôn ngữ với 1 API thống nhất.
- **Decision**: `tree-sitter-languages` (binding sẵn cho 30+ ngôn ngữ).
- **Alternatives**: Mỗi ngôn ngữ 1 parser riêng (ast, javalang, …) → 4× code.

### ADR-007: FastAPI thay vì Flask hoặc gRPC

- **Status**: Accepted
- **Context**: Cần async (vì LLM call), auto OpenAPI schema, dễ deploy.
- **Decision**: FastAPI.

### ADR-008: Anti-hallucination 3 lớp (cite + RAG + verifier)

- **Status**: Accepted
- **Context**: LLM hay bịa lỗ hổng, đặc biệt model nhỏ.
- **Decision**: Mọi finding bị reject nếu (1) không có `line_start`/`line_end` hợp lệ; (2) cite CWE không tồn tại; (3) verifier không re-derive được. Detail in `docs/05_CODE_UNDERSTANDING.md` § 5.

## 7. Anti-hallucination — chi tiết

```
RawFinding from Detector
    │
    ▼
┌───────────────────────────────┐
│ Filter 1: schema validation   │  ← line range int, CWE in dictionary, severity ∈ enum
└──────────────┬────────────────┘
               │ valid
               ▼
┌───────────────────────────────┐
│ Filter 2: dedup vs static     │  ← if Semgrep already flagged same (file, line, cwe) → boost confidence; do not add new
└──────────────┬────────────────┘
               │
               ▼
┌───────────────────────────────┐
│ Filter 3: range exists in file│  ← read file, check line range exists, non-empty
└──────────────┬────────────────┘
               │
               ▼
┌───────────────────────────────┐
│ Verifier LLM (different model)│  ← prompt critique: "is this really vuln? cite same lines"
└──────────────┬────────────────┘
               │ keep if confirmed
               ▼
           FinalFinding
```

## 8. Non-functional requirements

| NFR | Yêu cầu | Cách đo |
|---|---|---|
| Performance | < 10 phút cho 50K LOC | E2E timing trên repo Flask v3 |
| Cost | < 0.5 USD / repo trung bình | Cost log từ router |
| Reliability | 0 crash trên test suite 100 repo OSS | CI gauntlet test |
| Reproducibility | Cùng input → output đồng nhất (đến cỡ confidence) | Seed cố định + LLM temperature=0 + dedup |
| Privacy | Local fallback khi opt-in | `--no-cloud` flag không gọi cloud LLM |
| Observability | Có log từng bước + cost report | structlog + JSON log |
| Extensibility | Thêm tool mới ≤ 100 LOC | Interface `SASTTool` |
| Maintainability | Test coverage ≥ 60 % | pytest-cov |
