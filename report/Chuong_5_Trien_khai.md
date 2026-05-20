# Chương 5 — Triển khai

> Chương 5 trình bày toàn bộ phần *hiện thực hoá* kiến trúc đã thiết kế ở
> Chương 4: stack công nghệ, cấu trúc mã nguồn, các thành phần cốt lõi
> (LLM Router, SAST wrappers, Chunker, Detector, Verifier, RAG, Planner,
> Skip-cache), CLI / API, đóng gói Docker và quy trình CI/CD. Mục tiêu là
> để người đọc có thể *clone repo → cài đặt → chạy* được hệ thống và
> tự kiểm chứng các kết quả trong Chương 6 (Đánh giá).

## 5.1. Stack công nghệ

Hệ thống được hiện thực bằng **Python 3.11+**, cố ý chọn phiên bản tối
thiểu là 3.11 để dùng được `Self`, `LiteralString`, structural pattern
matching mượt và `asyncio.TaskGroup`. Toàn bộ phụ thuộc khai báo trong
`pyproject.toml` (build system Hatchling) — không dùng `requirements.txt`
nhằm tránh tình trạng "lock đôi". Bảng 5.1 liệt kê các thư viện trụ cột;
phiên bản chính xác xem `pyproject.toml`.

**Bảng 5.1 — Thư viện chính**

| Vai trò | Thư viện | Lý do chọn |
|---|---|---|
| Web API | `fastapi`, `uvicorn` | Async-first, type-driven, OpenAPI tự sinh |
| CLI | `typer`, `rich` | Trải nghiệm CLI hiện đại, type hint native |
| Schema & settings | `pydantic` v2, `pydantic-settings` | Validation nhanh + load `.env` đồng nhất |
| HTTP client | `httpx` (AsyncClient) | Connection pooling, HTTP/2, timeouts |
| Concurrency | `asyncio`, `anyio` | Cooperative I/O, tránh thread overhead |
| LLM providers | `openai`, `anthropic`, `google-generativeai`, `ollama` | SDK chính thức từng nhà cung cấp |
| RAG | `chromadb`, `sentence-transformers` | Vector store local + embedder MiniLM-L6-v2 |
| Code chunking | `tree_sitter`, `tree-sitter-languages` | Parser AST đa ngôn ngữ, tách hàm chính xác |
| Logging | `structlog` | Cấu trúc JSON, dễ tích hợp Loki/ELK |
| Testing | `pytest`, `pytest-asyncio`, `respx` | Async test + HTTP mock |
| Lint / format / type | `ruff`, `mypy --strict` | Tốc độ ruff, mypy bắt lỗi sớm |

**Bảng 5.2 — Công cụ ngoài (binary)**

| Tool | Vai trò | Cách cài |
|---|---|---|
| `semgrep` | Pattern matching đa ngôn ngữ | `pipx install semgrep` |
| `bandit` | Python-only security linter | `pipx install bandit` |
| `gitleaks` | Phát hiện secret trong code & git history | `brew install gitleaks` / binary release |
| `joern` (4.x) | CPG (Code Property Graph) builder + queries | `curl -fsSL joern.io/install.sh \| bash` |

Tất cả tool bên ngoài đều bị abstract bởi `coba.tools.base.SASTTool`;
nếu thiếu một tool nào đó, hệ thống *suy thoái mềm* (graceful
degradation) — chỉ log warning, không crash.

## 5.2. Cấu trúc mã nguồn

```
CobA/
├── src/coba/
│   ├── agent/              # planner, chunker, detector, verifier, rag, loop, callgraph, skip_cache
│   ├── api/                # FastAPI app + Pydantic request/response
│   ├── cli/                # Typer commands: scan, serve, doctor, models, eval
│   ├── config/             # Settings (pydantic-settings)
│   ├── data/               # cwe_top25.json, fewshot_examples.json
│   ├── eval/               # M4 — runner, metrics, matching, report
│   ├── llm/                # base, router, providers (openai/anthropic/gemini/ollama), cost
│   ├── prompts/            # detector.j2, verifier.j2
│   ├── tools/              # SAST wrappers + joern_queries/call_graph.sc
│   └── utils/              # schemas, logging, sanitize
├── tests/                  # 130+ pytest cases, không phụ thuộc LLM/internet
├── docs/                   # 12 tài liệu thiết kế (00–10 + references.bib)
├── examples/               # Source mẫu vulnerable per-language
├── benchmarks/             # configs + dataset placeholders
├── scripts/                # build_cwe_kb.py, download_datasets.sh
├── pyproject.toml          # build + deps + ruff + mypy + pytest config
├── Makefile                # install-dev, format, lint, typecheck, test, serve, …
├── Dockerfile              # multi-stage build, image cuối ≈ 280 MB
└── .github/workflows/      # CI (lint + typecheck + test) trên Python 3.11 & 3.12
```

Việc chia subpackage theo *trách nhiệm* (không phải theo kiểu MVC) phản
ánh kiến trúc Chương 4: `agent/` chứa lõi reasoning loop, `tools/` chỉ
quan tâm I/O với SAST binary, `llm/` chỉ lo provider abstraction. Mỗi
module có một docstring đầu file mô tả trách nhiệm.

## 5.3. LLM Router

`coba.llm.router.LLMRouter` là điểm vào duy nhất cho mọi cuộc gọi LLM.
Thiết kế tuân theo *strategy pattern*: router quyết định provider theo
một `RoutePolicy` được build từ `Settings` (cấu hình env), sau đó gọi
provider tương ứng thực hiện request. Trạng thái duy nhất router giữ là
`CostTracker` — bộ đếm chi phí daily/per-task an toàn về thread.

```python
class LLMRouter:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self.policy = RoutePolicy.from_settings(self.settings)
        self.cost = CostTracker(daily_budget_usd=self.settings.coba_llm_daily_budget_usd)
        self._providers: list[LLMProvider] = [
            OpenAIProvider(self.settings.openai_api_key),
            AnthropicProvider(self.settings.anthropic_api_key),
            GeminiProvider(self.settings.google_api_key),
            OllamaProvider(self.settings.ollama_base_url),
        ]
```

### 5.3.1. Provider abstraction

Mọi provider kế thừa `LLMProvider`:

```python
class LLMProvider(ABC):
    name: str

    @abstractmethod
    async def complete(
        self,
        model: str,
        messages: list[LLMMessage],
        *,
        temperature: float = 0.2,
        max_tokens: int | None = None,
        json_mode: bool = False,
    ) -> LLMResponse: ...
```

`LLMResponse` (Pydantic) gồm: `content: str`, `usage: LLMUsage`,
`provider: str`, `model: str`, `finish_reason`. Khi provider đó không
cấu hình API key, instance vẫn được tạo nhưng `is_available()` trả
`False` để router bỏ qua.

### 5.3.2. Routing policy

`RoutePolicy.choose(task: TaskKind)` ưu tiên theo thứ tự:

1. Model cụ thể được cấu hình cho task (`COBA_LLM_DETECTOR`,
   `COBA_LLM_VERIFIER`).
2. Provider của model đó còn budget và `is_available()`.
3. Nếu provider chính fail → fallback theo nhóm: cloud → cloud khác
   cùng tier giá; nếu `COBA_NO_CLOUD=true` → Ollama local.

Khi tất cả provider fail, router raise `ProviderUnavailable`; orchestrator
bắt lỗi và đánh dấu chunk đó `n_schema_rejected += 1` thay vì crash scan.

### 5.3.3. Cost tracker và budget

`CostTracker` giữ ledger thread-safe, tra giá theo bảng `MODEL_PRICES`
(`docs/06_LLM_INTEGRATION.md` § 1 và § 8). Mỗi response gọi
`tracker.record(model, task, usage)`; sau scan, tổng cost ghi vào
`ScanReport.stats.total_cost_usd`. Daily budget được kiểm tra trước
mỗi call; vượt ngưỡng → `BudgetExceeded`. Cộng thêm M3c (mục 5.10),
mỗi scan còn có **per-scan budget cap** kiểm soát ở tầng Orchestrator.

## 5.4. SAST tool wrappers

Bốn wrapper hiện có sống trong `src/coba/tools/`:

| Wrapper | Tool | Ngôn ngữ | Output → `StaticHint` |
|---|---|---|---|
| `SemgrepRunner` | Semgrep | Đa ngôn ngữ | rule_id + path + line + extra.cwe |
| `BanditRunner` | Bandit | Python | test_id (B###) + filename + line_number |
| `GitleaksRunner` | Gitleaks | Mọi text | rule + file + start_line |
| `JoernRunner` | Joern (CPG) | C/Java/JS/Python | rule “CPG-build” + call graph JSON |

Mỗi wrapper kế thừa `SASTTool`:

```python
class SASTTool(ABC):
    name: str
    languages: list[Language]
    binary: str

    def installed(self) -> bool:
        return shutil.which(self.binary) is not None

    @abstractmethod
    async def run(self, target: Path) -> list[StaticHint]: ...
```

`installed()` chỉ kiểm tra binary có trong `$PATH`. `run()` chạy
subprocess bất đồng bộ với `asyncio.create_subprocess_exec` để không
block event loop, kèm timeout cứng (Semgrep 300 s, Bandit 120 s,
Gitleaks 60 s, Joern 600 s). Mọi `StaticHint` đều mang trường `file`
(đường dẫn tuyệt đối đã canonicalize) — đây là kết quả của M2; chính
nhờ vậy mà `Planner.prioritize` và `_hints_for_chunk` có thể nối hint
với chunk chính xác.

Trường hợp parser fail (vd. Joern không build được CPG), wrapper trả
list rỗng và log structured error; orchestrator coi tool đó như “không
phát hiện gì” và tiếp tục.

## 5.5. Chunker và Planner

### 5.5.1. Tree-sitter chunker

`coba.agent.chunker.chunk_file` dùng `tree-sitter` với grammar tương
ứng ngôn ngữ:

```python
def chunk_file(
    file: Path,
    *,
    max_chars: int = 8000,
    window_lines: int = 200,
    window_overlap: int = 30,
    call_graph: CallGraph | None = None,
) -> list[Chunk]:
```

Thuật toán:

1. Đọc file (UTF-8, ignore BOM).
2. Map đuôi file → `Language` (`Language.from_path`).
3. Parse AST; duyệt cây tìm node hàm/method (`function_definition`,
   `method_declaration`, `class_method`, …). Mỗi node thoả mãn ngưỡng
   `max_chars` → một `Chunk` cấp hàm.
4. Nếu file không có hàm nào (script, module-level code) hoặc parser
   fail → fallback **window chunking**: cửa sổ 200 dòng, overlap 30.
5. Khi `call_graph` được cung cấp (M3a), gọi
   `_enrich_with_callgraph(chunks, call_graph)` để gắn `callers`/`callees`
   (top 20).

### 5.5.2. Planner — discover + chunk + prioritize

`Planner` (`src/coba/agent/planner.py`) có 3 trách nhiệm:

```python
class Planner:
    def discover_files(self, target: Path) -> list[Path]: ...
    def chunk_files(self, files, *, call_graph=None) -> list[Chunk]: ...
    @staticmethod
    def prioritize(
        chunks: list[Chunk], hints_by_file: dict[str, list[StaticHint]]
    ) -> list[Chunk]: ...
    def plan(self, target, *, call_graph=None) -> tuple[list[Path], list[Chunk]]: ...
```

- `discover_files`: walk thư mục, loại trừ `_IGNORE_DIRS`
  (`node_modules`, `dist`, `.git`, …) và đuôi không trong `_TEXT_EXTS`;
  bỏ file > 512 KB (`COBA_MAX_FILE_SIZE_KB`).
- `chunk_files`: gọi `chunk_file` cho từng file, swallow exception và
  log warning để 1 file lỗi không kéo sụp toàn scan.
- `prioritize` (M3c): xem § 5.10.

## 5.6. Detector

`coba.agent.detector.Detector` chuyển `Chunk + StaticHint[]` thành
`RawFinding[]` qua một LLM call duy nhất. Prompt nằm trong
`src/coba/prompts/detector.j2` (Jinja2) — phiên bản hoá ở dòng đầu
(`{# version: ... #}`).

Pseudo-code:

```python
async def detect(self, chunk: Chunk, hints: list[StaticHint] | None = None):
    hints = hints or []
    cwe_keys = [h.cwe for h in hints if h.cwe]
    cwe_ctx = [self.rag.by_cwe(k) for k in cwe_keys] or self.rag.query(
        hints=[h.message for h in hints], top_k=3
    )
    candidate_cwes = cwe_keys or [c.cwe_id for c in cwe_ctx if c]
    examples = self._collect_fewshot(chunk, candidate_cwes)  # M3b
    prompt = self._render_prompt(chunk, hints, cwe_ctx, examples)
    resp = await self.router.complete(
        TaskKind.DETECTOR,
        [LLMMessage(role=SYSTEM, content=_DETECTOR_SYSTEM),
         LLMMessage(role=USER, content=prompt)],
        temperature=0.0, max_tokens=1024, json_mode=True,
    )
    return _parse_raw_findings(resp.content)
```

Một số chi tiết quan trọng:

- **Temperature 0**: ép LLM deterministic để eval lặp lại được.
- **JSON mode**: bật `response_format` cho OpenAI / `tool_use` cho
  Anthropic / `response_mime_type` cho Google. Output luôn là JSON
  array gồm các object khớp schema `RawFinding`.
- **Sanitizer**: trước khi đưa vào prompt, `chunk.body` đi qua
  `sanitize_code_for_prompt` để vô hiệu hoá các pattern prompt-injection
  phổ biến (`Ignore all previous instructions`, fake system tag, …) —
  xem § 5.13.
- **Few-shot retrieval (M3b)**: `_collect_fewshot` round-robin các CWE
  bị hint, lấy tối đa `fewshot_k = 2` cặp `(vuln, safe)` từ
  `src/coba/data/fewshot_examples.json`. Ưu tiên ví dụ cùng ngôn ngữ
  với chunk.

Output mỗi `RawFinding` được validate qua Pydantic; nếu LLM trả mảng có
phần tử không hợp lệ (sai schema, line âm, v.v.), phần tử đó bị loại
và đếm vào `n_schema_rejected`.

## 5.7. Verifier

`coba.agent.verifier.Verifier` đóng vai trò *critic*: kiểm tra lại từng
`RawFinding` và trả `VerifyResult`:

```python
@dataclass
class VerifyResult:
    verdict: Verdict          # TRUE_POSITIVE | FALSE_POSITIVE | UNVERIFIED
    confidence: float         # 0..1
    rationale: str
```

Khác Detector ở chỗ:

- Dùng model mạnh hơn (`COBA_LLM_VERIFIER=claude-3-5-sonnet`).
- Prompt yêu cầu LLM xác định *cụ thể* taint source → sink hoặc lập luận
  vì sao đây là false positive.
- Output có cả `verdict` lẫn `confidence`, dùng để blend với confidence
  của Detector: `blended = 0.4 * detector_conf + 0.6 * verifier_conf`
  (ADR-009, M2).

Sau Verifier, các finding có `verdict=FALSE_POSITIVE` bị loại
(`n_verifier_rejected += 1`); những finding còn lại merge thành
`Finding` final.

## 5.8. RAG — knowledge base CWE + few-shot

CobA có hai *kho tri thức* phục vụ Detector:

### 5.8.1. CWE knowledge base

`RagIndex` (`src/coba/agent/rag.py`):

- **Built-in fallback**: bảng 18 CWE Top-25 (vừa đủ cho v0 prototype).
- **Chroma collection** (sau M2): `scripts/build_cwe_kb.py` parse MITRE
  CWE XML → embeddings MiniLM-L6-v2 → persist vào
  `.coba_data/chroma/cwe/`. `ChromaRagIndex` kế thừa cùng interface,
  load lazy.

API tra cứu: `by_cwe(id)` (exact lookup), `query(hints, top_k=3)`
(similarity search dùng text concatenated từ Semgrep messages).

### 5.8.2. Few-shot bank (M3b)

`src/coba/data/fewshot_examples.json` gồm 20 cặp `(vuln, safe,
explanation)` phủ 15 CWE × 5 ngôn ngữ (Python, Java, C, C++, JS).
`FewShotIndex.examples_for(cwe, language, top_k)`:

1. Lọc theo CWE id (case-insensitive).
2. Ưu tiên ví dụ cùng ngôn ngữ với chunk.
3. Fallback sang ngôn ngữ khác nếu thiếu.
4. Cắt còn `top_k` (default `k=2`).

Lý do giữ JSON thay vì Chroma: số lượng entry còn ít, cần *deterministic
ordering* để eval reproducible. Khi corpus ≥ 200 entries sẽ migrate sang
Chroma kèm re-ranker.

## 5.9. Call graph integration (M3a)

`coba.agent.callgraph.CallGraph` đại diện cho CPG callgraph thu gọn:
ánh xạ `(file, function) → callees[]` và `(file, function) → callers[]`.
`JoernRunner.extract_call_graph(target)` thực hiện:

```python
async def extract_call_graph(self, target: Path) -> CallGraph:
    if not self.installed():
        return EMPTY_CALL_GRAPH
    cpg = await self.build_cpg(target)         # cache theo Merkle hash
    if cpg is None:
        return EMPTY_CALL_GRAPH
    script = Path(__file__).parent / "joern_queries" / "call_graph.sc"
    rc, stdout, _ = await self._run_subprocess(
        [self.binary, "--script", str(script), "--param", f"cpg={cpg}"],
        timeout=300.0,
    )
    if rc != 0:
        return EMPTY_CALL_GRAPH
    return CallGraph.from_json(stdout)
```

Script Scala `call_graph.sc` emit JSON dạng:

```json
[{ "file": "src/auth.py", "function": "login", "line": 24,
   "callees": ["check_password", "issue_token"], "callers": ["handle_request"] }, ...]
```

Mọi sự cố (Joern thiếu, CPG fail, JSON sai) đều trả `EMPTY_CALL_GRAPH`
— orchestrator coi như callgraph trống và tiếp tục.

Khi callgraph có dữ liệu, `chunker._enrich_with_callgraph` gắn
`callers`/`callees` (cap 20) lên các chunk hàm; prompt Detector render
hai block "Callers" / "Callees" để LLM có ngữ cảnh inter-procedural —
giải quyết RQ4 trong eval (CPG-aware vs line-based recall).

## 5.10. Planner upgrade — priority queue, skip-cache, budget cap (M3c)

Chương 4 § 4.4 đã đưa ra ba tối ưu kế hoạch của M3c. Phần này mô tả
hiện thực:

### 5.10.1. Skip-cache theo SHA-256

`coba.agent.skip_cache.SkipCache` là cache content-addressed:

```python
class SkipCache:
    def __init__(self, cache_dir: Path, *, enabled: bool = True) -> None:
        self.root = Path(cache_dir) / "skip"
        if enabled:
            self.root.mkdir(parents=True, exist_ok=True)

    def get(self, sha256: str) -> SkipCacheRecord | None: ...
    def put(self, record: SkipCacheRecord) -> None: ...
```

- Mỗi file được hash SHA-256 nội dung bytes (`hash_file`).
- Record JSON lưu dưới `.coba_cache/skip/<aa>/<sha>.json` (shard 2 ký
  tự đầu để không bùng nổ entry trên một thư mục).
- Schema version `skip-cache.v1` — record khác schema bị treat as miss.
- Mọi lỗi I/O hoặc JSON corrupt: log debug, trả miss; cache hỏng không
  bao giờ kéo sập scan.
- File "sạch" (0 finding) vẫn được lưu record `n_findings=0` — nếu
  không, scan sạch sẽ re-scan mãi.

Trong Orchestrator (bước **2.5**), `_apply_skip_cache(files, chunks)`
phân tách:

```python
def _apply_skip_cache(self, files, chunks):
    cached_findings, chunks_to_scan, file_hashes = ..., ..., {}
    for f in files:
        sha = hash_file(f)
        if sha is None: continue
        file_hashes[_normalize_file_key(str(f))] = sha
        rec = self.skip_cache.get(sha)
        if rec is None: continue
        cached_findings.extend(rec.to_findings())
        cached_files.add(...)
    for ch in chunks:
        if _normalize_file_key(ch.file) not in cached_files:
            chunks_to_scan.append(ch)
    return cached_findings, chunks_to_scan, file_hashes
```

Cache hit `n_chunks_cache_hit = len(chunks) - len(chunks_to_scan)` được
ghi vào `ScanStats`.

### 5.10.2. Priority queue theo SAST hints

`Planner.prioritize(chunks, hints_by_file)` sort chunks giảm dần theo
*số* `StaticHint` rơi vào `[line_start, line_end]`:

```python
@staticmethod
def prioritize(chunks, hints_by_file):
    if not hints_by_file: return list(chunks)
    def score(chunk):
        key = _file_key(chunk.file)
        candidates = hints_by_file.get(key, []) + hints_by_file.get("_global", [])
        return sum(1 for h in candidates if chunk.line_start <= h.line <= chunk.line_end)
    return sorted(chunks, key=lambda c: (-score(c), c.file, c.line_start))
```

Tie-break deterministic (file alpha → line_start) để output report
reproducible.

### 5.10.3. Per-scan budget cap

Trước M3c, chỉ có *daily* budget ở LLMRouter (chống tốn vô hạn nhiều
session). M3c thêm cap **theo scan** trong `_run_detector`:

```python
async def _run_detector(self, chunks, hints_by_file):
    budget = self.settings.coba_scan_budget_usd
    skipped = 0
    results = []
    for chunk in chunks:
        if budget > 0 and self.router.cost.spent >= budget:
            skipped += 1; continue
        results.append(await one(chunk))
    return results, skipped
```

Setting `COBA_SCAN_BUDGET_USD=2.0` default; đặt `0` để tắt. Khi cap
chạm, log một lần duy nhất `orchestrator.budget_exhausted` và bỏ phần
còn lại. Vì queue đã prioritize, các chunk "nóng" được quét trước nên
recall không sụt khi cap chạm.

### 5.10.4. Persist sau scan

Sau khi merge cached + fresh findings (bước **4.5**),
`_persist_skip_cache` ghi *chỉ* các finding mới vào cache:

```python
def _persist_skip_cache(self, all_findings, chunks_scanned, file_hashes, cached_findings):
    scanned_files = {_normalize_file_key(c.file) for c in chunks_scanned}
    cached_id = {(f.file, f.line_start, f.cwe) for f in cached_findings}
    per_file = {k: [] for k in scanned_files}
    for f in all_findings:
        if (f.file, f.line_start, f.cwe) in cached_id: continue
        key = _normalize_file_key(f.file)
        if key in per_file: per_file[key].append(f)
    for key, findings in per_file.items():
        sha = file_hashes.get(key)
        if sha:
            self.skip_cache.put(SkipCacheRecord.from_findings(sha, key, findings))
```

Không tránh duplicate này, mỗi scan kế tiếp sẽ nhân đôi findings của
file cached.

## 5.11. CLI & API

### 5.11.1. CLI (`coba` command)

`src/coba/cli/main.py` dùng Typer:

```bash
coba scan <path> [--profile fast|accuracy] [--no-cloud] [--json]
coba serve [--host 0.0.0.0] [--port 8000]
coba doctor                # liệt kê tool nào installed, env vars, …
coba models                # in policy LLM hiện tại + giá
coba eval --config <name>  # M4: chạy eval pipeline
```

Mỗi command kèm rich progress bar (Rich library) khi chạy interactive;
khi stdout không phải TTY, output JSON-line cho CI scrape.

### 5.11.2. FastAPI app

`src/coba/api/app.py`:

```python
app = FastAPI(title="CobA", version=__version__)

@app.post("/scan", response_model=ScanReport)
async def scan(req: ScanRequest, orch: Orchestrator = Depends(get_orchestrator)):
    return await orch.scan(req)

@app.get("/health")
async def health(): return {"status": "ok", "version": __version__}
```

Pydantic Request/Response trùng schema dùng cho CLI — đảm bảo hợp đồng
duy nhất. OpenAPI docs tự sinh ở `/docs` (Swagger UI).

## 5.12. Đóng gói Docker

`Dockerfile` multi-stage:

```dockerfile
FROM python:3.11-slim AS builder
WORKDIR /app
COPY pyproject.toml .
RUN pip install --no-cache-dir build && pip install --no-cache-dir .

FROM python:3.11-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl unzip ca-certificates openjdk-21-jre-headless && \
    rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin
COPY src/ /app/src/
ENV PYTHONPATH=/app/src
ENTRYPOINT ["coba"]
```

Image cuối ≈ 280 MB (chưa kể model embeddings); thêm Joern qua volume
nếu cần CPG. `docker-compose.yml` (production mode):

```yaml
services:
  coba:
    build: .
    environment:
      - OPENAI_API_KEY
      - COBA_NO_CLOUD=false
    volumes:
      - ./.coba_data:/app/.coba_data
      - ./.coba_cache:/app/.coba_cache
    ports: ["8000:8000"]
    command: ["serve", "--host", "0.0.0.0"]
```

Cache & data được mount để snapshot ChromaDB và skip-cache không mất
giữa các container restart.

## 5.13. Bảo mật runtime

### 5.13.1. Sanitizer prompt-injection

`coba.utils.sanitize.sanitize_code_for_prompt` chèn marker `[SAFE-CODE]`
trước/sau code và regex-replace 18 mẫu prompt injection phổ biến (xem
`tests/data/prompt_injection_samples.txt`). Mọi `chunk.body` đưa vào
prompt LLM đều đi qua sanitizer.

### 5.13.2. Logging redaction

`structlog` chain có processor `redact_secrets` regex-match
`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, … và thay bằng `***`. Body
request POST tới `/scan` chứa source code không được log mặc định
(`coba_log_level=INFO`); muốn debug phải bật `DEBUG`.

### 5.13.3. No-cloud mode

`COBA_NO_CLOUD=true` (CLI: `--no-cloud`) ép `RoutePolicy` chỉ chọn
Ollama. Phù hợp khi quét repo của doanh nghiệp không được phép gửi code
ra ngoài. Verifier cũng đổi sang Ollama → chất lượng giảm (xem § 5.3
ADR-006 trong Chương 4) nhưng pipeline vẫn chạy.

## 5.14. Tổ chức cấu hình — Settings

`coba.config.settings.Settings` (pydantic-settings) là class duy nhất
load từ env / `.env`. Bảng 5.3 liệt kê các nhóm cấu hình chính (đầy đủ
ở `.env.example`).

**Bảng 5.3 — Nhóm settings**

| Nhóm | Biến quan trọng | Ví dụ giá trị |
|---|---|---|
| LLM API key | `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GOOGLE_API_KEY` | (provider auto-disable nếu thiếu) |
| LLM routing | `COBA_LLM_DETECTOR`, `COBA_LLM_VERIFIER`, `COBA_LLM_OFFLINE_FALLBACK` | `gpt-4o-mini`, `claude-3-5-sonnet`, `qwen2.5-coder:7b` |
| Budget | `COBA_LLM_DAILY_BUDGET_USD`, `COBA_SCAN_BUDGET_USD` | `5.0`, `2.0` |
| Tool binaries | `SEMGREP_BIN`, `JOERN_BIN`, `BANDIT_BIN`, `GITLEAKS_BIN` | đường dẫn override |
| Server | `COBA_HOST`, `COBA_PORT`, `COBA_LOG_LEVEL` | `0.0.0.0`, `8000`, `INFO` |
| RAG | `CHROMA_PERSIST_DIR`, `EMBEDDING_MODEL` | `.coba_data/chroma`, `all-MiniLM-L6-v2` |
| Limits | `COBA_MAX_FILE_SIZE_KB`, `COBA_PARALLEL_LLM_CALLS` | `512`, `4` |
| Cache | `COBA_SKIP_CACHE_ENABLED` | `true` |
| Privacy | `COBA_NO_CLOUD` | `false` |

## 5.15. Pipeline CI/CD

`.github/workflows/ci.yml` chạy với mỗi push lên `main` và mỗi pull
request → `main`:

```yaml
strategy:
  matrix:
    python-version: ["3.11", "3.12"]
steps:
  - uses: actions/checkout@v4
  - uses: actions/setup-python@v5
    with: { python-version: ${{ matrix.python-version }}, cache: pip }
  - run: pip install -e ".[dev]"
  - run: make lint
  - run: make typecheck
  - run: make test
```

`make lint` chạy `ruff format --check` + `ruff check`; `make typecheck`
chạy `mypy src` (strict mode); `make test` chạy `pytest -q`. Pre-commit
hook bản local thực thi cùng các bước này, nên CI hiếm khi đỏ vì lý do
format.

Tích hợp **Cubic AI code review** ở cấp PR (optional check): mỗi PR
được tự động sinh summary và phát hiện regression rủi ro thấp/trung;
review của con người vẫn là bước bắt buộc trước khi merge.

## 5.16. Testing strategy

Repo có ~130 unit test ở thời điểm cuối M3, chia nhóm:

| Nhóm | Số test (xấp xỉ) | Phạm vi |
|---|---|---|
| `tests/test_schemas.py` | 12 | Validate Pydantic schemas |
| `tests/test_sanitize.py` | 18 | Prompt injection corpus |
| `tests/test_tool_wrappers.py` | 18 | Mock subprocess output cho Semgrep/Bandit/Gitleaks/Joern |
| `tests/test_chunker*.py` | 11 | tree-sitter parse, window fallback |
| `tests/test_rag.py` + `test_fewshot_rag.py` | 14 | KB lookup + few-shot indexing |
| `tests/test_verifier.py` | 7 | Verifier blended confidence |
| `tests/test_eval_*.py` | 22 | Matching + metrics + runner |
| `tests/test_callgraph.py` + `test_chunker_callgraph.py` | 11 | CPG enrichment |
| `tests/test_skip_cache.py` | 9 | Cache roundtrip + corruption + clean files |
| `tests/test_planner_prioritize.py` | 6 | Priority queue ordering |
| `tests/test_orchestrator_*.py` | 11 | Cache + budget integration |

Tất cả test không gọi LLM thật (mock bằng `respx` cho HTTP, stub
provider cho async). Joern, Semgrep, Bandit cũng được mock bằng cách
override `subprocess.run`. Vì vậy `make test` chạy < 3 giây trên máy
laptop, đủ nhanh cho pre-commit.

## 5.17. Quy trình phát triển (dev workflow)

```bash
git clone https://github.com/nam091/CobA.git
cd CobA
make install-dev            # tạo venv, pip install -e ".[dev]", pre-commit install
make install-tools          # cài semgrep, bandit, gitleaks, joern (1 lần)
cp .env.example .env        # điền API keys vào .env

make format && make lint    # format + lint
make typecheck              # mypy src
make test                   # pytest

coba scan examples/vulnerable_python.py   # smoke run
coba serve                                # bật API server tại :8000
```

Quy ước branch: `devin/<unix_ts>-<short-desc>` (vd.
`devin/1779270227-planner-upgrade`); commit imperative mood ≤ 72 ký
tự dòng đầu. PR phải pass: `format`, `lint`, `typecheck`, `test`
trước khi gửi.

## 5.18. Tóm tắt

- Mã nguồn ≈ **6 000 LoC Python** (lõi) + 1 file Scala (Joern) + 130
  unit test, tổ chức theo subpackage chia theo trách nhiệm.
- Kiến trúc Chương 4 được hiện thực **đầy đủ**: LLMRouter (4 provider),
  4 SAST wrapper, tree-sitter chunker, Detector + Verifier (with
  blended confidence), RAG (CWE KB + few-shot), CPG-aware callgraph,
  skip-cache + priority queue + budget cap, FastAPI + CLI, Docker
  image, CI/CD GitHub Actions.
- Mọi tính năng cốt lõi đều có **suy thoái mềm**: thiếu tool / thiếu
  network / thiếu credential → log + tiếp tục, không crash. Đây là
  nền tảng để Chương 6 có thể chạy đánh giá lặp lại ở các môi trường
  khác nhau (laptop sinh viên, CI runner, máy chấm) mà không cần
  cấu hình đặc biệt.

Chương 6 sẽ trình bày khung đánh giá chi tiết (PrimeVul, OWASP
Benchmark) và kết quả thực nghiệm thực tế dựa trên hệ thống mô tả ở
đây.
