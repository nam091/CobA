# 03 — TOOLS: Mỗi tool dùng ở đâu, dùng như thế nào

> Bảng tổng hợp công cụ trong pipeline CobA. Mỗi tool có **vai trò**, **input/output**, **command cụ thể**, **lý do chọn**, **alternative đã loại**.

## 1. Tổng quan stack

| Layer | Tool | Vai trò | Ngôn ngữ hỗ trợ |
|---|---|---|---|
| Pre-scan SAST | **Semgrep** | Pattern matching theo rules YAML | Python, Java, C/C++, JS, Go, Ruby, … |
| Pre-scan (Python) | **Bandit** | SAST chuyên Python | Python only |
| Secret detection | **Gitleaks** | Tìm key/token hard-coded | All |
| Graph engine | **Joern** | CPG (AST+CFG+PDG), taint query | Python, Java, C/C++, JS |
| AST parser | **Tree-sitter** | AST chuẩn cho chunking | 30+ ngôn ngữ |
| Detector LLM | **GPT-4o-mini / Claude Haiku** | Phát hiện vuln semantic | All (input là text) |
| Verifier LLM | **Claude 3.5 Sonnet / GPT-4o** | Critique & confirm | All |
| Offline fallback | **Qwen2.5-Coder 7B/32B (Ollama)** | Local LLM khi không có cloud | All |
| Embedding | **sentence-transformers MiniLM L6 v2** | Vector hoá code/CWE | All |
| Vector DB | **ChromaDB** | RAG store | - |
| Web framework | **FastAPI** | HTTP API | - |
| CLI | **Typer** | CLI Python | - |
| Logging | **structlog** | Structured JSON log | - |

## 2. Semgrep — pre-scan SAST

### 2.1. Vai trò

Quét nhanh pattern-based để tìm "hot spots". Output → priority queue cho LLM Detector.

### 2.2. Input / Output

- **Input**: thư mục/file, ruleset YAML.
- **Output**: JSON với `results[].path`, `results[].start.line`, `results[].extra.metavars`, `results[].check_id` (mapping về CWE qua metadata).

### 2.3. Command cụ thể

```bash
# Default rules (semgrep registry, p/security-audit)
semgrep --config=p/security-audit \
        --config=p/owasp-top-ten \
        --config=p/cwe-top-25 \
        --json --quiet \
        --timeout 60 \
        --max-target-bytes 1000000 \
        /path/to/repo > semgrep.json

# Multi-language thì semgrep auto detect
# Custom rule riêng cho CobA:
semgrep --config=src/coba/tools/rules/semgrep/ ...
```

### 2.4. Wrapper code

`src/coba/tools/semgrep.py`:
```python
class SemgrepRunner(SASTTool):
    name = "semgrep"
    languages = ["python", "java", "c", "cpp", "javascript", "typescript"]
    DEFAULT_CONFIGS = ["p/security-audit", "p/owasp-top-ten", "p/cwe-top-25"]

    async def run(self, target: Path) -> list[Finding]:
        cmd = ["semgrep", *self._configs(), "--json", "--quiet", str(target)]
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=PIPE)
        raw = await proc.stdout.read()
        return self._normalize(json.loads(raw))
```

### 2.5. Lý do chọn

- Open source (LGPL-2.1).
- Hơn 2000 rules sẵn (p/security-audit, p/owasp-top-ten).
- Multi-lang ngay từ tool, không cần adapter.
- Fast (~30 s cho 50K LOC).
- Dễ viết rule custom (YAML, không cần Datalog/Scala).

### 2.6. Alternative đã loại

| Alt | Lý do loại |
|---|---|
| CodeQL | License hạn chế research/educational; query language khó (QL/Datalog) |
| SonarQube | Cần server riêng, license commercial cho rule advanced |
| Snyk Code | SaaS, không offline |
| Bearer | Tốt cho privacy nhưng ít CWE coverage |

## 3. Bandit — pre-scan Python

### 3.1. Vai trò

SAST chuyên Python (vì nhiều rule Python tốt hơn Semgrep).

### 3.2. Command

```bash
bandit -r /path/to/python/code \
       -f json \
       --skip B101 \
       --severity-level low \
       -o bandit.json
```

### 3.3. Wrapper

`src/coba/tools/bandit.py`. Chuẩn hoá `bandit.results[].issue_cwe.id` về schema `Finding`.

### 3.4. Lý do chọn

- De facto Python SAST.
- Maintained by PyCQA.

## 4. Gitleaks — secret detection

### 4.1. Vai trò

Tìm key, token, password hard-coded. CWE-798.

### 4.2. Command

```bash
gitleaks detect --source /path/to/repo \
                --report-format json \
                --report-path gitleaks.json \
                --no-banner --redact
```

### 4.3. Lý do chọn

- Open source (MIT).
- Detect ~150 loại secret pattern.
- Fast (Go binary).

## 5. Joern — CPG engine

### 5.1. Vai trò

Build Code Property Graph, query taint flow, call graph, data flow inter-procedural.

### 5.2. Input / Output

- **Input**: source dir (Python/Java/C/JS).
- **Output**: CPG binary file (`cpg.bin`), query results JSON.

### 5.3. Command

```bash
# 1) Parse
joern-parse /path/to/repo --output cpg.bin

# 2) Query (Scala script)
joern --script src/coba/tools/joern_queries/taint_sources.sc --param cpg=cpg.bin

# 3) Hoặc dùng joern-export để dump call graph
joern-export cpg.bin --repr ast --format json --out /tmp/joern_export/
```

### 5.4. Query scripts mẫu (`src/coba/tools/joern_queries/`)

#### `taint_user_input_to_sql.sc`
```scala
@main def main(cpg: String) = {
  importCpg(cpg)
  val sources = cpg.call.name(".*request.args.*|.*request.form.*").l
  val sinks   = cpg.call.name(".*execute.*|.*executemany.*").l
  val flows   = sources.reachableByFlows(sinks).p
  flows.foreach(println)
}
```

### 5.5. Wrapper

`src/coba/tools/joern.py`. Subprocess gọi `joern-parse` và `joern --script`. Cache `cpg.bin` theo hash content (skip rebuild nếu hash cũ).

### 5.6. Lý do chọn

- Open source (Apache-2.0).
- Multi-lang real (C, C++, Java, Python, JS, Go, PHP, Kotlin, Ruby experimental).
- CPG cho phép taint analysis inter-procedural.

### 5.7. Hạn chế

- Build CPG chậm (~1 phút cho 10K LOC, 5 phút cho 50K LOC).
- Memory cần ~4 GB cho repo lớn.
- Query language Scala (CPG Query Language - CPGQL) học curve cao.

**Mitigation**: cache CPG theo Merkle hash file. Pre-write 10–20 query phổ biến.

## 6. Tree-sitter — chunking

### 6.1. Vai trò

Parse AST cho 4 ngôn ngữ với cùng 1 API → cắt code theo function boundary.

### 6.2. Code

```python
from tree_sitter_languages import get_parser
parser = get_parser("python")
tree = parser.parse(source_bytes)
# duyệt tree, lấy function_definition nodes
```

### 6.3. Lý do chọn

- Bindings sẵn (`tree-sitter-languages`).
- Incremental parser (cập nhật khi edit).
- Là tool Github Code Search dùng → đáng tin.

## 7. LLM — Detector / Verifier / Embedding

Chi tiết riêng trong `06_LLM_INTEGRATION.md`. Quick summary ở đây:

| Vai trò | Default model | Lý do |
|---|---|---|
| Detector | GPT-4o-mini | Rẻ ($0.15/1M in), tốc độ tốt, đủ thông minh cho per-chunk task |
| Verifier | Claude 3.5 Sonnet | Khả năng reasoning cao, ít bịa hơn GPT khi critique |
| Offline fallback | Qwen2.5-Coder 7B | Best small code LLM 2024, fit RTX 4090 với q4 |
| Heavy reasoning (eval) | GPT-4o hoặc Claude Opus | Chỉ dùng eval comparison |
| Embedding | all-MiniLM-L6-v2 | Nhẹ (80 MB), tốc độ tốt, đủ dùng cho RAG |

## 8. ChromaDB — Vector DB cho RAG

### 8.1. Vai trò

Lưu embedding của CWE descriptions, CVE corpus, PrimeVul examples.

### 8.2. Setup

```python
import chromadb
client = chromadb.PersistentClient(path=".coba_data/chroma")
cwe_kb = client.get_or_create_collection("cwe_kb")
cwe_kb.add(
    documents=[entry.description for entry in cwe_entries],
    metadatas=[{"cwe_id": e.id, "type": "cwe"} for e in cwe_entries],
    ids=[e.id for e in cwe_entries],
)
```

### 8.3. Collections

| Collection | Số document (kỳ vọng) | Nguồn |
|---|---|---|
| `cwe_kb` | ~250 | MITRE CWE database |
| `cve_corpus` | ~5,000 | NVD top CVE + snippet |
| `primevul_examples` | ~3,000 pairs | PrimeVul subset |

## 9. FastAPI — API server

### 9.1. Endpoint

```
POST /scan           {target_path | git_url, languages?, profile?}  → ScanJob
GET  /scan/{id}                                                    → ScanReport
GET  /health
GET  /models
GET  /tools  (status + version các tool external)
```

### 9.2. Lý do chọn

Async, auto OpenAPI, dễ test. Không cần gRPC vì client là CLI/dev tool.

## 10. Typer — CLI

```bash
coba scan ./repo --languages python,java -o report.json
coba serve --port 8000
coba doctor                # check tool external
coba eval --dataset primevul
coba models                # list available LLMs
```

## 11. structlog — logging

- JSON output mặc định cho production.
- Console human-readable cho dev.
- Mỗi log có `trace_id` để correlate (scan_id).

## 12. Tổng kết — Pipeline 1 chunk

```
chunk (.py / .java / .c / .js)
    │
    ▼
[Tree-sitter parse AST] ─→ function boundary, neighbours via Joern call graph
    │
    ▼
[Semgrep / Bandit findings] ─→ inject as "static hints" vào prompt
    │
    ▼
[RAG retrieve] ─→ top-3 CWE entries + top-2 PrimeVul examples
    │
    ▼
[Detector LLM]  (GPT-4o-mini, temperature=0)
    │
    ▼
RawFinding
    │
    ▼
[Schema filter + dedup + line-range check]
    │
    ▼
[Verifier LLM] (Claude 3.5 Sonnet, temperature=0)
    │
    ▼
FinalFinding → ScanReport
```
