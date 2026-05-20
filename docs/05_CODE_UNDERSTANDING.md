# 05 — CODE UNDERSTANDING: Cách agent đọc/hiểu code

> Hệ thống đọc code **theo từng phần**, không đọc toàn bộ. Tài liệu này mô tả 5 quyết định cốt lõi:
> (1) Chunking ra sao, (2) Context bao nhiêu, (3) Prompt structure, (4) Anti-hallucination, (5) Cross-file reasoning.

## 1. Chunking strategy — CPG-aware

### 1.1. Vấn đề của chunking truyền thống

- **Line-based** (mỗi 200 dòng): cắt giữa hàm → mất ngữ cảnh.
- **Token-based** (LangChain RecursiveSplitter): không tôn trọng cấu trúc syntax.
- **File-based**: file lớn vượt context window.

### 1.2. Giải pháp CobA — Hybrid Function + CPG

Pseudo-algorithm:

```python
def chunk(file: Path) -> list[Chunk]:
    ast = tree_sitter.parse(file)
    functions = [node for node in ast.walk() if node.type == "function_definition"]

    chunks = []
    for fn in functions:
        # 1) main body of the function
        body = source[fn.start_byte:fn.end_byte]

        # 2) callers (via Joern call graph) — collapsed to signature only
        callers = joern.callers_of(fn.name, max=3, language=file.lang)
        caller_signatures = [c.signature for c in callers]

        # 3) callees (out-going calls) — same treatment
        callees = joern.callees_of(fn.name, max=5)

        # 4) imports / class context
        imports = file_imports(file)

        chunk = Chunk(
            language=file.lang,
            file=file.path,
            function=fn.name,
            line_start=fn.start_line,
            line_end=fn.end_line,
            body=body,
            callers=caller_signatures,
            callees=[c.signature for c in callees],
            imports=imports,
        )

        # 5) ensure within token budget (default ≤ 2000 tokens)
        if estimate_tokens(chunk) > 2000:
            chunk = trim(chunk, keep=["body", "imports"])

        chunks.append(chunk)

    # files without functions (config/script): fall back to 200-line windows
    if not functions:
        chunks = window_split(file, lines=200, overlap=30)

    return chunks
```

### 1.3. Lý do hiệu quả

- Function là **unit ngữ nghĩa** tự nhiên — vuln thường xảy ra ở 1 function.
- Caller signatures cho LLM biết "ai gọi tới hàm này với input gì" (taint context).
- Callees giúp đoán "hàm này gọi sink không" (vd. `execute`, `system`).
- Imports/use statements giúp đoán framework (Flask, Spring, Express).

## 2. Context budget

| Phần | Max tokens | Lý do |
|---|---|---|
| System prompt | 800 | Định nghĩa task, format output |
| Few-shot examples | 600 | 2 examples = ~ 300 token mỗi |
| RAG snippets (CWE + similar vuln) | 600 | 3 CWE + 2 PrimeVul examples |
| Code chunk body | 2,000 | ≈ 80–120 LOC |
| Caller/callee signatures | 200 | 3 caller + 5 callee |
| Imports | 100 | 5–10 import line |
| Static hints (Semgrep finding) | 100 | 1–3 hint |
| **Total input** | **~ 4,400** | Fit GPT-4o-mini (128K), Qwen 7B (32K) thoải mái |
| **Output budget** | 1,000 | JSON findings array |

## 3. Prompt structure

`src/coba/prompts/detector.j2`:

```
SYSTEM:
You are a senior application-security engineer. You audit source code chunks for vulnerabilities.
You MUST output strict JSON matching the schema. Cite line ranges that exist in the chunk.
Do NOT invent CWE ids. Use only the CWE list provided in <cwe_context>.
If no vulnerability is found, return an empty array.

CONTEXT — CWE knowledge:
<cwe_context>
{% for cwe in rag.cwe %}
- CWE-{{cwe.id}}: {{cwe.name}}. {{cwe.description}}
{% endfor %}
</cwe_context>

CONTEXT — similar past examples:
<examples>
{% for ex in rag.examples %}
Language: {{ex.language}}, CWE-{{ex.cwe}}
BEFORE (vulnerable):
```{{ex.language}}
{{ex.code_before}}
```
AFTER (fixed):
```{{ex.language}}
{{ex.code_after}}
```
EXPLANATION: {{ex.explanation}}
---
{% endfor %}
</examples>

CONTEXT — static-analyzer hints (Semgrep/Bandit; may be wrong):
{% for h in static_hints %}
- {{h.tool}} @ line {{h.line}}: {{h.message}} (rule: {{h.rule_id}}, suspected CWE-{{h.cwe}})
{% endfor %}

CONTEXT — chunk metadata:
File: {{chunk.file}}
Function: {{chunk.function}} (lines {{chunk.line_start}}–{{chunk.line_end}})
Language: {{chunk.language}}
Called by: {{chunk.callers | join(", ")}}
Calls into: {{chunk.callees | join(", ")}}

CODE:
```{{chunk.language}}
{{chunk.body}}
```

OUTPUT FORMAT (strict JSON):
{
  "findings": [
    {
      "cwe": "CWE-89",
      "severity": "high",        // low|medium|high|critical
      "confidence": 0.85,        // 0..1
      "line_start": 42,
      "line_end": 47,
      "title": "SQL injection via concatenated user input",
      "description": "...max 200 words...",
      "data_flow": ["source: request.args.get('id') @ L41", "sink: db.execute(query) @ L46"],
      "fix_suggestion": "Use parameterized queries: db.execute('... WHERE id=?', (id,))"
    }
  ]
}
```

`src/coba/prompts/verifier.j2`:

```
SYSTEM:
You are a vulnerability triage reviewer. Given a finding claim and the original code,
decide whether it is a TRUE_POSITIVE or FALSE_POSITIVE.
Re-derive the data flow yourself. If you cannot, return FALSE_POSITIVE.

FINDING CLAIM:
{{finding_json}}

ORIGINAL CODE (with line numbers):
{{code_with_lines}}

EXPANDED CONTEXT (caller bodies):
{% for c in callers_full %}
{{c.signature}} @ {{c.file}}:{{c.line}}
```{{c.language}}
{{c.body}}
```
{% endfor %}

OUTPUT:
{
  "verdict": "TRUE_POSITIVE" | "FALSE_POSITIVE",
  "confidence": 0.0–1.0,
  "rationale": "...max 150 words; cite specific lines...",
  "corrections": {                  // only if TRUE_POSITIVE but original claim has wrong details
    "cwe": "CWE-...",
    "line_start": ...,
    "line_end": ...
  } | null
}
```

## 4. Anti-hallucination — 3 lớp filter

### Layer 1 — Schema & syntax

- JSON phải parse được. Nếu không → reject + retry 1 lần.
- `line_start ≤ line_end ≤ chunk.line_end` (nằm trong chunk).
- `cwe` phải nằm trong CWE list cung cấp ở RAG (~250 entry chính).
- `severity ∈ {low, medium, high, critical}`.

### Layer 2 — Code grounding

- Đọc lại đoạn code ở `line_start..line_end` trong file thực; nếu trống/chỉ comment → reject.
- Nếu `data_flow` cite source/sink mà không tồn tại trong code → reject.

### Layer 3 — Verifier critique

- LLM khác model với Detector.
- Cho expanded context (caller bodies + class context).
- Yêu cầu re-derive data flow. Nếu không re-derive được → mark `FALSE_POSITIVE` → drop.

### Đo lường

Tỷ lệ pass mỗi layer được log để ablation study (RQ3):
- L1 reject rate ~ 5–10 %.
- L2 reject rate ~ 10–15 %.
- L3 reject rate ~ 30–40 %. ← Verifier là filter mạnh nhất.

## 5. Cross-file reasoning

### 5.1. Khi nào cần

- Taint flow xuyên file (source ở file A, sink ở file B).
- Wrapper functions (e.g. `db_query()` ở `db.py` được gọi từ nhiều file).

### 5.2. Giải pháp

```
1. Joern build CPG cho cả repo.
2. Khi LLM Detector flag finding tại file A line L, gọi:
     callers   = joern.callers_of_line(A, L, depth=2)
     callees   = joern.callees_of_line(A, L, depth=2)
3. Bao gồm caller/callee function bodies (collapsed > 50 LOC) vào prompt Verifier.
4. Verifier nhìn rộng → quyết định TP/FP.
```

### 5.3. Limit độ sâu

- Depth ≤ 2 (đủ bắt source → wrapper → sink).
- Caller body > 50 LOC: chỉ giữ signature + comment đầu hàm.

## 6. Multi-language handling

| Aspect | Python | Java | C/C++ | JS/TS |
|---|---|---|---|---|
| Parser | Tree-sitter `python` | Tree-sitter `java` | Tree-sitter `c`, `cpp` | Tree-sitter `javascript`, `typescript` |
| CPG | Joern `pysrc2cpg` | Joern `javasrc2cpg` | Joern `c2cpg` | Joern `jssrc2cpg` |
| SAST | Bandit + Semgrep py | Semgrep java | Semgrep c | Semgrep js |
| Common sources | `request.args`, `input()` | `request.getParameter`, `Scanner.next` | `argv`, `getenv`, `read` | `req.query`, `req.body` |
| Common sinks | `subprocess.run`, `eval`, `cursor.execute` | `Runtime.exec`, `Statement.execute` | `system`, `strcpy`, `sprintf` | `child_process.exec`, `eval`, `db.query` |

`src/coba/agent/language_specs.py` định nghĩa source/sink/sanitizer table cho từng ngôn ngữ.

## 7. Confidence calibration

LLM trả `confidence ∈ [0, 1]` nhưng không calibrated. CobA recalibrate:

1. Collect ~ 500 finding với label TP/FP từ eval set.
2. Fit isotonic regression mapping `raw_conf → calibrated_conf`.
3. Filter threshold: `calibrated_conf ≥ 0.5` cho high severity, `≥ 0.7` cho medium.

## 8. Output schema (FinalFinding)

```python
class FinalFinding(BaseModel):
    id: str                       # uuid
    file: str
    function: str | None
    line_start: int
    line_end: int
    cwe: str                      # "CWE-89"
    severity: Severity            # enum
    confidence: float             # calibrated [0, 1]
    title: str
    description: str
    data_flow: list[str]
    fix_suggestion: str | None
    sources: list[str]            # ["semgrep:python.lang.security.audit.exec-detected", "llm-detector"]
    verifier_verdict: Verdict     # TRUE_POSITIVE | UNVERIFIED
    verifier_rationale: str | None
    cost_usd: float               # cost LLM cho finding này
    timestamp: datetime
```

## 9. Tóm tắt — Pipeline 1 finding

```
File → Tree-sitter AST → function chunks
chunks → Semgrep/Bandit hints + RAG retrieve
chunk + context → Detector LLM → RawFinding
RawFinding → Schema check + Code grounding check
Pass? → Verifier LLM (with caller/callee context) → Verdict
Verdict=TP → FinalFinding → ScanReport
```

## 10. Câu hỏi thầy có thể hỏi

- **Q**: "LLM bịa lỗ hổng có phải vấn đề lớn không?"
  **A**: Có — đo trong eval. Tỷ lệ finding bị reject ở Layer 3 (~ 35 %) là minh chứng filter cần thiết.

- **Q**: "Tại sao không feed cả file?"
  **A**: 70 % file > 2000 LOC sẽ vượt token budget của model rẻ. Chunking giữ chi phí < 0.5 USD/repo. Đồng thời, focus attention LLM vào function → tăng độ chính xác.

- **Q**: "Vì sao Verifier dùng model khác?"
  **A**: Tránh **confirmation bias** — cùng model có xu hướng đồng ý với chính nó. Model khác (Claude vs GPT) bridge weakness của nhau.
