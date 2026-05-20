# 06 — LLM INTEGRATION: Các LLM đã tích hợp, vai trò, cost

> Trả lời thẳng câu hỏi quan trọng: **"Những LLM nào đã tích hợp vào dự án?"**

## 1. Danh sách LLM tích hợp

CobA hỗ trợ **4 provider**, với **9 model** được cấu hình mặc định. Tất cả đều có thể đổi qua `.env` hoặc CLI flag.

### 1.1. Cloud providers (3)

| Provider | Model | Context | Cost in (USD/1M) | Cost out | Vai trò mặc định |
|---|---|---|---|---|---|
| **OpenAI** | `gpt-4o-mini` | 128K | 0.15 | 0.60 | **Detector (default)** |
| **OpenAI** | `gpt-4o` | 128K | 2.50 | 10.00 | Verifier alt / Heavy eval |
| **Anthropic** | `claude-3-5-haiku-20241022` | 200K | 0.80 | 4.00 | Detector cheap-alt |
| **Anthropic** | `claude-3-5-sonnet-20241022` | 200K | 3.00 | 15.00 | **Verifier (default)** |
| **Anthropic** | `claude-3-opus-20240229` | 200K | 15.00 | 75.00 | Heavy eval comparison only |
| **Google** | `gemini-1.5-flash` | 1M | 0.075 | 0.30 | Embedding alt / cheap detector |
| **Google** | `gemini-1.5-pro` | 2M | 1.25 | 5.00 | Long-context detector |

### 1.2. Local provider (1, qua Ollama)

| Model | Size | Quantization | RAM/VRAM | Vai trò |
|---|---|---|---|---|
| `qwen2.5-coder:7b` | 7B | q4_K_M (~4.7 GB) | 8 GB VRAM | **Offline fallback (default)** |
| `qwen2.5-coder:32b` | 32B | q4_K_M (~19 GB) | 24 GB VRAM | Best local quality (cần 4090/A100) |
| `deepseek-coder-v2:16b` | 16B (MoE 2.4B active) | q4_K_M (~9 GB) | 12 GB VRAM | Alt local code model |
| `llama3.1:8b` | 8B | q4_K_M (~4.7 GB) | 8 GB VRAM | General reasoning fallback |
| `codellama:13b` | 13B | q4_K_M (~7.4 GB) | 10 GB VRAM | Code-focused alt |

**Embedding (local)**:
- `sentence-transformers/all-MiniLM-L6-v2` (80 MB) — default cho RAG.
- `BAAI/bge-large-en-v1.5` (1.3 GB) — alt cho RAG chất lượng cao hơn.

## 2. Vai trò trong pipeline

```
                    ┌────────────────┐
chunk + RAG ────────▶│  DETECTOR       │  ←  gpt-4o-mini (default)
                    │  cheap+fast     │     fallback → qwen2.5-coder:7b
                    └──────────┬─────┘
                                │ raw findings
                                ▼
                    ┌────────────────┐
                    │  VERIFIER        │  ←  claude-3-5-sonnet (default)
                    │  smart critique  │     fallback → gpt-4o
                    └──────────┬─────┘
                                │ confirmed
                                ▼
                              REPORT


                    ┌────────────────┐
                    │  EMBEDDER        │  ←  all-MiniLM-L6-v2 (local)
                    │  for RAG         │
                    └────────────────┘
```

## 3. Lý do chọn từng LLM (justification cho thầy)

### 3.1. Tại sao GPT-4o-mini cho Detector?

| Tiêu chí | Đánh giá |
|---|---|
| Giá | 0.15 USD/1M in → quét 50K LOC ≈ 0.04 USD |
| Tốc độ | ~ 60 tok/s output → < 3s/chunk |
| Chất lượng code | GPT-4o family, đủ tốt cho per-chunk detection |
| Function calling / JSON mode | Có — đảm bảo strict JSON output |
| Coverage benchmark | HumanEval pass@1 87 %, đứng top tier cho price-point |

### 3.2. Tại sao Claude 3.5 Sonnet cho Verifier?

| Tiêu chí | Đánh giá |
|---|---|
| Chất lượng reasoning | SOTA non-OpenAI (HumanEval 92 %, MMLU 88.7 %) |
| Khả năng critique | Anthropic train CAI (Constitutional AI) → tốt cho "is X really true?" |
| Long context (200K) | Cho phép feed expanded context (caller bodies) |
| Khác provider với Detector | Tránh confirmation bias (xem ADR-008 trong `02_ARCHITECTURE.md`) |
| Cost | $3/1M in × ~ 10 % chunk được verify → khả thi |

### 3.3. Tại sao Qwen2.5-Coder cho offline fallback?

| Tiêu chí | Đánh giá |
|---|---|
| Open-weights | Apache-2.0, có thể self-host |
| Code-specialized | Train trên 5.5T token code, tốt hơn Llama generic |
| Multi-lang | Tốt với Python, Java, C/C++, JS — đúng scope CobA |
| Size 7B | Fit 1×RTX 4090 (24 GB) thoải mái với q4 |
| Benchmark | HumanEval 88 % (7B), 92 % (32B) — comparable GPT-4 family |
| Hỗ trợ JSON mode | Qua structured output prompting (chưa native như OpenAI) |

### 3.4. Tại sao 3.5 Haiku và Flash là backup?

Trường hợp:
- Budget tight → switch Detector sang `gemini-1.5-flash` ($0.075/1M).
- High volume → `claude-3-5-haiku` cho context dài (200K) mà rẻ.

## 4. LLM Router — kiến trúc

`src/coba/llm/router.py`:

```python
class LLMRouter:
    """
    Provider-abstract router with retry, rate limit, cost tracking.
    """

    def __init__(self, settings: Settings):
        self.providers: dict[str, LLMProvider] = {
            "openai":   OpenAIProvider(settings.openai_api_key),
            "anthropic":AnthropicProvider(settings.anthropic_api_key),
            "google":   GeminiProvider(settings.google_api_key),
            "ollama":   OllamaProvider(settings.ollama_base_url),
        }
        self.policy = self._load_policy()
        self.cost = CostTracker(daily_budget=settings.llm_daily_budget_usd)

    async def complete(self, task: TaskKind, messages: list[Message]) -> LLMResponse:
        model_id = self.policy.choose(task)
        provider = self._provider_for(model_id)
        try:
            resp = await provider.complete(model_id, messages)
            self.cost.record(resp.usage, provider.price(model_id))
            return resp
        except (RateLimitError, BudgetExceeded, ProviderDown):
            fallback = self.policy.fallback_for(task)
            return await self._provider_for(fallback).complete(fallback, messages)
```

### 4.1. Policy file (`config/llm_policy.yaml`)

```yaml
routes:
  detector:
    primary: gpt-4o-mini
    fallbacks: [claude-3-5-haiku-20241022, qwen2.5-coder:7b]
  verifier:
    primary: claude-3-5-sonnet-20241022
    fallbacks: [gpt-4o, qwen2.5-coder:32b]
  embedder:
    primary: all-MiniLM-L6-v2  # local
    fallbacks: []
  heavy_eval:
    primary: gpt-4o
    fallbacks: [claude-3-5-sonnet-20241022]

budget:
  daily_usd: 5.0
  per_scan_usd: 1.0

retry:
  max_attempts: 3
  backoff_factor: 2
  jitter_seconds: 1

rate_limit:
  openai: { rpm: 500, tpm: 200000 }
  anthropic: { rpm: 100, tpm: 100000 }
  google: { rpm: 60, tpm: 1000000 }
  ollama: { rpm: 1000, tpm: 1000000 }
```

### 4.2. Cost tracker

- Mỗi response log `prompt_tokens`, `completion_tokens`, `provider`, `model`, `task`, `scan_id`.
- Tính `cost = (in_tokens × in_price + out_tokens × out_price) / 1M`.
- Trả về `ScanReport.cost_breakdown` cuối mỗi scan.

## 4.3. Few-shot retrieval cho Detector

Mỗi chunk được Detector audit kèm 0–`fewshot_k` ví dụ `(vuln, safe)` ngắn lấy từ `src/coba/data/fewshot_examples.json`. Class `coba.agent.rag.FewShotIndex` chịu trách nhiệm:

- **Lookup theo CWE**: trả về toàn bộ entry có cùng `cwe` id.
- **Ưu tiên ngôn ngữ**: khi `chunk.language=python`, các ví dụ Python xếp trước; fallback sang ngôn ngữ khác nếu CWE đó chưa có ví dụ Python.
- **Round-robin theo CWE**: nếu chunk có nhiều CWE candidate (nhiều static hints), Detector lấy 1 ví dụ/CWE trước khi top up — tránh tình huống 2 ví dụ về SQLi át toàn bộ context khi chunk còn có CSRF.
- **Determinism**: thứ tự ví dụ bám theo thứ tự xuất hiện trong file JSON. Không random, không re-rank.

Prompt template (`detector.j2`) chèn block `EXAMPLES — vulnerable vs safe patterns` giữa CWE-knowledge và static-hints. Mỗi ví dụ gồm `VULN:`, `SAFE:`, và 1 dòng `WHY:` ≤ 40 từ.

Lý do thiết kế:

| Trade-off | Lựa chọn | Lý do |
|---|---|---|
| Built-in vs RAG-retrieval | Built-in JSON (deterministic) | Reproducibility — eval phải lặp lại được hệ số xác định. Khi corpus đủ lớn (≥ 200 entries) sẽ chuyển sang Chroma. |
| Vuln-only vs vuln+safe | vuln + safe + explanation | "Học bằng đối chiếu" giúp LLM nhận diện pattern chính xác hơn, đồng thời gợi ý fix khi sinh `fix_suggestion`. |
| Top-k cố định | `fewshot_k=2` mặc định | 2 ví dụ ≈ 200–400 tokens; cost insignificant so với chunk body 1–8K tokens, nhưng đủ để học ngữ cảnh. |

## 5. Prompt versioning

Mọi prompt nằm trong `src/coba/prompts/*.j2`, có version header:

```jinja
{# version: 2025-01-15.v3
   author: CobA
   notes: switched to JSON mode, removed verbose preamble. #}
```

Khi đổi prompt, bump version → eval lại để so sánh.

## 6. Function calling / Structured output

| Provider | JSON mode |
|---|---|
| OpenAI | `response_format={"type": "json_schema", "json_schema": {...}}` |
| Anthropic | `tool_use` với pre-defined tool schema |
| Google | `generation_config={"response_mime_type": "application/json", "response_schema": {...}}` |
| Ollama | format=json (cơ bản); strict schema cần re-prompt nếu invalid |

CobA chuẩn hoá qua `LLMProvider.complete_structured()`.

## 7. Local LLM setup hướng dẫn

```bash
# Cài Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull các model
ollama pull qwen2.5-coder:7b
ollama pull qwen2.5-coder:32b      # nếu có RTX 4090 hoặc cao hơn

# Kiểm tra
ollama list
curl http://localhost:11434/api/tags
```

`coba doctor` sẽ check tự động.

## 8. Cost projection (per scan)

Repo 50K LOC, scenarios:

| Scenario | Detector | Verifier | Total tokens | Cost USD |
|---|---|---|---|---|
| **Default** | gpt-4o-mini | claude-3-5-sonnet | 8M in / 0.5M out | **~ 0.30** |
| **Premium** | gpt-4o | claude-3-5-sonnet | 8M in / 0.5M out | ~ 4.50 |
| **Cheap cloud** | gemini-1.5-flash | claude-3-5-haiku | 8M in / 0.5M out | ~ 0.15 |
| **Offline (Qwen)** | qwen2.5-coder:7b | qwen2.5-coder:7b | - | **0.00** + GPU time |

→ Default ≈ **0.30 USD/repo 50K LOC**. Budget 130 USD đủ chạy > 400 scan.

## 9. Câu hỏi thầy có thể hỏi

- **Q**: "Vì sao không train fine-tune model riêng?"
  **A**: Scope đề tài là *ứng dụng LLM*, không phải *train LLM*. Fine-tune cần GPU lớn (8×A100), data nhiều, thời gian dài. Sinh viên 16 tuần không khả thi. CobA dùng RAG + prompt engineering thay thế.

- **Q**: "Có lo về privacy khi gửi code lên cloud LLM không?"
  **A**: Có. CobA có `--no-cloud` flag để chạy 100 % local (Qwen + embedding local). OpenAI/Anthropic enterprise có cam kết không train trên API data, nhưng vẫn nên dùng local cho code nhạy cảm.

- **Q**: "LLM thay đổi liên tục (GPT-5 sắp ra), làm sao maintain?"
  **A**: Provider-abstracted router. Đổi model = đổi 1 dòng `.env` hoặc `llm_policy.yaml`. Không phải sửa code.

- **Q**: "Có đo được model nào tốt nhất không?"
  **A**: Trong eval (Ch.6 § 6.6 — RQ5/RQ6) sẽ so 4 model: GPT-4o-mini, Claude Haiku, Gemini Flash, Qwen 7B trên cùng PrimeVul-1K → bảng comparison.
