# AGENTS.md — Hướng dẫn cho AI agents (Devin, Cursor, Copilot…) làm việc với repo CobA

## 1. Repo này là gì?

Đồ án nghiên cứu **"Nghiên cứu ứng dụng LLM trong phân tích lỗ hổng an toàn mã nguồn"**. Repo gồm:

- `docs/` — 12 tài liệu thiết kế (PLAN, ARCHITECTURE, TOOLS, …). Trả lời các câu hỏi thầy giáo có thể hỏi khi bảo vệ.
- `src/coba/` — Python source code (Python 3.11+).
- `report/` — Báo cáo khoá luận tiếng Việt (Markdown).
- `benchmarks/` — Script đánh giá trên PrimeVul, OWASP Benchmark.

## 2. Quy tắc chung

1. **Tài liệu là first-class citizen.** Trước khi sửa code, đọc `docs/02_ARCHITECTURE.md` và `docs/03_TOOLS.md`. Khi thêm tool/LLM mới, update `docs/03_TOOLS.md` hoặc `docs/06_LLM_INTEGRATION.md` trong cùng PR.
2. **Báo cáo viết tiếng Việt** (`report/Chuong_*.md`). Code, comment, log, tên biến viết tiếng Anh.
3. **Không hard-code secret.** Dùng `pydantic-settings` → biến môi trường → `.env`. Không commit `.env`.
4. **Không sửa file generated** (Joern CPG, chroma_db, …). Đều bị ignore trong `.gitignore`.

## 3. Quy trình dev

```bash
make install-dev      # cài + setup pre-commit
make install-tools    # cài Semgrep, Bandit, Gitleaks, Joern (chỉ chạy 1 lần)
make format           # ruff format + ruff check --fix
make lint             # ruff check + format --check
make typecheck        # mypy src
make test             # pytest (unit tests only, không cần LLM/Joern)
```

Trước khi tạo PR phải qua: `make format && make lint && make typecheck && make test`.

## 4. Quy tắc đặt tên & cấu trúc

- Branch: `devin/<timestamp>-<short-desc>` (e.g. `devin/1779246874-add-verifier-agent`).
- Commit: imperative mood, dưới 72 ký tự dòng đầu. Tiếng Anh.
- Module mới đặt trong `src/coba/<sub-package>/`. Nếu là tool wrapper → `src/coba/tools/<tool>.py`.
- Test mirror cấu trúc: `tests/test_<module>.py`.

## 5. Quy tắc đối với LLM router (quan trọng)

Khi thêm LLM mới:
1. Thêm provider class kế thừa `coba.llm.base.LLMProvider` trong `src/coba/llm/<provider>.py`.
2. Register vào `LLMRouter._registry` (xem `src/coba/llm/router.py`).
3. Update bảng trong `docs/06_LLM_INTEGRATION.md` (cost, latency, context window).
4. Thêm test mock trong `tests/test_llm_<provider>.py`.

## 6. Quy tắc đối với tool wrapper (Semgrep/Joern/…)

Mỗi tool wrapper tuân thủ interface `coba.tools.base.SASTTool` (xem `src/coba/tools/base.py`):
- `name: str`
- `languages: list[str]`
- `run(target: Path) -> list[Finding]`
- Phải có timeout, không được hang vĩnh viễn.
- Phải chuẩn hoá output về schema `coba.utils.schemas.Finding`.

## 7. Coding conventions

- Type hints: bắt buộc cho mọi public function.
- Async I/O: dùng `httpx.AsyncClient` cho LLM/HTTP, `anyio` cho concurrency.
- Logging: dùng `structlog`. Không `print()` trong code production (chỉ trong CLI hiển thị).
- Schema: tất cả I/O ra ngoài (CLI, API, file) dùng pydantic models. Đặt trong `src/coba/utils/schemas.py`.

## 8. Khi thêm CWE/rule mới

- File rule Semgrep: `src/coba/tools/rules/semgrep/<cwe-id>.yml`.
- Test fixture: `examples/vulnerable_samples/<lang>/<cwe-id>_<short_name>.{py,java,c,js}`.
- Update CWE coverage matrix trong `docs/08_EVALUATION.md`.

## 9. Không làm

- Không commit dataset > 5 MB (dùng `scripts/download_datasets.sh`).
- Không gọi LLM trong unit test (mock bằng `respx` hoặc `pytest-httpx`).
- Không bỏ pre-commit (`--no-verify`).
- Không gọi LLM trên user input thô — luôn qua sanitizer (xem `src/coba/utils/sanitize.py`).
