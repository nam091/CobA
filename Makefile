.PHONY: help install install-dev install-tools format lint typecheck test test-cov \
        run serve clean docker-build docker-run eval download-datasets

PYTHON ?= python3
PIP    ?= $(PYTHON) -m pip

help:
	@echo "CobA — Code-base Audit Agent"
	@echo ""
	@echo "Setup:"
	@echo "  install           Install package (production)"
	@echo "  install-dev       Install with dev + local-llm extras + pre-commit hooks"
	@echo "  install-tools     Install external SAST tools (Semgrep, Bandit, Gitleaks, Joern)"
	@echo ""
	@echo "Quality:"
	@echo "  format            Run ruff format"
	@echo "  lint              Run ruff lint"
	@echo "  typecheck         Run mypy"
	@echo "  test              Run pytest"
	@echo "  test-cov          Run pytest with coverage"
	@echo ""
	@echo "Run:"
	@echo "  run PATH=...      Scan a file/dir with the CLI"
	@echo "  serve             Start FastAPI server on :8000"
	@echo ""
	@echo "Benchmark:"
	@echo "  download-datasets Download PrimeVul subset + OWASP Benchmark"
	@echo "  eval              Run evaluation on benchmarks"
	@echo ""
	@echo "Docker:"
	@echo "  docker-build      Build docker image"
	@echo "  docker-run        Run docker image with .env"

install:
	$(PIP) install -e .

install-dev:
	$(PIP) install -e ".[dev,local-llm]"
	pre-commit install

install-tools:
	@echo "→ Semgrep"
	$(PIP) install semgrep
	@echo "→ Bandit"
	$(PIP) install bandit
	@echo "→ Gitleaks (binary)"
	@bash scripts/install_gitleaks.sh
	@echo "→ Joern (binary)"
	@bash scripts/install_joern.sh
	@echo "Done. Run 'coba doctor' to verify."

format:
	ruff format src tests
	ruff check --fix src tests

lint:
	ruff check src tests
	ruff format --check src tests

typecheck:
	mypy src

test:
	pytest -m "not integration and not slow"

test-cov:
	pytest --cov=src/coba --cov-report=term-missing --cov-report=html -m "not integration and not slow"

run:
	coba scan $(PATH)

serve:
	coba serve --host 0.0.0.0 --port 8000

clean:
	rm -rf build dist *.egg-info .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage
	find . -type d -name __pycache__ -prune -exec rm -rf {} +

download-datasets:
	bash scripts/download_datasets.sh

eval:
	coba eval --dataset primevul --subset 1000 --output benchmarks/results/

docker-build:
	docker build -t coba:latest -f Dockerfile .

docker-run:
	docker run --rm -it --env-file .env -p 8000:8000 -v $$(pwd):/workspace coba:latest
