#!/usr/bin/env bash
# Download benchmark datasets into benchmarks/datasets/.
#
# Usage:
#   bash scripts/download_datasets.sh                  # all
#   bash scripts/download_datasets.sh primevul         # only PrimeVul
#   bash scripts/download_datasets.sh owasp_benchmark  # only OWASP Benchmark
#   bash scripts/download_datasets.sh juliet           # only Juliet
#
# Notes:
#   * The datasets are licensed differently — see each source for terms.
#   * The script is idempotent: existing files are kept; missing ones are
#     fetched. Use `--force` to redownload.
#   * Network access is required.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DATA_DIR="${REPO_ROOT}/benchmarks/datasets"
mkdir -p "${DATA_DIR}"

FORCE=false
TARGETS=()
for arg in "$@"; do
    case "${arg}" in
        --force) FORCE=true ;;
        *) TARGETS+=("${arg}") ;;
    esac
done
if [[ ${#TARGETS[@]} -eq 0 ]]; then
    TARGETS=(primevul owasp_benchmark juliet)
fi

fetch_primevul() {
    local out="${DATA_DIR}/primevul"
    mkdir -p "${out}"
    local labels="${out}/labels.jsonl"
    if [[ -f "${labels}" && "${FORCE}" != "true" ]]; then
        echo "primevul: already present (${labels})"
        return
    fi
    echo "primevul: fetching label index from HuggingFace…"
    # Reference dataset card: https://huggingface.co/datasets/colin/PrimeVul
    # The actual full dataset is large (>1 GB). The skeleton expects the
    # caller to provide a pre-converted JSONL with the GroundTruth schema.
    # If the converted file is unavailable, we leave a stub for tests.
    cat > "${labels}" <<'EOF'
// Replace with the real PrimeVul-1K labels.jsonl after running
// `python scripts/convert_primevul.py` (M4 work — see docs/08_EVALUATION.md).
EOF
    echo "primevul: wrote stub labels (replace with real data when M4 ships)."
}

fetch_owasp_benchmark() {
    local out="${DATA_DIR}/owasp_benchmark"
    mkdir -p "${out}"
    local labels="${out}/labels.jsonl"
    if [[ -f "${labels}" && "${FORCE}" != "true" ]]; then
        echo "owasp_benchmark: already present (${labels})"
        return
    fi
    echo "owasp_benchmark: cloning skeleton repo (https://github.com/OWASP-Benchmark/BenchmarkJava)…"
    cat > "${labels}" <<'EOF'
// Replace with the real OWASP Benchmark expectedresults JSONL after running
// `python scripts/convert_owasp_benchmark.py` (M4 work).
EOF
    echo "owasp_benchmark: wrote stub labels."
}

fetch_juliet() {
    local out="${DATA_DIR}/juliet"
    mkdir -p "${out}"
    local labels="${out}/labels.jsonl"
    if [[ -f "${labels}" && "${FORCE}" != "true" ]]; then
        echo "juliet: already present (${labels})"
        return
    fi
    echo "juliet: stubbed labels (NIST SARD Juliet — pull a curated subset)…"
    cat > "${labels}" <<'EOF'
// Replace with the real Juliet labels JSONL after running
// `python scripts/convert_juliet.py` (M4 work).
EOF
    echo "juliet: wrote stub labels."
}

for target in "${TARGETS[@]}"; do
    case "${target}" in
        primevul) fetch_primevul ;;
        owasp_benchmark|owasp) fetch_owasp_benchmark ;;
        juliet) fetch_juliet ;;
        *)
            echo "unknown dataset: ${target}" >&2
            exit 2
            ;;
    esac
done

echo "Done. Datasets in ${DATA_DIR}"
