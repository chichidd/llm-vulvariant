#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
ROOT="${ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd -P)}"
APP_DIR="$(cd "$SCRIPT_DIR/.." && pwd -P)"
PROFILES_ROOT="${PROFILES_ROOT:-$ROOT/profiles}"
VULN_JSON="${VULN_JSON:-$ROOT/data/vuln.json}"
SOURCE_REPOS_ROOT="${SOURCE_REPOS_ROOT:-$ROOT/data/repos}"
TARGET_REPOS_ROOT="${TARGET_REPOS_ROOT:-$ROOT/data/repos-microsoft}"
SOURCE_SOFT_PROFILES_DIR="${SOURCE_SOFT_PROFILES_DIR:-$PROFILES_ROOT/soft}"
TARGET_SOFT_PROFILES_DIR="${TARGET_SOFT_PROFILES_DIR:-$PROFILES_ROOT/soft-microsoft}"
VULN_PROFILES_DIR="${VULN_PROFILES_DIR:-$PROFILES_ROOT/vuln}"
RUN_TAG="${RUN_TAG:-$(date +%Y%m%d-%H%M%S)-$$}"
RUN_ID="${RUN_ID:-microsoft-full-$RUN_TAG}"
SCAN_OUTPUT_DIR="${SCAN_OUTPUT_DIR:-$ROOT/results/scan-microsoft-full-$RUN_TAG}"
EXP_OUTPUT_DIR="${EXP_OUTPUT_DIR:-$ROOT/results/exploitability-microsoft-full-$RUN_TAG}"
RUNTIME_ROOT="${RUNTIME_ROOT:-$ROOT/results/claude-runtime}"
EXPLOITABILITY_TIMEOUT="${EXPLOITABILITY_TIMEOUT:-1800}"
EXPLOITABILITY_JOBS="${EXPLOITABILITY_JOBS:-1}"
EXPLOITABILITY_RUNTIME_MODE="${EXPLOITABILITY_RUNTIME_MODE:-run}"
TARGET_SCAN_TIMEOUT="${TARGET_SCAN_TIMEOUT:-7200}"
ALLOW_PARTIAL_EXPLOITABILITY="${ALLOW_PARTIAL_EXPLOITABILITY:-0}"
SUBMISSION_PREFIX="${SUBMISSION_PREFIX:-exploitable_findings}"
LLM_PROVIDER="${LLM_PROVIDER:-lab}"
LLM_NAME="${LLM_NAME:-}"
PYTHON_BIN="${PYTHON_BIN:-}"
SCAN_LOG="${SCAN_LOG:-$ROOT/output-microsoft-scan-$RUN_ID.log}"
EXP_LOG="${EXP_LOG:-$ROOT/output-microsoft-exploitability-$RUN_ID.log}"
STATUS_LOG="${STATUS_LOG:-$ROOT/output-microsoft-status-$RUN_ID.log}"

cd "$APP_DIR"

if [[ -z "$PYTHON_BIN" ]]; then
  if [[ -f /home/dongtian/miniconda3/etc/profile.d/conda.sh ]]; then
    source /home/dongtian/miniconda3/etc/profile.d/conda.sh
    if conda activate dsocr >/dev/null 2>&1; then
      PYTHON_BIN="python"
    elif command -v python >/dev/null 2>&1; then
      PYTHON_BIN="$(command -v python)"
    elif command -v python3 >/dev/null 2>&1; then
      PYTHON_BIN="$(command -v python3)"
    else
      echo "ERROR: neither python nor python3 is available in PATH" >&2
      exit 1
    fi
  elif command -v python >/dev/null 2>&1; then
    PYTHON_BIN="$(command -v python)"
  elif command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="$(command -v python3)"
  else
    echo "ERROR: neither python nor python3 is available in PATH" >&2
    exit 1
  fi
fi

read -r -a PYTHON_CMD <<<"$PYTHON_BIN"

mkdir -p "$SCAN_OUTPUT_DIR" "$EXP_OUTPUT_DIR" "$RUNTIME_ROOT"

if (( EXPLOITABILITY_JOBS > 1 )) && [[ "$EXPLOITABILITY_RUNTIME_MODE" != "folder" ]]; then
  EXPLOITABILITY_RUNTIME_MODE="folder"
fi

echo "[$(date -Iseconds)] RUN_ID=$RUN_ID" | tee -a "$STATUS_LOG"
echo "[$(date -Iseconds)] Stage 1/2: run batch scanner" | tee -a "$STATUS_LOG"
set +e
"${PYTHON_CMD[@]}" -m cli.batch_scanner \
  --vuln-json "$VULN_JSON" \
  --source-repos-root "$SOURCE_REPOS_ROOT" \
  --target-repos-root "$TARGET_REPOS_ROOT" \
  --profile-base-path "$PROFILES_ROOT" \
  --source-soft-profiles-dir "$SOURCE_SOFT_PROFILES_DIR" \
  --target-soft-profiles-dir "$TARGET_SOFT_PROFILES_DIR" \
  --vuln-profiles-dir "$VULN_PROFILES_DIR" \
  --scan-output-dir "$SCAN_OUTPUT_DIR" \
  --scan-all-profiled-targets \
  --similarity-threshold 0 \
  --fallback-top-n 1000 \
  --max-workers 8 \
  --scan-workers 8 \
  --target-scan-timeout "$TARGET_SCAN_TIMEOUT" \
  --max-iterations-cap 10 \
  --llm-provider "$LLM_PROVIDER" \
  --llm-name "$LLM_NAME" \
  --skip-existing-scans \
  >> "$SCAN_LOG" 2>&1
SCAN_EXIT=$?
set -e

SCAN_RESULTS_COUNT="$(find "$SCAN_OUTPUT_DIR" -name agentic_vuln_findings.json -type f 2>/dev/null || true)"
SCAN_RESULTS_COUNT="$(printf '%s\n' "$SCAN_RESULTS_COUNT" | sed '/^$/d' | wc -l | tr -d ' ')"
echo "[$(date -Iseconds)] batch_scanner exit=$SCAN_EXIT scan_results=$SCAN_RESULTS_COUNT" | tee -a "$STATUS_LOG"
if (( SCAN_EXIT != 0 )); then
  if [[ "$ALLOW_PARTIAL_EXPLOITABILITY" != "1" ]]; then
    echo "[$(date -Iseconds)] batch_scanner failed with exit=$SCAN_EXIT; abort before exploitability" | tee -a "$STATUS_LOG"
    exit "$SCAN_EXIT"
  fi
  if (( SCAN_RESULTS_COUNT == 0 )); then
    echo "[$(date -Iseconds)] No scan outputs were produced; abort before exploitability" | tee -a "$STATUS_LOG"
    exit "$SCAN_EXIT"
  fi
  echo "[$(date -Iseconds)] Partial exploitability explicitly allowed after scan exit=$SCAN_EXIT" | tee -a "$STATUS_LOG"
fi

echo "[$(date -Iseconds)] Stage 2/2: run exploitability" | tee -a "$STATUS_LOG"
"${PYTHON_CMD[@]}" -m cli.exploitability \
  --scan-results-dir "$SCAN_OUTPUT_DIR" \
  --soft-profile-dir "$TARGET_SOFT_PROFILES_DIR" \
  --repo-base-path "$TARGET_REPOS_ROOT" \
  --generate-report \
  --report-only-exploitable \
  --submission-output-dir "$EXP_OUTPUT_DIR" \
  --submission-prefix "$SUBMISSION_PREFIX" \
  --claude-runtime-root "$RUNTIME_ROOT" \
  --claude-runtime-mode "$EXPLOITABILITY_RUNTIME_MODE" \
  --run-id "$RUN_ID" \
  --jobs "$EXPLOITABILITY_JOBS" \
  --timeout "$EXPLOITABILITY_TIMEOUT" \
  >> "$EXP_LOG" 2>&1
if (( SCAN_EXIT != 0 )); then
  echo "[$(date -Iseconds)] Exploitability completed, but batch_scanner previously failed with exit=$SCAN_EXIT" | tee -a "$STATUS_LOG"
  exit "$SCAN_EXIT"
fi
echo "[$(date -Iseconds)] Pipeline completed" | tee -a "$STATUS_LOG"
