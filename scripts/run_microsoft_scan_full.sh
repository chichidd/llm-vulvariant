#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REVISION_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd -P)"
ROOT="${ROOT:-$REVISION_ROOT}"
APP_DIR="$(cd "$SCRIPT_DIR/.." && pwd -P)"
export PYTHONPATH="$APP_DIR/src${PYTHONPATH:+:$PYTHONPATH}"
PROFILES_ROOT="${PROFILES_ROOT:-$ROOT/evidence/profiles}"
VULN_JSON="${VULN_JSON:-$ROOT/exp-glm-0823/input/vuln.json}"
SOURCE_REPOS_ROOT="${SOURCE_REPOS_ROOT:-$ROOT/repos/general}"
TARGET_REPOS_ROOT="${TARGET_REPOS_ROOT:-$ROOT/repos/microsoft}"
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
SUBMISSION_PREFIX="${SUBMISSION_PREFIX:-exploitable_findings}"
LLM_PROVIDER="lab"
LLM_NAME="GLM-5.2"
LAB_LLM_API_BASE="https://llm.shtech.org/v1"
LAB_LLM_MODEL="GLM-5.2"
export LAB_LLM_API_BASE LAB_LLM_MODEL
PYTHON_BIN="${PYTHON_BIN:-}"
LOG_DIR="$ROOT/results/logs"
SCAN_LOG="${SCAN_LOG:-$LOG_DIR/output-microsoft-scan-$RUN_ID.log}"
EXP_LOG="${EXP_LOG:-$LOG_DIR/output-microsoft-exploitability-$RUN_ID.log}"
STATUS_LOG="${STATUS_LOG:-$LOG_DIR/output-microsoft-status-$RUN_ID.log}"

cd "$APP_DIR"

if [[ -z "$PYTHON_BIN" ]]; then
  if command -v python >/dev/null 2>&1; then
    PYTHON_BIN="$(command -v python)"
  elif command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="$(command -v python3)"
  else
    echo "ERROR: neither python nor python3 is available in PATH" >&2
    exit 1
  fi
fi
read -r -a PYTHON_CMD <<<"$PYTHON_BIN"

mkdir -p "$SCAN_OUTPUT_DIR" "$EXP_OUTPUT_DIR" "$RUNTIME_ROOT" "$LOG_DIR"


if (( EXPLOITABILITY_JOBS > 1 )) && [[ "$EXPLOITABILITY_RUNTIME_MODE" != "folder" ]]; then
  EXPLOITABILITY_RUNTIME_MODE="folder"
fi

echo "[$(date -Iseconds)] Preflight: verify every target repository has an exact HEAD profile" | tee -a "$STATUS_LOG"
"${PYTHON_CMD[@]}" - "$TARGET_REPOS_ROOT" "$TARGET_SOFT_PROFILES_DIR" <<'PY' | tee -a "$STATUS_LOG"
import re
import subprocess
import sys
from pathlib import Path

repos_root = Path(sys.argv[1])
profiles_root = Path(sys.argv[2])
target_repos = sorted(
    path
    for path in repos_root.iterdir()
    if path.is_dir() and (path / ".git").exists()
)
if not target_repos:
    raise SystemExit(f"No target git repositories found under {repos_root}")

missing = []
for repo_path in target_repos:
    commit = subprocess.run(
        ["git", "-C", str(repo_path), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip().lower()
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise SystemExit(f"Invalid HEAD commit for {repo_path}")
    profile = profiles_root / repo_path.name / commit / "software_profile.json"
    if not profile.is_file():
        missing.append((repo_path.name, commit, profile))

print(f"target_repositories={len(target_repos)}")
print(f"missing_target_profiles={len(missing)}")
for repo_name, commit, profile in missing:
    print(f"  missing {repo_name}@{commit} -> {profile}")
if missing:
    raise SystemExit(1)
PY

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
  --run-id "$RUN_ID" \
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

echo "[$(date -Iseconds)] batch_scanner exit=$SCAN_EXIT" | tee -a "$STATUS_LOG"
if (( SCAN_EXIT != 0 )); then
  echo "[$(date -Iseconds)] batch_scanner failed with exit=$SCAN_EXIT; abort before exploitability" | tee -a "$STATUS_LOG"
  exit "$SCAN_EXIT"
fi

mapfile -t SCAN_COMMIT_MANIFESTS < <(
  find "$SCAN_OUTPUT_DIR" -maxdepth 1 -type f -name 'scan-output-commit-bindings-*.json' -print
)
if (( ${#SCAN_COMMIT_MANIFESTS[@]} != 1 )); then
  echo "[$(date -Iseconds)] Expected exactly one scanner terminal binding manifest, found ${#SCAN_COMMIT_MANIFESTS[@]}" | tee -a "$STATUS_LOG"
  exit 1
fi
SCAN_COMMIT_MANIFEST="${SCAN_COMMIT_MANIFESTS[0]}"
read -r SCAN_COMMIT_MANIFEST_SHA256 _ < <(sha256sum "$SCAN_COMMIT_MANIFEST")

echo "[$(date -Iseconds)] Stage 2/2: run exploitability" | tee -a "$STATUS_LOG"
"${PYTHON_CMD[@]}" -m cli.exploitability \
  --scan-results-dir "$SCAN_OUTPUT_DIR" \
  --scan-output-commit-manifest "$SCAN_COMMIT_MANIFEST" \
  --scan-output-commit-manifest-sha256 "$SCAN_COMMIT_MANIFEST_SHA256" \
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
echo "[$(date -Iseconds)] Pipeline completed" | tee -a "$STATUS_LOG"
