#!/usr/bin/env bash
set -euo pipefail

# Generate software profiles for all repo/commit pairs in vuln.json.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
APP_DIR="${APP_DIR:-$(cd "$SCRIPT_DIR/.." && pwd -P)}"
source "$SCRIPT_DIR/profile_paths.sh"

VULN_JSON="${VULN_JSON:-../data/vuln.json}"
REPO_BASE_PATH="${REPO_BASE_PATH:-../data/repos}"
PROFILE_BASE_PATH="${PROFILE_BASE_PATH:-../profiles}"
SOFT_PROFILE_DIRNAME="${SOFT_PROFILE_DIRNAME:-soft}"
OUTPUT_DIR="${OUTPUT_DIR:-}"
LLM_PROVIDER="${LLM_PROVIDER:-deepseek}"
LLM_NAME="${LLM_NAME:-}"
FORCE_REGENERATE=0
EXTRA_ARGS=()

PYTHON_BIN="${PYTHON_BIN:-}"
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

cleanup_codeql_temp_artifacts() {
  local repo_dir="$1"
  [[ -d "$repo_dir" ]] || return 0

  "${PYTHON_CMD[@]}" - cleanup_codeql_temp_artifacts "$APP_DIR" "$repo_dir" <<'PY'
from pathlib import Path
import shutil
import sys

app_dir = Path(sys.argv[2]).resolve()
repo_dir = Path(sys.argv[3]).resolve()

sys.path.insert(0, str(app_dir / "src"))

from config import _path_config
from utils import repo_lock as repo_lock_module

_path_config["repo_root"] = app_dir

cleaned = False
with repo_lock_module.hold_repo_lock(repo_dir, purpose="cleanup_codeql_temp_artifacts"):
    detected_source_root = repo_dir / "_codeql_detected_source_root"
    if detected_source_root.exists() or detected_source_root.is_symlink():
        detected_source_root.unlink()
        cleaned = True

    build_dir = repo_dir / "_codeql_build_dir"
    if build_dir.exists():
        shutil.rmtree(build_dir)
        cleaned = True

if cleaned:
    print(f"Cleaned CodeQL temp artifacts: {repo_dir}")
PY
}

usage() {
  cat <<EOF
Usage: $0 [options] [-- ...extra software-profile args]

Options:
  --vuln-json PATH               Path to vuln.json (default: $VULN_JSON)
  --repo-base-path PATH          Repositories base path (default: $REPO_BASE_PATH)
  --profile-base-path PATH       Profiles base path (default: $PROFILE_BASE_PATH)
  --soft-profile-dirname NAME    Soft profile subdir under profile base (default: $SOFT_PROFILE_DIRNAME)
  --output-dir PATH              Explicit output dir (overrides profile-base + soft-profile-dirname)
  --llm-provider NAME            LLM provider (default: $LLM_PROVIDER)
  --llm-name NAME                Optional LLM model override
  --force-regenerate             Ignore existing software profile/checkpoints and rebuild
  -h, --help                     Show help

Examples:
  $0
  $0 --profile-base-path ~/vuln/profiles --soft-profile-dirname soft
  $0 --output-dir /tmp/soft-profiles --llm-provider deepseek
  $0 --force-regenerate
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --vuln-json)
      VULN_JSON="$2"; shift 2 ;;
    --repo-base-path)
      REPO_BASE_PATH="$2"; shift 2 ;;
    --profile-base-path)
      PROFILE_BASE_PATH="$2"; shift 2 ;;
    --soft-profile-dirname)
      SOFT_PROFILE_DIRNAME="$2"; shift 2 ;;
    --output-dir)
      OUTPUT_DIR="$2"; shift 2 ;;
    --llm-provider)
      LLM_PROVIDER="$2"; shift 2 ;;
    --llm-name)
      LLM_NAME="$2"; shift 2 ;;
    --force-regenerate)
      FORCE_REGENERATE=1; shift ;;
    -h|--help)
      usage; exit 0 ;;
    --)
      shift
      EXTRA_ARGS+=("$@")
      break ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 1 ;;
  esac
done

OUTPUT_DIR="$(resolve_profile_dir "$PROFILE_BASE_PATH" "$SOFT_PROFILE_DIRNAME" "$OUTPUT_DIR")"
VULN_JSON="$(_profile_realpath "$VULN_JSON")"
REPO_BASE_PATH="$(_profile_realpath "$REPO_BASE_PATH")"

echo "=========================================="
echo "Software Profile Batch Generator"
echo "=========================================="
echo "VULN_JSON:      $VULN_JSON"
echo "REPO_BASE_PATH: $REPO_BASE_PATH"
echo "OUTPUT_DIR:     $OUTPUT_DIR"
echo "LLM_PROVIDER:   $LLM_PROVIDER"
if [[ -n "$LLM_NAME" ]]; then
  echo "LLM_NAME:       $LLM_NAME"
fi
if [[ "$FORCE_REGENERATE" -eq 1 ]]; then
  echo "FORCE_REGENERATE: enabled"
fi
echo ""

if [[ ! -f "$VULN_JSON" ]]; then
  echo "Error: vuln.json not found: $VULN_JSON" >&2
  exit 1
fi
if [[ ! -d "$REPO_BASE_PATH" ]]; then
  echo "Error: repo base path not found: $REPO_BASE_PATH" >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "Error: command not found: jq" >&2
  exit 1
fi

mkdir -p "$OUTPUT_DIR"

if ! loader_output="$(jq -r '.[] | "\(.repo_name)|\(.commit)"' "$VULN_JSON" | sort -u)"; then
  echo "Error: failed to parse vuln.json: $VULN_JSON" >&2
  exit 1
fi

if [[ -n "$loader_output" ]]; then
  mapfile -t entries <<< "$loader_output"
else
  entries=()
fi
if [[ ${#entries[@]} -eq 0 ]]; then
  echo "No entries found in vuln.json"
  exit 0
fi

total="${#entries[@]}"
current=0
failed=0
succeeded=0
failed_entries=()

for entry in "${entries[@]}"; do
  IFS='|' read -r repo_name commit <<< "$entry"
  [[ -n "$repo_name" && -n "$commit" ]] || continue
  current=$((current + 1))
  repo_dir="$REPO_BASE_PATH/$repo_name"

  echo "=========================================="
  echo "[$current/$total] Processing: $repo_name @ ${commit:0:12}"
  echo "=========================================="
  if ! cleanup_codeql_temp_artifacts "$repo_dir"; then
    failed=$((failed + 1))
    failed_entries+=("$repo_name@$commit:cleanup")
    echo "Failed: $repo_name @ ${commit:0:12} (cleanup failed)"
    echo ""
    continue
  fi

  cmd=(
    software-profile
    --repo-name "$repo_name"
    --repo-base-path "$REPO_BASE_PATH"
    --target-version "$commit"
    --llm-provider "$LLM_PROVIDER"
    --output-dir "$OUTPUT_DIR"
  )
  if [[ -n "$LLM_NAME" ]]; then
    cmd+=(--llm-name "$LLM_NAME")
  fi
  if [[ "$FORCE_REGENERATE" -eq 1 ]]; then
    cmd+=(--force-regenerate)
  fi
  cmd+=("${EXTRA_ARGS[@]}")

  # Prevent the child command from consuming this script's stdin and
  # terminating the outer loop early.
  if "${cmd[@]}" </dev/null; then
    succeeded=$((succeeded + 1))
    echo "Success: $repo_name @ ${commit:0:12}"
  else
    failed=$((failed + 1))
    failed_entries+=("$repo_name@$commit")
    echo "Failed: $repo_name @ ${commit:0:12}"
  fi
  echo ""
done

echo "=========================================="
echo "Batch Processing Complete"
echo "=========================================="
echo "Total processed: $total"
echo "Succeeded: $succeeded"
echo "Failed: $failed"
if [[ ${#failed_entries[@]} -gt 0 ]]; then
  echo "Failed entries:"
  for failed_entry in "${failed_entries[@]}"; do
    echo "  - $failed_entry"
  done
fi
echo "Results saved to: $OUTPUT_DIR"

if [[ "$failed" -gt 0 ]]; then
  exit 1
fi
