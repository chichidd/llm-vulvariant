#!/usr/bin/env bash
set -euo pipefail

# Run `software-profile p-analysis` for each first-level repo under data/repos.
#
# Shared path helper for profile-dir fallback logic.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
APP_DIR="${APP_DIR:-$(cd "$SCRIPT_DIR/.." && pwd -P)}"
source "$SCRIPT_DIR/profile_paths.sh"

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

# Examples:
#   ./scripts/run_all_software_profiles.sh
#   ./scripts/run_all_software_profiles.sh --llm-provider openai --llm-name gpt-4.1 --output-dir ~/vuln/profiles/soft --verbose
#   ./scripts/run_all_software_profiles.sh --force-regenerate
#   ./scripts/run_all_software_profiles.sh -- --verbose
#.  under llm-vulvariant: ./scripts/run_all_software_profiles.sh --llm-provider deepseek --output-dir ~/vuln/profiles/soft
# Notes:
# - Repo name A is the folder name under data/repos (first level only).
# - Extra args must be supported by the current software-profile CLI.

ROOT_DIR="${ROOT_DIR:-../data/repos}"

LLM_PROVIDER=""   # optional; if empty, don't pass it (tool default applies)
LLM_NAME=""       # optional; if empty, don't pass it (tool default applies)
OUTPUT_DIR=""     # optional; if empty, don't pass it (tool default applies)
PROFILE_BASE_PATH=""      # optional; used when OUTPUT_DIR is empty
SOFT_PROFILE_DIRNAME="soft"  # optional; used when OUTPUT_DIR is empty
FORCE_REGENERATE=0

EXTRA_ARGS=()

has_force_regenerate_arg() {
  local arg
  for arg in "${EXTRA_ARGS[@]}"; do
    if [[ "$arg" == "--force-regenerate" ]]; then
      return 0
    fi
  done
  return 1
}

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

resolve_locked_head_commit() {
  local repo_dir="$1"
  "${PYTHON_CMD[@]}" - resolve_locked_head_commit "$APP_DIR" "$repo_dir" <<'PY'
from pathlib import Path
import sys

app_dir = Path(sys.argv[2]).resolve()
repo_dir = Path(sys.argv[3]).resolve()

sys.path.insert(0, str(app_dir / "src"))

from config import _path_config
from utils import git_utils as git_utils_module
from utils import repo_lock as repo_lock_module

_path_config["repo_root"] = app_dir
git_utils_module.logger.disabled = True
repo_lock_module.logger.disabled = True

with repo_lock_module.hold_repo_lock(repo_dir, purpose="script_resolve_head_commit"):
    commit = git_utils_module.get_git_commit(str(repo_dir))

if not commit:
    raise SystemExit(f"Failed to resolve git HEAD for {repo_dir}")

print(commit)
PY
}

usage() {
  cat <<EOF
Usage: $0 [--root DIR] [--llm-provider X1] [--llm-name X2] [--output-dir C1] [--profile-base-path P] [--soft-profile-dirname N] [--force-regenerate] [-- ...extra args...]

Env overrides:
  ROOT_DIR=data/repos

Examples:
  $0
  $0 --llm-provider openai --llm-name gpt-4.1 --output-dir ~/vuln/profiles/soft --verbose
  $0 --force-regenerate
  $0 -- --verbose
EOF
}

# Parse known args; everything else is forwarded.
while [[ $# -gt 0 ]]; do
  case "$1" in
    --root)
      ROOT_DIR="$2"; shift 2 ;;
    --llm-provider)
      LLM_PROVIDER="$2"; shift 2 ;;
    --llm-name)
      LLM_NAME="$2"; shift 2 ;;
    --output-dir)
      OUTPUT_DIR="$2"; shift 2 ;;
    --profile-base-path)
      PROFILE_BASE_PATH="$2"; shift 2 ;;
    --soft-profile-dirname)
      SOFT_PROFILE_DIRNAME="$2"; shift 2 ;;
    --force-regenerate)
      FORCE_REGENERATE=1; shift ;;
    -h|--help)
      usage; exit 0 ;;
    --)
      shift
      EXTRA_ARGS+=("$@")
      break ;;
    *)
      EXTRA_ARGS+=("$1")
      shift ;;
  esac
done

if has_force_regenerate_arg; then
  FORCE_REGENERATE=1
fi

# Normalize ROOT_DIR to an absolute path relative to the repository root so
# forwarded flags stay stable even when the script is launched elsewhere.
ROOT_DIR="$(_profile_realpath "$ROOT_DIR")"

if [[ -n "$OUTPUT_DIR" ]]; then
  OUTPUT_DIR="$(_profile_realpath "$OUTPUT_DIR")"
  mkdir -p "$OUTPUT_DIR"
fi
if [[ -n "$PROFILE_BASE_PATH" ]]; then
  PROFILE_BASE_PATH="$(_profile_realpath "$PROFILE_BASE_PATH")"
fi


if [[ ! -d "$ROOT_DIR" ]]; then
  echo "ERROR: ROOT_DIR not found: $ROOT_DIR" >&2
  exit 1
fi

BASE_CMD=(software-profile)

# Add optional knobs only if user provided them (otherwise tool defaults apply)
if [[ -n "$LLM_PROVIDER" ]]; then
  BASE_CMD+=(--llm-provider "$LLM_PROVIDER")
fi
if [[ -n "$LLM_NAME" ]]; then
  BASE_CMD+=(--llm-name "$LLM_NAME")
fi
if [[ -n "$OUTPUT_DIR" ]]; then
  BASE_CMD+=(--output-dir "$OUTPUT_DIR")
else
  if [[ -n "$PROFILE_BASE_PATH" ]]; then
    BASE_CMD+=(--profile-base-path "$PROFILE_BASE_PATH")
  fi
  if [[ -n "$SOFT_PROFILE_DIRNAME" ]]; then
    BASE_CMD+=(--software-profile-dirname "$SOFT_PROFILE_DIRNAME")
  fi
fi
if [[ "$FORCE_REGENERATE" -eq 1 ]] && ! has_force_regenerate_arg; then
  BASE_CMD+=(--force-regenerate)
fi

# Pass the root directory so software-profile knows where to find repos
BASE_CMD+=(--repo-base-path "$ROOT_DIR")

# Forward additional supported software-profile flags such as --verbose.
BASE_CMD+=("${EXTRA_ARGS[@]}")


echo "Base command:"
printf '  %q' "${BASE_CMD[@]}"
echo
echo
echo "Root: $ROOT_DIR"
echo

shopt -s nullglob
failed_repos=()
failed=0
succeeded=0
total=0
for d in "$ROOT_DIR"/*; do
  [[ -d "$d" ]] || continue
  total=$((total + 1))
done
for repo_dir in "$ROOT_DIR"/*; do
  [[ -d "$repo_dir" ]] || continue

  # Only first-level git repos
  if [[ -d "$repo_dir/.git" ]] || git -C "$repo_dir" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    repo_name="$(basename "$repo_dir")"
    if ! commit="$(resolve_locked_head_commit "$repo_dir")"; then
      failed=$((failed + 1))
      failed_repos+=("$repo_name@unknown")
      echo "=== Failed resolving commit for repo: $repo_name ===" >&2
      echo
      continue
    fi
    
    echo "=== Running for repo: $repo_name ==="
    echo "Repo path: $repo_dir"
    if ! cleanup_codeql_temp_artifacts "$repo_dir"; then
      failed=$((failed + 1))
      failed_repos+=("$repo_name@$commit")
      echo "Failed: $repo_name @ ${commit:0:12} (cleanup failed)"
      echo
      continue
    fi

    # If the tool needs to run within the repo, run it from that directory.
    # If it instead needs an explicit path flag, add it here.
    if (
      cd "$repo_dir"
      "${BASE_CMD[@]}" --repo-name "$repo_name" --target-version "$commit"
    ); then
      succeeded=$((succeeded + 1))
      echo
    else
      failed=$((failed + 1))
      failed_repos+=("$repo_name@$commit")
      echo "Failed: $repo_name @ ${commit:0:12}"
      echo
    fi
  else
    echo "=== Skipping (not a git repo): $repo_dir ==="
  fi
done

echo "=========================================="
echo "Batch Processing Complete"
echo "=========================================="
echo "Total processed: $total"
echo "Succeeded: $succeeded"
echo "Failed: $failed"
if [[ ${#failed_repos[@]} -gt 0 ]]; then
  echo "Failed repos:"
  for failed_repo in "${failed_repos[@]}"; do
    echo "  - $failed_repo"
  done
fi
echo "Results saved to: $OUTPUT_DIR"

if [[ "$failed" -gt 0 ]]; then
  exit 1
fi
