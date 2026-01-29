#!/usr/bin/env bash
set -euo pipefail

# Run `software-profile p-analysis` for each first-level repo under data/repos.
#
# Examples:
#   ./run_profiles.sh
#   ./run_profiles.sh --llm-provider openai --llm-name gpt-4.1 --output-dir ./repo-profiles --verbose
#   ./run_profiles.sh -- --verbose --some-other-flag 123
#
# Notes:
# - Repo name A is the folder name under data/repos (first level only).
# - You can pass any extra args; they will be forwarded to the command.

ROOT_DIR="${ROOT_DIR:-../data/repos}"

LLM_PROVIDER=""   # optional; if empty, don't pass it (tool default applies)
LLM_NAME=""       # optional; if empty, don't pass it (tool default applies)
OUTPUT_DIR=""     # optional; if empty, don't pass it (tool default applies)

EXTRA_ARGS=()

usage() {
  cat <<EOF
Usage: $0 [--root DIR] [--llm-provider X1] [--llm-name X2] [--output-dir C1] [-- ...extra args...]

Env overrides:
  ROOT_DIR=data/repos

Examples:
  $0
  $0 --llm-provider openai --llm-name gpt-4.1 --output-dir ./repo-profiles --verbose
  $0 -- --verbose --dry-run
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


# --- Normalize OUTPUT_DIR to an absolute path (relative to where the script was launched) ---
START_DIR="$(pwd -P)"

if [[ -n "$OUTPUT_DIR" ]]; then
  # If OUTPUT_DIR is relative, make it absolute based on START_DIR.
  if [[ "$OUTPUT_DIR" != /* ]]; then
    OUTPUT_DIR="$START_DIR/$OUTPUT_DIR"
  fi

  # Normalize path if realpath is available; otherwise keep as-is.
  if command -v realpath >/dev/null 2>&1; then
    OUTPUT_DIR="$(realpath -m "$OUTPUT_DIR")"
  fi

  # Ensure output directory exists (so the tool can write into it).
  mkdir -p "$OUTPUT_DIR"
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
fi

# Forward any additional flags like --verbose, --enable-dee, etc.
BASE_CMD+=("${EXTRA_ARGS[@]}")


echo "Base command:"
printf '  %q' "${BASE_CMD[@]}"
echo
echo
echo "Root: $ROOT_DIR"
echo

shopt -s nullglob
for repo_dir in "$ROOT_DIR"/*; do
  [[ -d "$repo_dir" ]] || continue

  # Only first-level git repos
  if [[ -d "$repo_dir/.git" ]] || git -C "$repo_dir" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    repo_name="$(basename "$repo_dir")"
    
    # Skip if already completed (check for output file)
    if [[ -n "$OUTPUT_DIR" ]] && [[ -f "$OUTPUT_DIR/${repo_name}/software_profile.json" ]]; then
      echo "=== Skipping (already completed): $repo_name ==="
      continue
    fi
    
    echo "=== Running for repo: $repo_name ==="
    echo "Repo path: $repo_dir"

    # If the tool needs to run within the repo, run it from that directory.
    # If it instead needs an explicit path flag, add it here.
    (
      cd "$repo_dir"
      "${BASE_CMD[@]}" --repo-name "$repo_name"
    )

    echo
  else
    echo "=== Skipping (not a git repo): $repo_dir ==="
  fi
done


# software-profile   --repo-name ms-swift   --llm-provider openai --llm-name deepseek-chat      --enable-deep-analysis  --output-dir ./repo-profiles/ --enable-deep-analysis

# software-profile   --repo-name llama_index   --llm-provider openai --llm-name deepseek-chat     --enable-deep-analysis  --output-dir ./repo-profiles/ --enable-deep-analysis

# software-profile   --repo-name langchain   --llm-provider openai --llm-name deepseek-chat     --enable-deep-analysis  --output-dir ./repo-profiles/ --enable-deep-analysis

# software-profile   --repo-name llama_index   --llm-provider openai --llm-name deepseek-chat     --enable-deep-analysis  --output-dir ./repo-profiles/ --enable-deep-analysis

