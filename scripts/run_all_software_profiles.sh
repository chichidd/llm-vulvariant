#!/usr/bin/env bash
set -euo pipefail

# Run `software-profile p-analysis` for each first-level repo under data/repos.
#
# Examples:
#   ./run_profiles.sh
#   ./run_profiles.sh --llm-provider openai --llm-name gpt-4.1 --output-dir ~/vuln/profiles/soft --verbose
#   ./run_profiles.sh --force-regenerate
#   ./run_profiles.sh -- --verbose --some-other-flag 123
#.  under llm-vulvariant: ./scripts/run_all_software_profiles.sh --llm-provider deepseek --output-dir ~/vuln/profiles/soft
# Notes:
# - Repo name A is the folder name under data/repos (first level only).
# - You can pass any extra args; they will be forwarded to the command.

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

  local cleaned=0
  if [[ -L "$repo_dir/_codeql_detected_source_root" || -e "$repo_dir/_codeql_detected_source_root" ]]; then
    rm -f "$repo_dir/_codeql_detected_source_root"
    cleaned=1
  fi
  if [[ -d "$repo_dir/_codeql_build_dir" ]]; then
    rm -rf "$repo_dir/_codeql_build_dir"
    cleaned=1
  fi
  if [[ "$cleaned" -eq 1 ]]; then
    echo "Cleaned CodeQL temp artifacts: $repo_dir"
  fi
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


# --- Normalize OUTPUT_DIR to an absolute path (relative to where the script was launched) ---
START_DIR="$(pwd -P)"

# Normalize ROOT_DIR to an absolute path so forwarded flags remain valid
# even when the command runs inside each repository directory.
if [[ "$ROOT_DIR" != /* ]]; then
  ROOT_DIR="$START_DIR/$ROOT_DIR"
fi
if command -v realpath >/dev/null 2>&1; then
  ROOT_DIR="$(realpath -m "$ROOT_DIR")"
fi

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
    if [[ -n "$OUTPUT_DIR" && "$FORCE_REGENERATE" -eq 0 ]]; then
      commit="$(git -C "$repo_dir" rev-parse HEAD 2>/dev/null || true)"
      if [[ -n "$commit" ]] && [[ -f "$OUTPUT_DIR/${repo_name}/${commit}/software_profile.json" ]]; then
        echo "=== Skipping (already completed): $repo_name@$commit ==="
        continue
      fi
    fi
    
    echo "=== Running for repo: $repo_name ==="
    echo "Repo path: $repo_dir"
    cleanup_codeql_temp_artifacts "$repo_dir"

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


# software-profile   --repo-name ms-swift   --llm-provider openai --llm-name deepseek-chat      --enable-deep-analysis  --output-dir ~/vuln/profiles/soft --enable-deep-analysis

# software-profile   --repo-name llama_index   --llm-provider openai --llm-name deepseek-chat     --enable-deep-analysis  --output-dir ~/vuln/profiles/soft --enable-deep-analysis

# software-profile   --repo-name langchain   --llm-provider openai --llm-name deepseek-chat     --enable-deep-analysis  --output-dir ~/vuln/profiles/soft --enable-deep-analysis

# software-profile   --repo-name llama_index   --llm-provider openai --llm-name deepseek-chat     --enable-deep-analysis  --output-dir ~/vuln/profiles/soft --enable-deep-analysis
