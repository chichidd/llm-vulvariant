#!/usr/bin/env bash
set -euo pipefail

# Generate software profiles for all repo/commit pairs in vuln.json.

VULN_JSON="${VULN_JSON:-$HOME/vuln/data/vuln.json}"
REPO_BASE_PATH="${REPO_BASE_PATH:-$HOME/vuln/data/repos}"
PROFILE_BASE_PATH="${PROFILE_BASE_PATH:-$HOME/vuln/profiles}"
SOFT_PROFILE_DIRNAME="${SOFT_PROFILE_DIRNAME:-soft}"
OUTPUT_DIR="${OUTPUT_DIR:-}"
LLM_PROVIDER="${LLM_PROVIDER:-deepseek}"
LLM_NAME="${LLM_NAME:-}"
EXTRA_ARGS=()

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
Usage: $0 [options] [-- ...extra software-profile args]

Options:
  --vuln-json PATH               Path to vuln.json (default: $VULN_JSON)
  --repo-base-path PATH          Repositories base path (default: $REPO_BASE_PATH)
  --profile-base-path PATH       Profiles base path (default: $PROFILE_BASE_PATH)
  --soft-profile-dirname NAME    Soft profile subdir under profile base (default: $SOFT_PROFILE_DIRNAME)
  --output-dir PATH              Explicit output dir (overrides profile-base + soft-profile-dirname)
  --llm-provider NAME            LLM provider (default: $LLM_PROVIDER)
  --llm-name NAME                Optional LLM model override
  -h, --help                     Show help

Examples:
  $0
  $0 --profile-base-path ~/vuln/profiles --soft-profile-dirname soft
  $0 --output-dir /tmp/soft-profiles --llm-provider deepseek
  $0 -- --force-full-analysis
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

if [[ -z "$OUTPUT_DIR" ]]; then
  OUTPUT_DIR="$PROFILE_BASE_PATH/$SOFT_PROFILE_DIRNAME"
fi

VULN_JSON="$(realpath -m "$VULN_JSON")"
REPO_BASE_PATH="$(realpath -m "$REPO_BASE_PATH")"
OUTPUT_DIR="$(realpath -m "$OUTPUT_DIR")"

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
echo ""

if [[ ! -f "$VULN_JSON" ]]; then
  echo "Error: vuln.json not found: $VULN_JSON" >&2
  exit 1
fi
if [[ ! -d "$REPO_BASE_PATH" ]]; then
  echo "Error: repo base path not found: $REPO_BASE_PATH" >&2
  exit 1
fi

mkdir -p "$OUTPUT_DIR"

mapfile -t entries < <(jq -r '.[] | "\(.repo_name)|\(.commit)"' "$VULN_JSON" | sort -u)
if [[ ${#entries[@]} -eq 0 ]]; then
  echo "No entries found in vuln.json"
  exit 0
fi

total="${#entries[@]}"
current=0
failed=0
succeeded=0

for entry in "${entries[@]}"; do
  IFS='|' read -r repo_name commit <<< "$entry"
  [[ -n "$repo_name" && -n "$commit" ]] || continue
  current=$((current + 1))
  repo_dir="$REPO_BASE_PATH/$repo_name"

  echo "=========================================="
  echo "[$current/$total] Processing: $repo_name @ ${commit:0:12}"
  echo "=========================================="
  cleanup_codeql_temp_artifacts "$repo_dir"

  cmd=(
    software-profile
    --repo-name "$repo_name"
    --repo-base-path "$REPO_BASE_PATH"
    --target-version "$commit"
    --llm-provider "$LLM_PROVIDER"
    --output-dir "$OUTPUT_DIR"
    --force-full-analysis
  )
  if [[ -n "$LLM_NAME" ]]; then
    cmd+=(--llm-name "$LLM_NAME")
  fi
  cmd+=("${EXTRA_ARGS[@]}")

  # Prevent the child command from consuming this script's stdin and
  # terminating the outer loop early.
  if "${cmd[@]}" </dev/null; then
    succeeded=$((succeeded + 1))
    echo "Success: $repo_name @ ${commit:0:12}"
  else
    failed=$((failed + 1))
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
echo "Results saved to: $OUTPUT_DIR"
