#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
ROOT="${ROOT:-$SCRIPT_DIR/../data/repos}"

if command -v realpath >/dev/null 2>&1; then
  ROOT="$(realpath -m "$ROOT")"
fi

if [[ ! -d "$ROOT" ]]; then
  echo "ERROR: repo root not found: $ROOT" >&2
  exit 1
fi

for d in "$ROOT"/*; do
  [[ -d "$d" ]] || continue

  # first-level only: pull if it is a git repo
  if [[ -d "$d/.git" ]] || git -C "$d" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "=== Updating: $d ==="
    
    # Resolve the tracked default branch from local refs so the helper does
    # not require network access just to decide what to check out.
    default_branch="$(git -C "$d" symbolic-ref -q --short refs/remotes/origin/HEAD 2>/dev/null || true)"
    default_branch="${default_branch#origin/}"
    if [[ -z "$default_branch" ]]; then
      echo "=== Skipping (default branch not found): $d ===" >&2
      continue
    fi
    
    # Checkout the default branch
    git -C "$d" checkout "$default_branch"
    
    echo
  else
    echo "=== Skipping (not a git repo): $d ==="
  fi
done
