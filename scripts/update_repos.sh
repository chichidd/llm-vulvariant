#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
ROOT="${ROOT:-$SCRIPT_DIR/../../data/repos}"

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
    git -C "$d" pull --ff-only
    echo
  else
    echo "=== Skipping (not a git repo): $d ==="
  fi
done
