#!/usr/bin/env bash
set -euo pipefail

ROOT="data/repos"

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