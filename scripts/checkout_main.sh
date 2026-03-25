#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
APP_DIR="${APP_DIR:-$(cd "$SCRIPT_DIR/.." && pwd -P)}"
ROOT="${ROOT:-$SCRIPT_DIR/../data/repos}"

if command -v realpath >/dev/null 2>&1; then
  ROOT="$(realpath -m "$ROOT")"
fi

if [[ ! -d "$ROOT" ]]; then
  echo "ERROR: repo root not found: $ROOT" >&2
  exit 1
fi

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

for d in "$ROOT"/*; do
  [[ -d "$d" ]] || continue

  # first-level only: pull if it is a git repo
  if [[ -d "$d/.git" ]] || git -C "$d" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "=== Updating: $d ==="
    "${PYTHON_CMD[@]}" - "$APP_DIR" "$d" <<'PY'
from pathlib import Path
import subprocess
import sys

app_dir = Path(sys.argv[1]).resolve()
repo_dir = Path(sys.argv[2]).resolve()

sys.path.insert(0, str(app_dir / "src"))

from config import _path_config
from utils import repo_lock as repo_lock_module

_path_config["repo_root"] = app_dir

with repo_lock_module.hold_repo_lock(repo_dir, purpose="checkout_main"):
    default_branch = subprocess.run(
        ["git", "-C", str(repo_dir), "symbolic-ref", "-q", "--short", "refs/remotes/origin/HEAD"],
        capture_output=True,
        text=True,
        check=False,
    ).stdout.strip()
    default_branch = default_branch.removeprefix("origin/")
    if not default_branch:
        raise SystemExit(0)
    subprocess.run(["git", "-C", str(repo_dir), "checkout", default_branch], check=True)
PY
    echo
  else
    echo "=== Skipping (not a git repo): $d ==="
  fi
done
