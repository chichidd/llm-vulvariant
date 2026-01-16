#!/usr/bin/env python3
"""Batch-scan repositories under a root folder.

Intended use: point at your project folder's `data/repos` which contains many
AI infra repositories (e.g., the examples you listed).

For each repo directory, it runs the ai-infra-module-modeler scanner and writes
outputs to `<out>/<repo_name>/`.

Outputs per repo:
- signals.json
- module_map.json
- MODULES.md
"""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path


def is_git_repo(p: Path) -> bool:
    return (p / ".git").exists() and (p / ".git").is_dir()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repos", required=True, help="Root folder that contains many repo folders")
    ap.add_argument("--out", required=True, help="Output root folder")
    ap.add_argument(
        "--scanner",
        default=str(
            Path(__file__).resolve().parents[1]
            / ".claude/skills/ai-infra-module-modeler/scripts/scan_repo.py"
        ),
        help="Path to scan_repo.py (defaults to the one in this skill pack)",
    )
    ap.add_argument("--exclude", nargs="*", default=[], help="Extra directory names to exclude")
    args = ap.parse_args()

    repos_root = Path(args.repos).expanduser().resolve()
    out_root = Path(args.out).expanduser().resolve()
    scanner = Path(args.scanner).expanduser().resolve()

    if not repos_root.exists() or not repos_root.is_dir():
        raise SystemExit(f"repos root not found: {repos_root}")
    if not scanner.exists():
        raise SystemExit(f"scanner not found: {scanner}")
    out_root.mkdir(parents=True, exist_ok=True)

    repo_dirs = [p for p in repos_root.iterdir() if p.is_dir()]
    if not repo_dirs:
        raise SystemExit(f"no repo folders found under: {repos_root}")

    for repo in sorted(repo_dirs, key=lambda p: p.name.lower()):
        # Heuristic: skip obvious non-repos unless it's a git repo or has code-ish files.
        if not is_git_repo(repo):
            has_code = any((repo / f).exists() for f in ["pyproject.toml", "package.json", "go.mod", "Cargo.toml"])
            if not has_code:
                continue

        out_dir = out_root / repo.name
        out_dir.mkdir(parents=True, exist_ok=True)

        cmd = ["python3", str(scanner), "--repo", str(repo), "--out", str(out_dir)]
        if args.exclude:
            cmd += ["--exclude", *args.exclude]

        print(f"[scan] {repo.name}")
        subprocess.run(cmd, check=False)

    print(f"Done. Results in: {out_root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
