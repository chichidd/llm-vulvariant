#!/usr/bin/env python3
"""Generate a non-destructive module skeleton from a module_map.json.

This script is intentionally conservative:
- It never overwrites existing files unless --force is set.
- It creates a stable folder layout that can be used as a starting point for
  documenting/refactoring an AI infra repository.

Expected input shape (produced by scan_repo.py):
{
  "repo": "...",
  "taxonomy": "AI_INFRA_TAXONOMY",
  "selected_modules": ["training_optimization", ...],
  "modules": {"training_optimization": {"score":..., "evidence":[...], "hits":{...}}, ...}
}
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List

from ai_infra_taxonomy import AI_INFRA_TAXONOMY


def safe_write(path: Path, content: str, force: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not force:
        return
    path.write_text(content, encoding="utf-8")


def render_module_readme(coarse: str, fine: Dict[str, Any], module_info: Dict[str, Any] | None) -> str:
    lines: List[str] = []
    lines.append(f"# Module: {coarse}")
    lines.append("")
    lines.append("## Purpose")
    lines.append("Describe the responsibility boundaries of this module and the key APIs/configs that belong here.")
    lines.append("")
    lines.append("## Submodules")
    for k in fine.keys():
        lines.append(f"- `{k}`: TODO")
    lines.append("")
    lines.append("## Evidence (from repo scan)")
    if module_info:
        lines.append(f"- score: {module_info.get('score')}")
        hits = module_info.get("hits", {})
        if hits:
            lines.append(f"- hits: {hits}")
        ev = module_info.get("evidence", [])
        for item in ev[:20]:
            lines.append(f"- {item}")
    else:
        lines.append("- (no scan evidence provided)")
    lines.append("")
    lines.append("## Checklist")
    lines.append(
        "See `references/checklists/` in the `ai-infra-module-modeler` skill for inclusion/exclusion criteria."
    )
    lines.append("")
    return "\n".join(lines)


def render_submodule_stub(coarse: str, fine_key: str) -> str:
    return "\n".join(
        [
            f"# Submodule: {coarse}.{fine_key}",
            "",
            "## Scope",
            "TODO: define scope and boundaries.",
            "",
            "## Typical files",
            "- TODO",
            "",
            "## Tests / benchmarks",
            "- TODO",
            "",
        ]
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--module-map", required=True, help="Path to module_map.json (from scan_repo.py)")
    ap.add_argument("--out", required=True, help="Output directory for skeleton")
    ap.add_argument("--force", action="store_true", help="Overwrite existing files")
    ap.add_argument(
        "--include-fine",
        action="store_true",
        help="Also create fine-grained submodule folders with stub READMEs",
    )
    args = ap.parse_args()

    module_map_p = Path(args.module_map).expanduser().resolve()
    out_dir = Path(args.out).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    data = json.loads(module_map_p.read_text(encoding="utf-8"))
    selected: List[str] = list(data.get("selected_modules", []))
    module_infos: Dict[str, Any] = dict(data.get("modules", {}))

    # Root README
    root_lines = [
        "# AI Infra Module Skeleton",
        "",
        f"Source scan: `{module_map_p}`",
        "",
        "## Modules",
    ]
    for m in selected:
        root_lines.append(f"- `{m}/`")
    safe_write(out_dir / "README.md", "\n".join(root_lines) + "\n", force=args.force)

    # Per-module dirs
    for coarse in selected:
        fine = AI_INFRA_TAXONOMY.get(coarse, {})
        mi = module_infos.get(coarse)
        coarse_dir = out_dir / coarse
        coarse_dir.mkdir(parents=True, exist_ok=True)
        safe_write(coarse_dir / "README.md", render_module_readme(coarse, fine, mi), force=args.force)

        if args.include_fine and isinstance(fine, dict):
            for fine_key in fine.keys():
                sd = coarse_dir / fine_key
                sd.mkdir(parents=True, exist_ok=True)
                safe_write(sd / "README.md", render_submodule_stub(coarse, fine_key), force=args.force)

    print(f"Wrote module skeleton to: {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
