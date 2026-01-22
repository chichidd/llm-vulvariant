#!/usr/bin/env python3
"""LLM-driven module classification for AI infra repositories.

This scanner uses repository structure plus LLM semantic reasoning (no keyword rules)
to classify a repo into a hierarchical AI-infra module taxonomy.

Outputs (in --out directory):
- signals.json: LLM grouping + assignment metadata
- module_map.json: coarse module labels with evidence (paths + counts)
- file_index.json: file -> module assignment (coarse.fine labels)
- module_profile.json: module list in software-profile schema
- MODULES.md: summary report
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import textwrap
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ai_infra_taxonomy import AI_INFRA_TAXONOMY, taxonomy_to_markdown


LLMConfig = None
create_llm_client = None


def _ensure_llm_import() -> bool:
    """Load llm client from installed package or repo source."""
    global LLMConfig, create_llm_client
    if LLMConfig and create_llm_client:
        return True
    try:
        from llm import LLMConfig as _LLMConfig, create_llm_client as _create_llm_client
    except Exception:
        project_root = Path(__file__).resolve().parents[4]
        src_root = project_root / "src"
        if src_root.exists() and str(src_root) not in sys.path:
            sys.path.insert(0, str(src_root))
        try:
            from llm import LLMConfig as _LLMConfig, create_llm_client as _create_llm_client
        except Exception:
            return False
    LLMConfig = _LLMConfig
    create_llm_client = _create_llm_client
    return True


# Directories commonly considered non-source or vendor content.
DEFAULT_EXCLUDE_DIRS = {
    ".git", ".hg", ".svn", ".tox", ".venv", "venv", "__pycache__", ".mypy_cache",
    "node_modules", "dist", "build", "target", "out", "bazel-bin", "bazel-out",
    "bazel-testlogs", "bazel-workspace", ".idea", ".vscode", ".pytest_cache",
}

DEFAULT_MAX_FILES = 2000
DEFAULT_MAX_BYTES = 200_000
DEFAULT_GROUP_DEPTH = 1000000
DEFAULT_GROUP_SAMPLE_FILES = 12
DEFAULT_GROUP_SNIPPETS = 2
DEFAULT_SNIPPET_BYTES = 800
DEFAULT_BATCH_SIZE = 12
DEFAULT_MIN_FILE_SCORE = 2

TEXT_EXTS = {
    ".py", ".pyi", ".md", ".rst", ".txt", ".toml", ".ini", ".cfg", ".json", ".yaml", ".yml",
    ".sh", ".bash", ".ps1", ".go", ".rs", ".java", ".kt", ".scala", ".c", ".cc", ".cpp",
    ".h", ".hpp", ".cu", ".cuh", ".cmake", ".gradle", ".dockerfile",
}

# A small set of "high-signal" files to read even if extension is unknown.
SPECIAL_FILENAMES = {
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml", "Makefile", "CMakeLists.txt",
    "pyproject.toml", "setup.py", "setup.cfg", "requirements.txt", "requirements.in",
    "Pipfile", "Pipfile.lock", "poetry.lock", "package.json", "pnpm-lock.yaml",
    "yarn.lock", "go.mod", "Cargo.toml", "Cargo.lock", "SECURITY.md", "README", "README.md",
}


def flatten_taxonomy(tax: dict) -> List[str]:
    """Return stable coarse module keys from taxonomy."""
    return list(tax.keys())


COARSE_MODULES = flatten_taxonomy(AI_INFRA_TAXONOMY)


@dataclass
class Evidence:
    score: int
    evidence: List[str]
    hits: Dict[str, int]


@dataclass
class Signals:
    repo: str
    files_scanned: int
    total_files: int
    excluded_dirs: List[str]
    group_depth: int
    llm_provider: str
    llm_model: str
    group_assignments: Dict[str, str]


@dataclass
class GroupSummary:
    group: str
    file_count: int
    sample_paths: List[str]
    snippets: List[Dict[str, str]]


def read_text_safely(path: Path, max_bytes: int = 200_000) -> str:
    try:
        data = path.read_bytes()
    except Exception:
        return ""
    if len(data) > max_bytes:
        data = data[:max_bytes]
    for enc in ("utf-8", "utf-8-sig", "latin-1"):
        try:
            return data.decode(enc, errors="ignore")
        except Exception:
            continue
    return ""


def should_scan_file(path: Path) -> bool:
    if path.name in SPECIAL_FILENAMES:
        return True
    ext = path.suffix.lower()
    return ext in TEXT_EXTS


def iter_files(repo: Path, exclude_dirs: set[str], max_files: int) -> Tuple[List[Path], List[Path], int]:
    scan_files: List[Path] = []
    all_files: List[Path] = []
    total = 0
    for root, dirs, filenames in os.walk(repo):
        root_p = Path(root)
        dirs[:] = [d for d in dirs if d not in exclude_dirs]
        for fn in filenames:
            total += 1
            p = root_p / fn
            if should_scan_file(p):
                all_files.append(p)
                if not max_files or len(scan_files) < max_files:
                    scan_files.append(p)
    return scan_files, all_files, total


def _group_key(rel_path: str, depth: int) -> str:
    parts = rel_path.split("/")
    dir_parts = parts[:-1]
    if not dir_parts:
        return "."
    depth = min(depth, len(dir_parts))
    return "/".join(dir_parts[:depth])


def group_files(file_paths: List[str], depth: int) -> Dict[str, List[str]]:
    grouped: Dict[str, List[str]] = {}
    for rel in file_paths:
        key = _group_key(rel, depth)
        grouped.setdefault(key, []).append(rel)
    for key in grouped:
        grouped[key] = sorted(grouped[key])
    return grouped


def _compact_text(text: str, max_chars: int) -> str:
    if not text:
        return ""
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) > max_chars:
        text = text[:max_chars].rstrip()
    return text


def select_sample_files(group_to_files: Dict[str, List[str]], max_files: int) -> List[str]:
    if max_files <= 0:
        return []
    samples: List[str] = []
    groups_sorted = sorted(group_to_files.items(), key=lambda kv: len(kv[1]), reverse=True)
    for _, files in groups_sorted:
        if len(samples) >= max_files:
            break
        if files:
            samples.append(files[0])
    idx = 1
    while len(samples) < max_files:
        added = False
        for _, files in groups_sorted:
            if len(samples) >= max_files:
                break
            if idx < len(files):
                samples.append(files[idx])
                added = True
        if not added:
            break
        idx += 1
    return samples


def build_group_summaries(
    repo: Path,
    group_to_files: Dict[str, List[str]],
    sample_files: List[str],
    sample_paths_per_group: int,
    snippet_bytes: int,
    max_snippets_per_group: int,
) -> List[GroupSummary]:
    sample_lookup = set(sample_files)
    summaries: List[GroupSummary] = []
    for group, files in sorted(group_to_files.items()):
        sample_paths = files[:sample_paths_per_group]
        snippets: List[Dict[str, str]] = []
        for rel in files:
            if rel not in sample_lookup:
                continue
            if len(snippets) >= max_snippets_per_group:
                break
            text = read_text_safely(repo / rel, max_bytes=snippet_bytes)
            text = _compact_text(text, max_chars=snippet_bytes)
            if text:
                snippets.append({"path": rel, "content": text})
        summaries.append(GroupSummary(
            group=group,
            file_count=len(files),
            sample_paths=sample_paths,
            snippets=snippets,
        ))
    return summaries


def load_taxonomy_reference() -> str:
    ref_path = Path(__file__).resolve().parents[1] / "references" / "taxonomy.md"
    if ref_path.exists():
        return ref_path.read_text(encoding="utf-8")
    return taxonomy_to_markdown()


def taxonomy_keys() -> Dict[str, List[str]]:
    return {coarse: list((fine or {}).keys()) for coarse, fine in AI_INFRA_TAXONOMY.items()}


def _response_content(response: Any) -> str:
    if isinstance(response, str):
        return response
    if isinstance(response, dict):
        return response.get("content") or response.get("message") or ""
    content = getattr(response, "content", None)
    if content:
        return content
    return ""


def _strip_think(text: str) -> str:
    if not text:
        return ""
    return re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()


def _parse_json_payload(text: str) -> Optional[Dict[str, Any]]:
    if not text:
        return None
    text = _strip_think(text)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, flags=re.DOTALL)
        if match:
            try:
                return json.loads(match.group(0))
            except json.JSONDecodeError:
                return None
    return None


def _split_module_name(module_name: str) -> Tuple[str, str]:
    if "." in module_name:
        coarse, fine = module_name.split(".", 1)
        if fine:
            return coarse, fine
        return coarse, coarse
    return module_name, module_name


def _default_module_name() -> str:
    if not AI_INFRA_TAXONOMY:
        return "platform_systems"
    coarse = next(iter(AI_INFRA_TAXONOMY.keys()))
    fine_map = AI_INFRA_TAXONOMY.get(coarse) or {}
    fine = next(iter(fine_map.keys()), "")
    return _module_name(coarse, fine)


def _module_name(coarse: str, fine: str) -> str:
    if not fine or fine == coarse:
        return coarse
    return f"{coarse}.{fine}"


def _normalize_module_name(module_name: str, default_module: str) -> str:
    if not module_name:
        return default_module
    coarse, fine = _split_module_name(str(module_name).strip())
    if coarse not in AI_INFRA_TAXONOMY:
        return default_module
    fine_map = AI_INFRA_TAXONOMY.get(coarse) or {}
    if fine in fine_map:
        return _module_name(coarse, fine)
    fallback_fine = next(iter(fine_map.keys()), "")
    return _module_name(coarse, fallback_fine)


def _prompt_for_groups(group_summaries: List[GroupSummary], taxonomy_ref: str) -> str:
    payload = [asdict(summary) for summary in group_summaries]
    prompt = f"""\
You are classifying AI infra repository areas into a fixed taxonomy.
Use semantic understanding of the group summaries, not keyword matching.

Return JSON exactly in this shape:
{{
  "assignments": [
    {{"group": "<group>", "module": "<coarse or coarse.fine>", "confidence": 0.0}}
  ]
}}

Rules:
- Use only the taxonomy keys provided below.
- If fine-grained module is unclear, use the coarse key.
- Keep confidence between 0 and 1.

Taxonomy keys (JSON):
{json.dumps(taxonomy_keys(), indent=2, ensure_ascii=True)}

Taxonomy reference:
{taxonomy_ref}

Groups to classify (JSON):
{json.dumps(payload, indent=2, ensure_ascii=True)}
"""
    return textwrap.dedent(prompt)


def classify_groups_with_llm(
    group_summaries: List[GroupSummary],
    llm_client: Any,
    batch_size: int,
    taxonomy_ref: str,
    require_llm: bool,
) -> Dict[str, str]:
    if not group_summaries:
        return {}
    if not llm_client:
        if require_llm:
            raise RuntimeError("LLM client not available")
        return {}

    assignments: Dict[str, str] = {}
    for i in range(0, len(group_summaries), batch_size):
        batch = group_summaries[i:i + batch_size]
        prompt = _prompt_for_groups(batch, taxonomy_ref)
        response = llm_client.chat([
            {"role": "system", "content": "You are an AI infra architect. Return JSON only."},
            {"role": "user", "content": prompt},
        ])
        content = _response_content(response)
        payload = _parse_json_payload(content)
        if not payload:
            if require_llm:
                raise RuntimeError("Failed to parse LLM response JSON")
            continue
        items = payload.get("assignments", [])
        for item in items:
            if not isinstance(item, dict):
                continue
            group = item.get("group")
            module = item.get("module")
            if group:
                assignments[str(group)] = str(module or "")
    return assignments


def build_module_profile(file_index: Dict[str, str]) -> List[Dict[str, Any]]:
    modules_by_name: Dict[str, List[str]] = {}
    for rel_path, module_name in file_index.items():
        modules_by_name.setdefault(module_name, []).append(rel_path)

    modules: List[Dict[str, Any]] = []
    for module_name, files in sorted(modules_by_name.items()):
        coarse, _ = _split_module_name(module_name)
        module = {
            "name": module_name,
            "category": coarse,
            "description": _describe_module(module_name, files),
            "paths": sorted(set(files)),
            "key_functions": [],
            "dependencies": [],
            "files": sorted(set(files)),
        }
        modules.append(module)
    return modules


def _describe_module(module_name: str, files: List[str]) -> str:
    coarse, fine = _split_module_name(module_name)
    coarse_label = coarse.replace("_", " ").title()
    fine_label = fine.replace("_", " ").title()
    description = f"{fine_label} responsibilities within {coarse_label}."
    top_dirs = _top_dirs_from_files(files)
    if top_dirs:
        description += f" Key areas: {', '.join(top_dirs)}."
    return description


def _top_dirs_from_files(files: List[str]) -> List[str]:
    counts: Dict[str, int] = {}
    for path in files:
        parts = path.split("/")
        if not parts:
            continue
        top = parts[0]
        counts[top] = counts.get(top, 0) + 1
    top_dirs = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:3]
    return [name for name, _ in top_dirs]


def build_evidences(file_index: Dict[str, str]) -> Dict[str, Evidence]:
    coarse_to_files: Dict[str, List[str]] = {}
    for rel_path, module_name in file_index.items():
        coarse, _ = _split_module_name(module_name)
        coarse_to_files.setdefault(coarse, []).append(rel_path)

    evidences: Dict[str, Evidence] = {}
    for coarse, files in sorted(coarse_to_files.items()):
        unique_files = sorted(set(files))
        evidence_paths = [f"path:{path}" for path in unique_files[:40]]
        evidences[coarse] = Evidence(
            score=len(unique_files),
            evidence=evidence_paths,
            hits={"files": len(unique_files)},
        )
    return evidences


def choose_modules(evidences: Dict[str, Evidence], min_file_score: int) -> List[str]:
    if not evidences:
        return []
    scores = [e.score for e in evidences.values()]
    top = max(scores) if scores else 0
    threshold = max(min_file_score, int(0.25 * top))
    picked = [m for m, e in evidences.items() if e.score >= threshold]
    picked_sorted = sorted(picked, key=lambda m: evidences[m].score, reverse=True)
    if len(picked_sorted) < 3:
        picked_sorted = sorted(evidences.keys(), key=lambda m: evidences[m].score, reverse=True)[:3]
    return picked_sorted


def scan(
    repo: Path,
    exclude_dirs: set[str],
    max_files: int,
    max_bytes: int,
    min_file_score: int,
    group_depth: int,
    group_sample_files: int,
    group_snippets: int,
    snippet_bytes: int,
    batch_size: int,
    llm_client: Any,
    require_llm: bool,
    file_list: Optional[List[str]] = None,
) -> Tuple[Signals, Dict[str, Evidence], Dict[str, str]]:
    scan_files, all_files, total_files = iter_files(repo, exclude_dirs, max_files)
    if file_list:
        file_paths = [str(p).replace("\\", "/") for p in file_list]
    else:
        file_paths = [str(p.relative_to(repo)).replace("\\", "/") for p in all_files]
        file_paths = sorted(file_paths)

    group_to_files = group_files(file_paths, group_depth)
    sample_files = select_sample_files(group_to_files, max_files)
    group_summaries = build_group_summaries(
        repo=repo,
        group_to_files=group_to_files,
        sample_files=sample_files,
        sample_paths_per_group=group_sample_files,
        snippet_bytes=min(max_bytes, snippet_bytes),
        max_snippets_per_group=group_snippets,
    )

    taxonomy_ref = load_taxonomy_reference()
    assignments = classify_groups_with_llm(
        group_summaries=group_summaries,
        llm_client=llm_client,
        batch_size=batch_size,
        taxonomy_ref=taxonomy_ref,
        require_llm=require_llm,
    )

    default_module = _default_module_name()
    file_index: Dict[str, str] = {}
    for group, files in group_to_files.items():
        module_name = assignments.get(group, default_module)
        module_name = _normalize_module_name(module_name, default_module)
        for rel in files:
            file_index[rel] = module_name

    evidences = build_evidences(file_index)

    signals = Signals(
        repo=str(repo),
        files_scanned=len(scan_files),
        total_files=total_files,
        excluded_dirs=sorted(list(exclude_dirs)),
        group_depth=group_depth,
        llm_provider=getattr(getattr(llm_client, "config", None), "provider", ""),
        llm_model=getattr(getattr(llm_client, "config", None), "model", ""),
        group_assignments=assignments,
    )
    return signals, evidences, file_index


def write_outputs(
    out_dir: Path,
    signals: Signals,
    evidences: Dict[str, Evidence],
    file_index: Dict[str, str],
    min_file_score: int,
) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    (out_dir / "signals.json").write_text(json.dumps(asdict(signals), indent=2), encoding="utf-8")
    (out_dir / "file_index.json").write_text(json.dumps(file_index, indent=2), encoding="utf-8")
    module_profile = {"modules": build_module_profile(file_index)}
    (out_dir / "module_profile.json").write_text(json.dumps(module_profile, indent=2), encoding="utf-8")

    picked = choose_modules(evidences, min_file_score)

    module_map = {
        "repo": signals.repo,
        "taxonomy": "AI_INFRA_TAXONOMY",
        "selected_modules": picked,
        "modules": {m: asdict(evidences[m]) for m in evidences},
    }
    (out_dir / "module_map.json").write_text(json.dumps(module_map, indent=2), encoding="utf-8")

    lines: List[str] = []
    lines.append(f"# Module summary for `{Path(signals.repo).name}`")
    lines.append("")
    lines.append(f"Scanned files: {signals.files_scanned} (of total files: {signals.total_files})")
    lines.append(f"Group depth: {signals.group_depth}")
    lines.append("")
    lines.append("## Detected modules (coarse)")
    for m in picked:
        e = evidences[m]
        lines.append(f"- **{m}** (files={e.score})")
    lines.append("")
    lines.append("## Evidence (sample paths)")
    for m in picked:
        e = evidences[m]
        lines.append(f"### {m}")
        for ev in e.evidence[:20]:
            lines.append(f"- {ev}")
        lines.append("")

    lines.append("## Taxonomy reference")
    lines.append("(Full taxonomy tree included for convenience.)")
    lines.append("")
    lines.append(taxonomy_to_markdown())

    (out_dir / "MODULES.md").write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True, help="Path to the repository (or subdir) to scan")
    ap.add_argument("--out", required=True, help="Output directory for analysis artifacts")
    ap.add_argument("--exclude", nargs="*", default=[], help="Extra directory names to exclude")
    ap.add_argument("--max-files", type=int, default=DEFAULT_MAX_FILES, help="Maximum files to scan")
    ap.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES, help="Maximum bytes to read per file")
    ap.add_argument("--min-file-score", type=int, default=DEFAULT_MIN_FILE_SCORE, help="Minimum file count to keep a module")
    ap.add_argument("--group-depth", type=int, default=DEFAULT_GROUP_DEPTH, help="Directory depth for grouping files")
    ap.add_argument("--group-sample-files", type=int, default=DEFAULT_GROUP_SAMPLE_FILES, help="Sample paths per group")
    ap.add_argument("--group-snippets", type=int, default=DEFAULT_GROUP_SNIPPETS, help="Snippets per group")
    ap.add_argument("--snippet-bytes", type=int, default=DEFAULT_SNIPPET_BYTES, help="Max bytes per snippet")
    ap.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE, help="Groups per LLM call")
    ap.add_argument("--llm-provider", default="deepseek", help="LLM provider (openai, deepseek, lab, mock)")
    ap.add_argument("--llm-model", default="", help="LLM model name (optional)")
    ap.add_argument("--require-llm", action="store_true", help="Fail if LLM is unavailable or returns invalid JSON")
    ap.add_argument("--file-list", default=None, help="Optional JSON file with relative paths to include in module mapping")
    args = ap.parse_args()

    repo = Path(args.repo).expanduser().resolve()
    if not repo.exists() or not repo.is_dir():
        raise SystemExit(f"repo path not found or not a directory: {repo}")
    if args.batch_size < 1:
        raise SystemExit("batch-size must be >= 1")
    if args.group_depth < 1:
        raise SystemExit("group-depth must be >= 1")
    if args.snippet_bytes < 1:
        raise SystemExit("snippet-bytes must be >= 1")

    if not _ensure_llm_import():
        raise SystemExit("LLM client is unavailable. Install dependencies or use the editable install.")

    out_dir = Path(args.out).expanduser().resolve()
    exclude_dirs = set(DEFAULT_EXCLUDE_DIRS) | set(args.exclude)

    file_list = None
    if args.file_list:
        file_list_path = Path(args.file_list).expanduser().resolve()
        if file_list_path.exists():
            file_list = json.loads(file_list_path.read_text(encoding="utf-8"))
            if not isinstance(file_list, list):
                raise SystemExit(f"file-list must be a JSON list: {file_list_path}")

    llm_config = LLMConfig(provider=args.llm_provider, model=args.llm_model)
    llm_client = create_llm_client(llm_config)

    signals, evidences, file_index = scan(
        repo,
        exclude_dirs,
        max_files=args.max_files,
        max_bytes=args.max_bytes,
        min_file_score=args.min_file_score,
        group_depth=args.group_depth,
        group_sample_files=args.group_sample_files,
        group_snippets=args.group_snippets,
        snippet_bytes=args.snippet_bytes,
        batch_size=args.batch_size,
        llm_client=llm_client,
        require_llm=args.require_llm,
        file_list=file_list,
    )
    write_outputs(out_dir, signals, evidences, file_index, min_file_score=args.min_file_score)
    print(f"Wrote: {out_dir / 'module_map.json'}")
    print(f"Wrote: {out_dir / 'MODULES.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
