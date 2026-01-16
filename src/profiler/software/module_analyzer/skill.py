"""Skill-based module analyzer for AI infra repositories.

Delegates classification to .claude/skills/ai-infra-module-modeler scripts and
adapts their outputs into the software profiler module schema.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from utils.logger import get_logger

logger = get_logger(__name__)


class SkillModuleAnalyzer:
    """Analyze repository modules using .claude/skills outputs."""

    def __init__(
        self,
        llm_client: Any = None,
        excluded_folders: Optional[List[str]] = None,
        code_extensions: Optional[List[str]] = None,
        max_files: int = 2000,
        max_file_bytes: int = 200_000,
        min_file_score: int = 2,
        max_key_functions: int = 12,
        llm_provider: Optional[str] = None,
        llm_model: Optional[str] = None,
        group_depth: int = 2,
        group_sample_files: int = 12,
        group_snippets: int = 2,
        snippet_bytes: int = 800,
        batch_size: int = 12,
        require_llm: bool = False,
    ):
        self.llm_client = llm_client
        self.excluded_folders = excluded_folders or []
        self.code_extensions = set(ext.lower() for ext in (code_extensions or []))
        self.max_files = max_files
        self.max_file_bytes = max_file_bytes
        self.min_file_score = min_file_score
        self.max_key_functions = max_key_functions
        self.llm_provider = llm_provider or getattr(getattr(llm_client, "config", None), "provider", "")
        self.llm_model = llm_model or getattr(getattr(llm_client, "config", None), "model", "")
        self.group_depth = group_depth
        self.group_sample_files = group_sample_files
        self.group_snippets = group_snippets
        self.snippet_bytes = snippet_bytes
        self.batch_size = batch_size
        self.require_llm = require_llm

        self.skill_root = self._resolve_skill_root()
        self.scan_script = self._resolve_scan_script()
        self.taxonomy = self._load_taxonomy()

    def analyze(
        self,
        repo_info: Dict[str, Any],
        repo_path: Path,
        storage_manager: Any = None,
        repo_name: Optional[str] = None,
        version: Optional[str] = None,
    ) -> Dict[str, Any]:
        repo_path = Path(repo_path).resolve()
        if not self.scan_script or not self.taxonomy:
            logger.warning("Skill assets not available; returning empty module list.")
            return {"modules": [], "llm_calls": 0}

        output_dir = self._resolve_output_dir(storage_manager, repo_name, version)
        if not self._run_scan(repo_path, output_dir, repo_info):
            return {"modules": [], "llm_calls": 0}

        module_map = self._load_json(output_dir / "module_map.json") or {}
        file_index = self._load_json(output_dir / "file_index.json") or {}
        module_profile = self._load_json(output_dir / "module_profile.json") or {}

        modules, filtered_index = self._build_modules(module_profile, module_map, file_index, repo_info)
        modules = self._attach_key_functions_and_dependencies(modules, repo_info, repo_path)

        if module_map:
            module_map["selected_modules"] = sorted(
                {m.get("category", "") for m in modules if m.get("category")}
            )

        result = {
            "modules": modules,
            "llm_calls": 0,
            "taxonomy": "ai_infra_taxonomy_v1",
            "module_map": module_map,
            "file_index": filtered_index,
        }

        if storage_manager and repo_name:
            path_parts = (repo_name, version) if version else (repo_name,)
            try:
                storage_manager.save_checkpoint("skill_module_map", module_map, *path_parts)
                storage_manager.save_checkpoint("skill_file_index", filtered_index, *path_parts)
            except Exception as exc:  # pylint: disable=broad-except
                logger.warning(f"Failed to save skill module artifacts: {exc}")

        return result

    def _resolve_skill_root(self) -> Optional[Path]:
        try:
            project_root = Path(__file__).resolve().parents[4]
        except IndexError:
            return None
        skill_root = project_root / ".claude" / "skills" / "ai-infra-module-modeler"
        return skill_root if skill_root.exists() else None

    def _resolve_scan_script(self) -> Optional[Path]:
        if not self.skill_root:
            return None
        script = self.skill_root / "scripts" / "scan_repo.py"
        return script if script.exists() else None

    def _load_taxonomy(self) -> Dict[str, Any]:
        if not self.skill_root:
            return {}
        scripts_dir = self.skill_root / "scripts"
        sys.path.insert(0, str(scripts_dir))
        try:
            taxonomy_mod = __import__("ai_infra_taxonomy")
            return getattr(taxonomy_mod, "AI_INFRA_TAXONOMY", {})
        except Exception as exc:  # pylint: disable=broad-except
            logger.warning(f"Failed to import ai_infra_taxonomy: {exc}")
            return {}
        finally:
            if sys.path and sys.path[0] == str(scripts_dir):
                sys.path.pop(0)

    def _resolve_output_dir(
        self,
        storage_manager: Any,
        repo_name: Optional[str],
        version: Optional[str],
    ) -> Path:
        if storage_manager and repo_name:
            path_parts = (repo_name, version) if version else (repo_name,)
            checkpoint_dir = storage_manager.get_checkpoint_dir(*path_parts)
            if checkpoint_dir:
                out_dir = checkpoint_dir / "skill_module_modeler"
                out_dir.mkdir(parents=True, exist_ok=True)
                return out_dir
        return Path(tempfile.mkdtemp(prefix="skill_module_modeler_"))

    def _run_scan(self, repo_path: Path, output_dir: Path, repo_info: Dict[str, Any]) -> bool:
        if not self.scan_script:
            return False

        file_list_path = None
        file_list = repo_info.get("files", [])
        if file_list:
            file_list_path = output_dir / "file_list.json"
            file_list_path.write_text(json.dumps(file_list, ensure_ascii=False, indent=2), encoding="utf-8")

        cmd = [
            sys.executable,
            str(self.scan_script),
            "--repo",
            str(repo_path),
            "--out",
            str(output_dir),
            "--max-files",
            str(self.max_files),
            "--max-bytes",
            str(self.max_file_bytes),
            "--min-file-score",
            str(self.min_file_score),
            "--group-depth",
            str(self.group_depth),
            "--group-sample-files",
            str(self.group_sample_files),
            "--group-snippets",
            str(self.group_snippets),
            "--snippet-bytes",
            str(self.snippet_bytes),
            "--batch-size",
            str(self.batch_size),
        ]
        if self.llm_provider:
            cmd.extend(["--llm-provider", str(self.llm_provider)])
        if self.llm_model:
            cmd.extend(["--llm-model", str(self.llm_model)])
        if self.require_llm:
            cmd.append("--require-llm")
        if file_list_path:
            cmd.extend(["--file-list", str(file_list_path)])
        if self.excluded_folders:
            cmd.append("--exclude")
            cmd.extend(self.excluded_folders)

        try:
            subprocess.run(cmd, check=True, capture_output=True)
            logger.info("Skill scan completed")
            return True
        except subprocess.CalledProcessError as exc:
            logger.warning(f"Skill scan failed: {exc}")
            return False

    def _load_json(self, path: Path) -> Optional[Dict[str, Any]]:
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:  # pylint: disable=broad-except
            logger.warning(f"Failed to read {path}: {exc}")
            return None

    def _build_modules(
        self,
        module_profile: Dict[str, Any],
        module_map: Dict[str, Any],
        file_index: Dict[str, str],
        repo_info: Dict[str, Any],
    ) -> Tuple[List[Dict[str, Any]], Dict[str, str]]:
        modules = self._extract_modules(module_profile)
        if modules:
            return self._normalize_modules(modules, file_index, repo_info), file_index

        code_files = [
            f for f in repo_info.get("files", [])
            if not self._is_excluded_path(f)
        ]

        module_scores = self._module_scores(module_map)
        default_coarse = self._pick_default_module(module_scores)
        default_fine = self._default_fine_module(default_coarse)
        default_module_name = self._module_name(default_coarse, default_fine)

        module_to_files: Dict[Tuple[str, str], List[str]] = {}
        filtered_index: Dict[str, str] = {}

        for file_path in code_files:
            module_name = file_index.get(file_path)
            if not module_name:
                module_name = self._lookup_file_index(file_path, file_index)
            if not module_name:
                module_name = default_module_name

            coarse, fine = self._split_module_name(module_name)
            module_to_files.setdefault((coarse, fine), []).append(file_path)
            filtered_index[file_path] = self._module_name(coarse, fine)

        selected = module_map.get("selected_modules", [])
        module_evidence = module_map.get("modules", {})
        config_files = [
            cfg.get("name")
            for cfg in repo_info.get("config_files", [])
            if isinstance(cfg, dict) and cfg.get("name")
        ]
        for coarse in selected:
            fine = self._default_fine_module(coarse)
            key = (coarse, fine)
            if key in module_to_files:
                continue
            evidence_paths = self._evidence_paths(module_evidence.get(coarse, {}).get("evidence", []))
            fallback_paths = evidence_paths or config_files
            if fallback_paths:
                module_to_files[key] = sorted(set(fallback_paths))

        modules = []
        for (coarse, fine), files in sorted(module_to_files.items()):
            name = self._module_name(coarse, fine)
            description = self._describe_module(coarse, fine, files)
            module = {
                "name": name,
                "category": coarse,
                "description": description,
                "paths": sorted(files),
                "key_functions": [],
                "dependencies": [],
                "files": sorted(files),
            }
            modules.append(module)

        return modules, filtered_index

    def _extract_modules(self, module_profile: Dict[str, Any]) -> List[Dict[str, Any]]:
        if isinstance(module_profile, list):
            return module_profile
        if isinstance(module_profile, dict):
            modules = module_profile.get("modules", [])
            if isinstance(modules, list):
                return modules
        return []

    def _normalize_modules(
        self,
        modules: List[Dict[str, Any]],
        file_index: Dict[str, str],
        repo_info: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        code_files = [
            f for f in repo_info.get("files", [])
            if not self._is_excluded_path(f)
        ]
        files_by_module: Dict[str, List[str]] = {}
        for rel_path in code_files:
            module_name = file_index.get(rel_path)
            if module_name:
                files_by_module.setdefault(module_name, []).append(rel_path)

        normalized = []
        for module in modules:
            name = module.get("name", "")
            category, _ = self._split_module_name(name)
            files = module.get("paths") or module.get("files") or files_by_module.get(name, [])
            normalized.append({
                "name": name,
                "category": module.get("category") or category,
                "description": module.get("description", ""),
                "paths": sorted(set(files)),
                "key_functions": module.get("key_functions", []),
                "dependencies": module.get("dependencies", []),
                "files": sorted(set(files)),
            })
        return normalized

    def _module_scores(self, module_map: Dict[str, Any]) -> Dict[str, int]:
        scores: Dict[str, int] = {}
        for name, payload in (module_map.get("modules") or {}).items():
            if isinstance(payload, dict):
                scores[name] = int(payload.get("score", 0))
        return scores

    def _pick_default_module(self, module_scores: Dict[str, int]) -> str:
        if module_scores:
            return max(module_scores, key=module_scores.get)
        return "platform_systems"

    def _default_fine_module(self, coarse: str) -> str:
        fine_candidates = list((self.taxonomy.get(coarse) or {}).keys())
        return fine_candidates[0] if fine_candidates else coarse

    def _module_name(self, coarse: str, fine: str) -> str:
        if not fine or fine == coarse:
            return coarse
        return f"{coarse}.{fine}"

    def _split_module_name(self, module_name: str) -> Tuple[str, str]:
        if "." in module_name:
            coarse, fine = module_name.split(".", 1)
            if not fine:
                fine = self._default_fine_module(coarse)
            return coarse, fine
        coarse = module_name
        fine = self._default_fine_module(coarse)
        return coarse, fine

    def _lookup_file_index(self, file_path: str, file_index: Dict[str, str]) -> Optional[str]:
        if not file_index:
            return None
        basename = Path(file_path).name
        for rel_path, module_name in file_index.items():
            if Path(rel_path).name == basename:
                return module_name
        return None

    def _evidence_paths(self, evidence: List[str]) -> List[str]:
        paths = []
        for item in evidence:
            if item.startswith("path:"):
                paths.append(item[len("path:"):].strip())
        return paths

    def _describe_module(self, coarse: str, fine: str, files: List[str]) -> str:
        coarse_label = coarse.replace("_", " ").title()
        fine_label = fine.replace("_", " ").title()
        description = f"{fine_label} responsibilities within {coarse_label}."
        top_dirs = self._top_dirs_from_files(files)
        if top_dirs:
            description += f" Key areas: {', '.join(top_dirs)}."
        return description

    def _top_dirs_from_files(self, files: List[str]) -> List[str]:
        counts: Dict[str, int] = {}
        for path in files:
            parts = path.split("/")
            if not parts:
                continue
            top = parts[0]
            counts[top] = counts.get(top, 0) + 1
        top_dirs = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:3]
        return [name for name, _ in top_dirs]

    def _is_excluded_path(self, rel_path: str) -> bool:
        parts = rel_path.replace("\\", "/").split("/")
        for part in parts:
            if self._matches_excluded(part):
                return True
        return False

    def _matches_excluded(self, name: str) -> bool:
        for pattern in self.excluded_folders:
            if Path(name).match(pattern):
                return True
        return False

    # === Deep analysis integration ===
    # Uses RepoAnalyzer outputs to attach key functions and module dependencies.
    def _attach_key_functions_and_dependencies(
        self,
        modules: List[Dict[str, Any]],
        repo_info: Dict[str, Any],
        repo_path: Path,
    ) -> List[Dict[str, Any]]:
        deep_analysis = repo_info.get("deep_analysis") or {}
        functions = deep_analysis.get("functions", [])
        call_edges = deep_analysis.get("call_graph_edges", [])
        if not functions and not call_edges:
            return modules

        file_to_module = {}
        basename_to_files = {}
        for module in modules:
            module_name = module.get("name", "")
            for file_path in module.get("paths", []):
                file_to_module[file_path] = module_name
                basename = Path(file_path).name
                basename_to_files.setdefault(basename, []).append(file_path)

        module_functions: Dict[str, Dict[str, List[str]]] = {}
        for func in functions:
            file_path = self._normalize_file_path(func.get("file", ""), repo_path)
            file_path = self._resolve_file_path(file_path, file_to_module, basename_to_files)
            if not file_path:
                continue
            module_name = file_to_module.get(file_path)
            if not module_name:
                continue
            name = func.get("name", "")
            if not name:
                continue
            bucket = module_functions.setdefault(module_name, {"entry": [], "other": []})
            if func.get("is_entry_point"):
                bucket["entry"].append(name)
            else:
                bucket["other"].append(name)

        module_dependencies: Dict[str, set] = {}
        for edge in call_edges:
            caller_file = self._normalize_file_path(edge.get("caller_file", ""), repo_path)
            callee_file = self._normalize_file_path(edge.get("callee_file", ""), repo_path)
            caller_file = self._resolve_file_path(caller_file, file_to_module, basename_to_files)
            callee_file = self._resolve_file_path(callee_file, file_to_module, basename_to_files)
            if not caller_file or not callee_file:
                continue
            caller_module = file_to_module.get(caller_file)
            callee_module = file_to_module.get(callee_file)
            if not caller_module or not callee_module or caller_module == callee_module:
                continue
            module_dependencies.setdefault(caller_module, set()).add(callee_module)

        for module in modules:
            module_name = module.get("name", "")
            funcs = module_functions.get(module_name, {})
            ordered = _unique_preserve_order(funcs.get("entry", []) + funcs.get("other", []))
            module["key_functions"] = ordered[: self.max_key_functions]
            deps = sorted(module_dependencies.get(module_name, []))
            module["dependencies"] = deps

        return modules

    def _normalize_file_path(self, file_path: str, repo_path: Path) -> str:
        if not file_path:
            return ""
        path = Path(file_path)
        if path.is_absolute():
            try:
                path = path.relative_to(repo_path)
            except ValueError:
                return path.name
        return str(path).replace("\\", "/")

    def _resolve_file_path(
        self,
        file_path: str,
        file_to_module: Dict[str, str],
        basename_to_files: Dict[str, List[str]],
    ) -> str:
        if not file_path:
            return ""
        if file_path in file_to_module:
            return file_path
        basename = Path(file_path).name
        candidates = basename_to_files.get(basename, [])
        if len(candidates) == 1:
            return candidates[0]
        for candidate in candidates:
            if candidate.endswith(file_path):
                return candidate
        return ""


def _unique_preserve_order(items: List[str]) -> List[str]:
    seen = set()
    ordered = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            ordered.append(item)
    return ordered
