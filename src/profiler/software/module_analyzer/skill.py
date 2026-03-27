"""Skill-based module analyzer for AI infra repositories.

Delegates classification to .claude/skills/ai-infra-module-modeler scripts and
adapts their outputs into the software profiler module schema.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from config import _path_config
from utils.claude_cli import (
    DEFAULT_SELECTED_MODEL_HINT,
    apply_claude_cli_usage_counters,
    run_claude_cli,
)
from utils.logger import get_logger
from profiler.software.module_analyzer.taxonomy_loader import load_ai_infra_taxonomy

logger = get_logger(__name__)

VALID_MODULE_CONFIDENCE_VALUES = frozenset({"high", "medium", "low"})


class SkillModuleAnalyzer:
    """Analyze repository modules using .claude/skills outputs."""

    def __init__(
        self,
        llm_client: Any = None,
        excluded_folders: Optional[List[str]] = None,
        code_extensions: Optional[List[str]] = None,
        max_key_functions: int = 12,
        validation_mode: bool = False,
        validation_temperature: float = 0.0,
        validation_max_workers: int = 1,
    ):
        self.llm_client = llm_client
        self.excluded_folders = excluded_folders or []
        self.code_extensions = set(ext.lower() for ext in (code_extensions or []))
        self.max_key_functions = max_key_functions
        self.validation_mode = bool(validation_mode)
        self.validation_temperature = float(validation_temperature)
        self.validation_max_workers = max(1, int(validation_max_workers))

        self.skill_root = self._resolve_skill_root()
        self.taxonomy = self._load_taxonomy()
        self._last_llm_usage: Dict[str, Any] = {}
        self._last_claude_cli_record_path: Optional[str] = None
        self._last_module_analysis_mode = "claude_cli"

    @staticmethod
    def _count_claude_attempts(response: Any) -> int:
        """Count only attempts that could have reached a real Claude session."""
        if response is None:
            return 0

        usage_summary = getattr(response, "usage_summary", None)
        if isinstance(usage_summary, dict) and (
            usage_summary.get("session_usage")
            or usage_summary.get("top_level_usage")
            or usage_summary.get("selected_model_usage")
        ):
            return 1
        if getattr(response, "timed_out", False):
            return 1
        if getattr(response, "returncode", None) == 0:
            return 1
        return 0

    def analyze(
        self,
        repo_info: Dict[str, Any],
        repo_path: Path,
        storage_manager: Any = None,
        repo_name: Optional[str] = None,
        version: Optional[str] = None,
        force_regenerate: bool = False,
    ) -> Dict[str, Any]:
        repo_path = Path(repo_path).resolve()
        if not self.taxonomy:
            logger.warning("Taxonomy not available; returning empty module list.")
            return {"modules": [], "llm_calls": 0, "analysis_completed": False}

        output_dir = self._resolve_output_dir(storage_manager, repo_name, version)
        if force_regenerate:
            self._reset_output_dir(output_dir)
        success, llm_usage, record_path, analysis_mode = self._run_module_analysis(
            repo_info,
            repo_path,
            output_dir,
            repo_name,
        )
        if not success:
            return {
                "modules": [],
                "llm_calls": self._infer_llm_call_count(llm_usage),
                "llm_usage": llm_usage,
                "claude_cli_record_path": str(record_path) if record_path else None,
                "module_analysis_record_path": str(record_path) if record_path else None,
                "module_analysis_mode": analysis_mode,
                "analysis_completed": False,
            }

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
            "llm_calls": self._infer_llm_call_count(llm_usage),
            "llm_usage": llm_usage,
            "claude_cli_record_path": str(record_path) if record_path else None,
            "module_analysis_record_path": str(record_path) if record_path else None,
            "module_analysis_mode": analysis_mode,
            "taxonomy": "ai_infra_taxonomy_v1",
            "module_map": module_map,
            "file_index": filtered_index,
            "analysis_completed": True,
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

        skill_root = _path_config['skill_path'] / "ai-infra-module-modeler"
        return skill_root if skill_root.exists() else None

    def _load_taxonomy(self) -> Dict[str, Any]:
        return load_ai_infra_taxonomy(self.skill_root)

    def _resolve_scan_script_path(self) -> Optional[Path]:
        """Locate the standalone module-analysis script used by validation mode."""
        if not self.skill_root:
            return None
        script_path = self.skill_root / "scripts" / "scan_repo.py"
        return script_path if script_path.exists() else None

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

    def _run_module_analysis(
        self,
        repo_info: Dict[str, Any],
        repo_path: Path,
        output_dir: Path,
        repo_name: Optional[str],
    ) -> Tuple[bool, Dict[str, Any], Path, str]:
        """Run module analysis with the configured execution mode."""
        if self.validation_mode:
            success, llm_usage, record_path = self._run_validation_script_analysis(
                repo_info,
                repo_path,
                output_dir,
                repo_name,
            )
            self._last_module_analysis_mode = "validation_script"
            return success, llm_usage, record_path, "validation_script"

        success, llm_usage, record_path = self._run_claude_analysis(
            repo_path,
            output_dir,
            repo_name,
        )
        self._last_module_analysis_mode = "claude_cli"
        return success, llm_usage, record_path, "claude_cli"

    def _write_module_analysis_record(self, record_path: Path, payload: Dict[str, Any]) -> None:
        """Persist a small invocation record for reproducibility and debugging."""
        try:
            record_path.parent.mkdir(parents=True, exist_ok=True)
            record_path.write_text(
                json.dumps(payload, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        except Exception as exc:  # pylint: disable=broad-except
            logger.warning("Failed to persist module-analysis record %s: %s", record_path, exc)

    def _run_validation_script_analysis(
        self,
        repo_info: Dict[str, Any],
        repo_path: Path,
        output_dir: Path,
        repo_name: Optional[str],
    ) -> Tuple[bool, Dict[str, Any], Path]:
        """Run the standalone scan script with pinned settings for validation runs."""
        output_dir.mkdir(parents=True, exist_ok=True)
        record_path = output_dir / "module_analysis_invocation.json"
        script_path = self._resolve_scan_script_path()
        llm_config = getattr(getattr(self, "llm_client", None), "config", None)
        provider = str(getattr(llm_config, "provider", "") or "").strip()
        model = str(getattr(llm_config, "model", "") or "").strip()

        if not script_path:
            self._write_module_analysis_record(
                record_path,
                {
                    "analysis_mode": "validation_script",
                    "started_at": datetime.now(UTC).isoformat(),
                    "finished_at": datetime.now(UTC).isoformat(),
                    "command": [],
                    "cwd": str(_path_config["repo_root"]),
                    "returncode": None,
                    "stdout": "",
                    "stderr": "scan_repo.py not found",
                },
            )
            logger.warning("Validation module analyzer script not found")
            return False, {}, record_path

        command = [
            sys.executable,
            str(script_path),
            "--repo",
            str(repo_path),
            "--out",
            str(output_dir),
            "--analysis-mode",
            "validation_script",
            "--llm-temperature",
            str(self.validation_temperature),
            "--max-workers",
            str(self.validation_max_workers),
            "--require-llm",
        ]
        validation_file_list_path = output_dir / "validation_file_list.json"
        validation_file_list = self._build_validation_file_list(repo_info)
        validation_file_list_path.write_text(
            json.dumps(validation_file_list, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        command.extend(["--file-list", str(validation_file_list_path)])
        if self.excluded_folders:
            command.extend(["--exclude", *self.excluded_folders])
        if provider:
            command.extend(["--llm-provider", provider])
        if model:
            command.extend(["--llm-model", model])

        started_at = datetime.now(UTC).isoformat()
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            cwd=str(_path_config["repo_root"]),
        )
        finished_at = datetime.now(UTC).isoformat()

        signals_path = output_dir / "signals.json"
        module_map_path = output_dir / "module_map.json"
        file_index_path = output_dir / "file_index.json"
        module_profile_path = output_dir / "module_profile.json"
        signals_payload = self._load_json(signals_path) or {}
        llm_usage = signals_payload.get("llm_usage_summary", {}) if isinstance(signals_payload, dict) else {}
        llm_usage = dict(llm_usage) if isinstance(llm_usage, dict) else {}
        if not llm_usage.get("source"):
            llm_usage["source"] = "llm_client"
        if provider and not llm_usage.get("provider"):
            llm_usage["provider"] = provider
        if model and not llm_usage.get("requested_model"):
            llm_usage["requested_model"] = model

        self._write_module_analysis_record(
            record_path,
            {
                "analysis_mode": "validation_script",
                "repo_name": repo_name,
                "repo_path": str(repo_path),
                "output_dir": str(output_dir),
                "started_at": started_at,
                "finished_at": finished_at,
                "command": command,
                "cwd": str(_path_config["repo_root"]),
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "signals_path": str(signals_path),
                "module_map_path": str(module_map_path),
                "file_index_path": str(file_index_path),
                "module_profile_path": str(module_profile_path),
            },
        )

        required_outputs = [signals_path, module_map_path, file_index_path, module_profile_path]
        outputs_ready = all(path.exists() for path in required_outputs)
        self._last_llm_usage = llm_usage
        self._last_claude_cli_record_path = str(record_path)

        if result.returncode == 0 and outputs_ready:
            logger.info("Validation module analysis completed: %s", result.stdout[:500])
            return True, llm_usage, record_path

        if result.returncode == 0 and not outputs_ready:
            logger.warning("Validation module analysis finished but required outputs are missing")
        elif result.stderr:
            logger.warning("Validation module analysis failed: %s", result.stderr[:500])
        else:
            logger.warning("Validation module analysis failed without stderr output")
        return False, llm_usage, record_path

    def _run_claude_analysis(
        self,
        repo_path: Path,
        output_dir: Path,
        repo_name: Optional[str],
    ) -> Tuple[bool, Dict[str, Any], Path]:
        """Run Claude CLI to analyze repository module structure."""
        output_dir.mkdir(parents=True, exist_ok=True)
        record_path = output_dir / "claude_cli_invocation.json"
        
        prompt = (
            f'Use the `ai-infra-module-modeler` skill to analyze the module structure of '
            f'{repo_path} and write outputs to the folder {output_dir.resolve()}'
        )
        if repo_name:
            logger.info(f"Running Claude analysis for {repo_name} with prompt: {prompt}")
        else:
            logger.info(f"Running Claude analysis with prompt: {prompt}")

        response = run_claude_cli(
            prompt=prompt,
            cwd=str(_path_config['repo_root']),
            record_path=record_path,
            preferred_model_hint=DEFAULT_SELECTED_MODEL_HINT,
            allow_plain_text_fallback=True,
        )
        if response.fallback_from_json_output:
            logger.warning(
                "Claude CLI appears to lack --output-format json support; module analysis retried in text mode"
            )
        llm_usage = apply_claude_cli_usage_counters(response.usage_summary, response)
        # Module-analysis llm_usage tracks real model calls, not local CLI
        # retries such as the unsupported --output-format probe.
        llm_usage["sessions_total"] = self._count_claude_attempts(response)
        llm_usage["calls_total"] = llm_usage["sessions_total"]
        self._last_llm_usage = llm_usage
        self._last_claude_cli_record_path = str(record_path)
        required_outputs = [
            output_dir / "module_map.json",
            output_dir / "file_index.json",
            output_dir / "module_profile.json",
        ]
        outputs_ready = all(path.exists() for path in required_outputs)

        if response.returncode == 0 and outputs_ready:
            result_text = ""
            if response.parsed_output:
                result_text = str(response.parsed_output.get("result", "")).strip()
            elif response.stdout:
                result_text = response.stdout.strip()
            if response.parse_error:
                logger.warning(
                    "Claude analysis stdout was not JSON; continuing because module artifacts are file-based"
                )
            logger.info(f"Claude analysis completed: {result_text[:500]}")
            return True, llm_usage, record_path
        if response.returncode == 0 and not outputs_ready:
            logger.warning("Claude analysis finished but required outputs are missing")
            return False, llm_usage, record_path

        if response.error_type == "FileNotFoundError":
            logger.error("Claude CLI not found. Please install it first.")
        elif response.timed_out:
            logger.warning("Claude analysis timed out")
        elif response.stderr:
            logger.warning(f"Claude analysis failed: {response.stderr[:500]}")
        elif response.parse_error:
            logger.warning(f"Claude analysis returned invalid JSON: {response.parse_error}")
        else:
            logger.warning("Claude analysis failed without stderr output")
        return False, llm_usage, record_path

    @staticmethod
    def _infer_llm_call_count(llm_usage: Optional[Dict[str, Any]]) -> int:
        if not isinstance(llm_usage, dict):
            return 0
        if "sessions_total" in llm_usage:
            return int(llm_usage.get("sessions_total", 0) or 0)
        if "calls_total" in llm_usage:
            return int(llm_usage.get("calls_total", 0) or 0)
        if llm_usage.get("session_usage") or llm_usage.get("selected_model_usage") or llm_usage.get("top_level_usage"):
            return 1
        return 0

    def _reset_output_dir(self, output_dir: Path) -> None:
        """Remove persisted skill outputs so a force-regenerated run starts clean."""
        if output_dir.exists():
            shutil.rmtree(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

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
        if self._modules_follow_task6_contract(modules):
            return self._normalize_modules(modules, file_index, repo_info), file_index
        if modules:
            logger.warning(
                "Ignoring persisted module_profile modules that do not satisfy the Task 6 contract; "
                "falling back to module_map/file_index synthesis"
            )

        code_files = [
            f for f in repo_info.get("files", [])
            if self._is_included_code_path(f)
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
                "responsibility": description,
                "entry_points": [],
                "key_functions": [],
                "interfaces": [],
                "depends_on": [],
                "dependencies": [],
                "boundary_rationale": "Grouped by inferred taxonomy ownership and observed file locality.",
                "evidence_paths": sorted(files),
                "confidence": "medium",
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

    def _modules_follow_task6_contract(self, modules: List[Dict[str, Any]]) -> bool:
        required_fields = (
            "name",
            "category",
            "description",
            "responsibility",
            "entry_points",
            "files",
            "key_functions",
            "interfaces",
            "depends_on",
            "dependencies",
            "boundary_rationale",
            "evidence_paths",
            "confidence",
        )
        list_fields = (
            "entry_points",
            "files",
            "key_functions",
            "interfaces",
            "depends_on",
            "dependencies",
            "evidence_paths",
        )
        string_fields = (
            "name",
            "category",
            "description",
            "responsibility",
            "boundary_rationale",
            "confidence",
        )

        if not isinstance(modules, list) or not modules:
            return False

        for module in modules:
            if not isinstance(module, dict):
                return False
            if any(field not in module for field in required_fields):
                return False

            for field in string_fields:
                value = module.get(field)
                if not isinstance(value, str) or not value.strip():
                    return False

            for field in list_fields:
                value = module.get(field)
                if not isinstance(value, list):
                    return False
                if any(not isinstance(item, str) or not item.strip() for item in value):
                    return False

            if module.get("confidence") not in VALID_MODULE_CONFIDENCE_VALUES:
                return False
            if module.get("depends_on") != module.get("dependencies"):
                return False

        return True

    def _normalize_modules(
        self,
        modules: List[Dict[str, Any]],
        file_index: Dict[str, str],
        repo_info: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        code_files = [
            f for f in repo_info.get("files", [])
            if self._is_included_code_path(f)
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
            depends_on = module.get("depends_on", [])
            if not isinstance(depends_on, list):
                depends_on = []
            dependencies = module.get("dependencies", [])
            if not isinstance(dependencies, list):
                dependencies = []
            if not depends_on and dependencies:
                depends_on = list(dependencies)
            if not dependencies and depends_on:
                dependencies = list(depends_on)
            files = [
                file_path
                for file_path in (module.get("files") or files_by_module.get(name, []))
                if self._is_included_code_path(file_path)
            ]
            normalized.append({
                "name": name,
                "category": module.get("category") or category,
                "description": module.get("description", ""),
                "responsibility": module.get("responsibility", module.get("description", "")),
                "entry_points": module.get("entry_points", []),
                "key_functions": module.get("key_functions", []),
                "interfaces": module.get("interfaces", []),
                "depends_on": depends_on,
                "dependencies": dependencies,
                "boundary_rationale": module.get("boundary_rationale", ""),
                "evidence_paths": module.get("evidence_paths", []),
                "confidence": module.get("confidence", "unknown"),
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
        """
        TODO: Improve description generation using LLMs in the future.
        """
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

    def _is_included_code_path(self, rel_path: str) -> bool:
        """Apply configured folder and extension filters to a relative path."""
        normalized_path = str(rel_path or "").replace("\\", "/").strip()
        if not normalized_path or self._is_excluded_path(normalized_path):
            return False
        if not self.code_extensions:
            return True
        return Path(normalized_path).suffix.lower() in self.code_extensions

    def _build_validation_file_list(self, repo_info: Dict[str, Any]) -> List[str]:
        """Build the exact validation scan scope from the configured filters."""
        validation_files = [
            str(file_path).replace("\\", "/")
            for file_path in repo_info.get("files", [])
            if self._is_included_code_path(str(file_path))
        ]
        return sorted(set(validation_files))

    def _matches_excluded(self, name: str) -> bool:
        for pattern in self.excluded_folders:
            if Path(name).match(pattern):
                return True
        return False

    # === Repo analysis integration ===
    # Uses RepoAnalyzer outputs to attach key functions and module dependencies.
    def _attach_key_functions_and_dependencies(
        self,
        modules: List[Dict[str, Any]],
        repo_info: Dict[str, Any],
        repo_path: Path,
    ) -> List[Dict[str, Any]]:
        repo_analysis = repo_info.get("repo_analysis") or {}
        functions = repo_analysis.get("functions", [])
        call_edges = repo_analysis.get("call_graph_edges", [])
        if not functions and not call_edges:
            return modules

        file_to_module = {}
        basename_to_files = {}
        for module in modules:
            module_name = module.get("name", "")
            for file_path in module.get("files"):
                file_to_module[file_path] = module_name
                basename = Path(file_path).name
                basename_to_files.setdefault(basename, []).append(file_path)

        module_functions: Dict[str, List[str]] = {}
        for func in functions:
            file_path = self._normalize_file_path(func.get("file", ""), repo_path)
            file_path = self._resolve_file_path(file_path, file_to_module, basename_to_files)
            if not file_path:
                continue
            module_name = file_to_module.get(file_path)
            if not module_name:
                continue
            name = func.get("name", "")
            if not name or name == "<module>":
                continue
            module_functions.setdefault(module_name, []).append(name)

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
            funcs = module_functions.get(module_name, [])
            ordered = _unique_preserve_order(funcs)
            module["key_functions"] = ordered[: self.max_key_functions]
            deps = sorted(module_dependencies.get(module_name, []))
            module["dependencies"] = deps
            module["depends_on"] = list(deps)

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
