"""Agent scan memory for tracking progress and enabling resume."""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from utils.logger import get_logger
from utils.io_utils import write_atomic_text
from .schedule_window import FROZEN_SCHEDULE_PAGE_SIZE

logger = get_logger(__name__)


@dataclass
class ScanMemory:
    """Lightweight scan memory supporting resume and progress tracking."""
    
    # Scan metadata
    target_repo: str = ""
    target_commit: str = ""
    cve_id: str = ""
    started_at: str = ""
    critical_stop_max_priority: int = 2
    
    # File status: {file_path: "pending"|"completed"|"skipped"}
    file_status: Dict[str, str] = field(default_factory=dict)
    
    # File completion reasons: {file_path: reason}
    file_completion_reasons: Dict[str, str] = field(default_factory=dict)

    # 跨续跑记录首次成功且带路径的工具结果顺序。
    # 显式完成也算首次触达；页面展示单独记录，不计入触达任务 ledger。
    coverage_first_touches: List[str] = field(default_factory=list)

    # 有界 schedule 窗口的跨续跑主机控制证据。
    schedule_presented_page_indices: List[int] = field(default_factory=list)
    schedule_window_events: List[Dict[str, Any]] = field(default_factory=list)
    
    # Module priorities: {module_name: priority (1=highest)}
    module_priorities: Dict[str, int] = field(default_factory=dict)
    
    # File to module mapping: {file_path: module_name}
    file_to_module: Dict[str, str] = field(default_factory=dict)
    
    # Findings and issues
    findings: List[Dict[str, Any]] = field(default_factory=list)
    issues: List[str] = field(default_factory=list)
    
    # Summary (LLM generated)
    summary: str = ""
    scan_signature: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScanMemory":
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


class AgentMemoryManager:
    """Manages agent scan memory with persistence."""
    
    def __init__(self, output_dir: Path, llm_client=None):
        self.output_dir = output_dir
        self.llm_client = llm_client
        self.memory_file = output_dir / "scan_memory.json"
        self.memory = ScanMemory()
    
    def _memory_matches_current_inputs(
        self,
        *,
        target_repo: str,
        target_commit: str,
        cve_id: str,
        module_priorities: Dict[str, int],
        file_to_module: Dict[str, str],
        scan_signature: Dict[str, Any],
    ) -> bool:
        """Return whether persisted memory still matches the current scan inputs."""
        return (
            self.memory.target_repo == target_repo
            and self.memory.target_commit == target_commit[:12]
            and self.memory.cve_id == cve_id
            and self.memory.module_priorities == module_priorities
            and self.memory.file_to_module == file_to_module
            and self.memory.scan_signature == self._normalize_scan_signature(scan_signature)
        )

    @staticmethod
    def _normalize_scan_signature(scan_signature: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize scan fingerprint-like data for stable comparison."""
        if not isinstance(scan_signature, dict):
            return {}

        scan_config = scan_signature.get("scan_config", {})
        if not isinstance(scan_config, dict):
            scan_config = {}

        llm_config = scan_signature.get("llm", {})
        if not isinstance(llm_config, dict):
            llm_config = {}

        def exact_object(container: Dict[str, Any], key: str) -> Dict[str, Any]:
            value = container.get(key, {})
            return dict(value) if isinstance(value, dict) else {}

        def exact_string(container: Dict[str, Any], key: str) -> str:
            value = container.get(key, "")
            return value if isinstance(value, str) else ""

        scan_languages = scan_config.get("scan_languages", [])
        if not isinstance(scan_languages, list):
            scan_languages = []
        normalized_languages = sorted(
            {
                str(language).strip().lower()
                for language in scan_languages
                if str(language).strip()
            }
        )

        codeql_database_names = scan_config.get("codeql_database_names", {})
        if not isinstance(codeql_database_names, dict):
            codeql_database_names = {}
        normalized_codeql_database_names = {}
        for lang, db_name in codeql_database_names.items():
            lang_key = str(lang).strip().lower()
            db_value = str(db_name).strip()
            if lang_key and db_value:
                normalized_codeql_database_names[lang_key] = db_value

        module_similarity = scan_config.get("module_similarity", {})
        if not isinstance(module_similarity, dict):
            module_similarity = {}
        try:
            normalized_module_similarity_threshold = float(module_similarity.get("threshold", 0.8))
        except (TypeError, ValueError):
            normalized_module_similarity_threshold = 0.8
        normalized_module_similarity = {
            "threshold": normalized_module_similarity_threshold,
            "model_name": str(module_similarity.get("model_name", "")).strip(),
            "device": str(module_similarity.get("device", "cpu")).strip(),
            "require_embedding": bool(module_similarity.get("require_embedding", False)),
            "resolved_model_path": str(module_similarity.get("resolved_model_path", "")).strip(),
            "artifact_hash": str(module_similarity.get("artifact_hash", "")).strip(),
        }
        raw_ablations = scan_config.get("ablations", {})
        if not isinstance(raw_ablations, dict):
            raw_ablations = {}
        normalized_ablations = {
            key: bool(raw_ablations.get(key, False))
            for key in ("repo_semantics", "reference_semantics", "candidate_priority", "memory", "verifier")
        }


        shared_public_memory = scan_config.get("shared_public_memory", {})
        if not isinstance(shared_public_memory, dict):
            shared_public_memory = {}
        normalized_shared_public_memory = {
            "enabled": bool(shared_public_memory.get("enabled", False)),
            "root_hash": str(shared_public_memory.get("root_hash", "")).strip(),
            "scope_key": str(shared_public_memory.get("scope_key", "")).strip(),
            "state_hash": str(shared_public_memory.get("state_hash", "")).strip(),
        }

        source_hashes = scan_signature.get("source_hashes", {})
        if not isinstance(source_hashes, dict):
            source_hashes = {}
        normalized_source_hashes = {
            str(label).strip(): str(file_hash).strip()
            for label, file_hash in source_hashes.items()
            if str(label).strip() and str(file_hash).strip()
        }
        config_hashes = scan_signature.get("config_hashes", {})
        if not isinstance(config_hashes, dict):
            config_hashes = {}
        normalized_config_hashes = {
            str(label).strip(): str(file_hash).strip()
            for label, file_hash in config_hashes.items()
            if str(label).strip() and str(file_hash).strip()
        }


        max_iterations = scan_config.get("max_iterations", 0)
        try:
            normalized_max_iterations = int(max_iterations)
        except (TypeError, ValueError):
            normalized_max_iterations = 0

        critical_stop_mode = str(scan_config.get("critical_stop_mode", "max")).strip().lower()

        try:
            normalized_critical_priority = int(scan_config.get("critical_stop_max_priority", 2))
        except (TypeError, ValueError):
            normalized_critical_priority = 2
        if normalized_critical_priority != 1:
            normalized_critical_priority = 2

        reference_profile_hash = str(scan_config.get("reference_profile_hash", "")).strip()
        candidate_file_schedule = scan_config.get("candidate_file_schedule", {})
        if not isinstance(candidate_file_schedule, dict):
            candidate_file_schedule = {}
        model_visible_input_projection = scan_config.get(
            "model_visible_input_projection",
            {},
        )
        if not isinstance(model_visible_input_projection, dict):
            model_visible_input_projection = {}
        model_input_stage_hashes = scan_config.get("model_input_stage_hashes", {})
        if not isinstance(model_input_stage_hashes, dict):
            model_input_stage_hashes = {}

        normalized_scan_signature = {
            "scan_config": {
                "max_iterations": normalized_max_iterations,
                "require_full_universe_completion": bool(
                    scan_config.get("require_full_universe_completion", False)
                ),
                "stop_when_critical_complete": bool(scan_config.get("stop_when_critical_complete", False)),
                "critical_stop_mode": critical_stop_mode,
                "critical_stop_max_priority": normalized_critical_priority,
                "model_visible_input_projection": model_visible_input_projection,
                "model_revision_attestation": exact_object(
                    scan_config,
                    "model_revision_attestation",
                ),
                "model_visible_input_runtime_projection": exact_object(
                    scan_config,
                    "model_visible_input_runtime_projection",
                ),
                "model_input_stage_hashes": model_input_stage_hashes,
                "endpoint_snapshot": exact_object(
                    scan_config,
                    "endpoint_snapshot",
                ),
                "endpoint_snapshot_sha256": exact_string(
                    scan_config,
                    "endpoint_snapshot_sha256",
                ),
                "decoding_config_requested": exact_object(
                    scan_config,
                    "decoding_config_requested",
                ),
                "decoding_config_requested_sha256": exact_string(
                    scan_config,
                    "decoding_config_requested_sha256",
                ),
                "decoding_config_effective": exact_object(
                    scan_config,
                    "decoding_config_effective",
                ),
                "decoding_config_effective_sha256": exact_string(
                    scan_config,
                    "decoding_config_effective_sha256",
                ),
                "scan_languages": normalized_languages,
                "codeql_database_names": normalized_codeql_database_names,
                "shared_public_memory": normalized_shared_public_memory,
                "module_similarity": normalized_module_similarity,
                "ablations": normalized_ablations,
                "reference_profile_hash": reference_profile_hash,
                "candidate_file_schedule": candidate_file_schedule,
            },
            "llm": {
                "provider": str(llm_config.get("provider", "")).strip(),
                "model": str(llm_config.get("model", "")).strip(),
                "model_revision": exact_string(
                    llm_config,
                    "model_revision",
                ),
                "model_revision_attestation": exact_object(
                    llm_config,
                    "model_revision_attestation",
                ),
                "endpoint_snapshot": exact_object(
                    llm_config,
                    "endpoint_snapshot",
                ),
                "endpoint_snapshot_sha256": exact_string(
                    llm_config,
                    "endpoint_snapshot_sha256",
                ),
                "decoding_config_requested": exact_object(
                    llm_config,
                    "decoding_config_requested",
                ),
                "decoding_config_requested_sha256": exact_string(
                    llm_config,
                    "decoding_config_requested_sha256",
                ),
                "decoding_config_effective": exact_object(
                    llm_config,
                    "decoding_config_effective",
                ),
                "decoding_config_effective_sha256": exact_string(
                    llm_config,
                    "decoding_config_effective_sha256",
                ),
                "base_url": str(llm_config.get("base_url", "")).strip(),
                "temperature": llm_config.get("temperature"),
                "top_p": llm_config.get("top_p"),
                "max_tokens": llm_config.get("max_tokens"),
                "enable_thinking": llm_config.get("enable_thinking"),
                "reasoning_effort": llm_config.get("reasoning_effort"),
                "service_tier": llm_config.get("service_tier"),
                "fallback_on_retry_exhausted": bool(
                    llm_config.get("fallback_on_retry_exhausted", False)
                ),
                "exact_decoding_enforced": bool(
                    llm_config.get("exact_decoding_enforced", False)
                ),
            },
            "source_hashes": normalized_source_hashes,
            "config_hashes": normalized_config_hashes,
        }
        return normalized_scan_signature

    @staticmethod
    def _normalize_critical_stop_max_priority(critical_stop_max_priority: int) -> int:
        """Normalize the persisted critical-scope priority."""
        return 1 if critical_stop_max_priority == 1 else 2

    def initialize(
        self,
        target_repo: str,
        target_commit: str,
        cve_id: str,
        module_priorities: Dict[str, int],
        file_to_module: Dict[str, str],
        critical_stop_max_priority: int = 2,
        scan_signature: Optional[Dict[str, Any]] = None,
        resume_enabled: bool = True,
    ) -> bool:
        """Initialize memory for a new scan or resume existing.
        
        Returns:
            True if resuming from existing memory, False if starting fresh.
        """
        normalized_max_priority = self._normalize_critical_stop_max_priority(
            critical_stop_max_priority
        )
        normalized_scan_signature = self._normalize_scan_signature(
            scan_signature or {}
        )
        if resume_enabled and self.load():
            if self._memory_matches_current_inputs(
                target_repo=target_repo,
                target_commit=target_commit,
                cve_id=cve_id,
                module_priorities=module_priorities,
                file_to_module=file_to_module,
                scan_signature=normalized_scan_signature,
            ):
                memory_updated = False
                if self.memory.critical_stop_max_priority != normalized_max_priority:
                    self.memory.critical_stop_max_priority = normalized_max_priority
                    memory_updated = True
                if self.memory.scan_signature != normalized_scan_signature:
                    self.memory.scan_signature = normalized_scan_signature
                    memory_updated = True
                if memory_updated:
                    self.save()
                logger.info(f"Resuming scan from {self.memory_file}")
                return True
            logger.warning("Discarding stale scan memory that does not match current scan inputs")

        if not resume_enabled and self.memory_file.exists():
            logger.info("Memory ablation enabled; ignoring persisted scan memory at %s", self.memory_file)
        self.memory = ScanMemory(
            target_repo=target_repo,
            target_commit=target_commit[:12],
            cve_id=cve_id,
            started_at=datetime.now().isoformat(),
            critical_stop_max_priority=normalized_max_priority,
            module_priorities=module_priorities,
            file_to_module=file_to_module,
            file_status={f: "pending" for f in file_to_module},
            scan_signature=normalized_scan_signature,
        )
        self.save()
        logger.info(f"Initialized new scan memory with {len(file_to_module)} files")
        return False
    
    def load(self) -> bool:
        """Load memory from disk. Returns True if successful."""
        if not self.memory_file.exists():
            return False
        try:
            data = json.loads(self.memory_file.read_text(encoding="utf-8"))
            self.memory = ScanMemory.from_dict(data)
            return True
        except Exception as e:
            logger.warning(f"Failed to load memory: {e}")
            return False
    
    def save(self):
        """Save memory to disk."""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        write_atomic_text(
            self.memory_file,
            json.dumps(self.memory.to_dict(), indent=2, ensure_ascii=False),
        )
    
    def mark_file(self, file_path: str, status: str):
        """更新文件状态并保持 completed <= reached。"""
        if file_path not in self.memory.file_status:
            return
        previous_status = self.memory.file_status[file_path]
        previous_touches = list(self.memory.coverage_first_touches)
        self.memory.file_status[file_path] = status
        if status == "completed" and file_path not in self.memory.coverage_first_touches:
            self.memory.coverage_first_touches.append(file_path)
        try:
            self.save()
        except Exception:
            self.memory.file_status[file_path] = previous_status
            self.memory.coverage_first_touches = previous_touches
            raise

    def mark_file_completed(self, file_path: str, reason: str = "") -> None:
        """Mark a tracked file as completed and persist the optional reason."""
        if file_path not in self.memory.file_status:
            return
        previous_status = self.memory.file_status[file_path]
        had_previous_reason = file_path in self.memory.file_completion_reasons
        previous_reason = self.memory.file_completion_reasons.get(file_path, "")
        previous_touches = list(self.memory.coverage_first_touches)
        self.memory.file_status[file_path] = "completed"
        if file_path not in self.memory.coverage_first_touches:
            self.memory.coverage_first_touches.append(file_path)
        if reason:
            self.memory.file_completion_reasons[file_path] = reason
        try:
            self.save()
        except Exception:
            self.memory.file_status[file_path] = previous_status
            if had_previous_reason:
                self.memory.file_completion_reasons[file_path] = previous_reason
            else:
                self.memory.file_completion_reasons.pop(file_path, None)
            self.memory.coverage_first_touches = previous_touches
            raise

    def record_coverage_first_touches(self, file_paths: List[str]) -> None:
        """原子追加新的成功带路径首次触达。"""
        if not isinstance(file_paths, list):
            raise ValueError("coverage first touches must be a list")
        normalized = [str(path).strip() for path in file_paths]
        if any(not path for path in normalized):
            raise ValueError("coverage first touches contain an empty path")
        previous = list(self.memory.coverage_first_touches)
        seen = set(previous)
        changed = False
        for path in normalized:
            if path in seen:
                continue
            seen.add(path)
            self.memory.coverage_first_touches.append(path)
            changed = True
        if not changed:
            return
        try:
            self.save()
        except Exception:
            self.memory.coverage_first_touches = previous
            raise

    def record_schedule_presented_page(self, page_index: int) -> None:
        """按连续顺序保存成功展示的 schedule 页。"""
        if isinstance(page_index, bool) or not isinstance(page_index, int) or page_index < 0:
            raise ValueError("presented schedule page index must be a non-negative integer")
        previous = list(self.memory.schedule_presented_page_indices)
        if page_index in previous:
            return
        expected = 0 if not previous else previous[-1] + 1
        if page_index != expected:
            raise ValueError("presented schedule pages must form a contiguous prefix")
        events = self.memory.schedule_window_events
        if (
            page_index >= len(events)
            or events[page_index].get("cursor_index")
            != page_index * FROZEN_SCHEDULE_PAGE_SIZE
        ):
            raise ValueError("presented schedule page has no matching entered-window event")
        self.memory.schedule_presented_page_indices.append(page_index)
        try:
            self.save()
        except Exception:
            self.memory.schedule_presented_page_indices = previous
            raise

    def record_schedule_window_event(self, event: Dict[str, Any]) -> None:
        """原子保存一个精确连续页条目事件。"""
        if not isinstance(event, dict):
            raise ValueError("schedule window event must be an object")
        normalized = json.loads(json.dumps(event, ensure_ascii=False))
        expected_keys = {
            "schema_version",
            "cursor_index",
            "window_end_index_exclusive",
            "window_file_count",
            "active_pending_file_count",
            "completed_window_count",
            "window_sha256",
        }
        if set(normalized) != expected_keys:
            raise ValueError("schedule window event must use the exact key set")
        cursor = normalized.get("cursor_index")
        end_cursor = normalized.get("window_end_index_exclusive")
        window_count = normalized.get("window_file_count")
        active_count = normalized.get("active_pending_file_count")
        completed_count = normalized.get("completed_window_count")
        window_sha256 = normalized.get("window_sha256")
        integer_values = (cursor, end_cursor, window_count, active_count, completed_count)
        if any(isinstance(value, bool) or not isinstance(value, int) for value in integer_values):
            raise ValueError("schedule window event counters must be integers")
        if (
            normalized.get("schema_version") != 1
            or cursor < 0
            or cursor % FROZEN_SCHEDULE_PAGE_SIZE != 0
            or window_count < 1
            or window_count > FROZEN_SCHEDULE_PAGE_SIZE
            or end_cursor != cursor + window_count
            or active_count != window_count
            or completed_count != 0
            or not isinstance(window_sha256, str)
            or len(window_sha256) != 64
            or any(character not in "0123456789abcdef" for character in window_sha256)
        ):
            raise ValueError("schedule window event content is invalid")
        previous = list(self.memory.schedule_window_events)
        for prior in previous:
            if prior.get("cursor_index") == cursor:
                if prior != normalized:
                    raise ValueError("schedule window event changed for an existing cursor")
                return
        expected_cursor = (
            0
            if not previous
            else previous[-1].get("window_end_index_exclusive")
        )
        if cursor != expected_cursor:
            raise ValueError("schedule window events must be exactly contiguous")
        self.memory.schedule_window_events.append(normalized)
        try:
            self.save()
        except Exception:
            self.memory.schedule_window_events = previous
            raise

    @staticmethod
    def _normalize_finding(
        finding: Dict[str, Any],
    ) -> tuple[Dict[str, Any], tuple[str, str, str, Optional[int]]]:
        """Normalize one finding payload and return its stable dedupe key."""
        file_path = str(finding.get("file_path", "") or "").strip()
        function_name = str(finding.get("function_name", "") or "").strip()
        vulnerability_type = str(finding.get("vulnerability_type", "") or "").strip()
        raw_line_number = finding.get("line_number")
        try:
            line_number = int(raw_line_number) if raw_line_number is not None else None
        except (TypeError, ValueError):
            line_number = None

        normalized_finding = dict(finding)
        normalized_finding["file_path"] = file_path
        normalized_finding["function_name"] = function_name
        normalized_finding["vulnerability_type"] = vulnerability_type
        if line_number is None:
            normalized_finding.pop("line_number", None)
        else:
            normalized_finding["line_number"] = line_number

        finding_key = (
            file_path,
            function_name,
            vulnerability_type,
            line_number,
        )
        return normalized_finding, finding_key

    def _build_existing_finding_keys(self) -> set[tuple[str, str, str, Optional[int]]]:
        """Build the current dedupe index for all findings already in memory."""
        dedupe_keys: set[tuple[str, str, str, Optional[int]]] = set()
        for existing in self.memory.findings:
            _, finding_key = self._normalize_finding(existing)
            dedupe_keys.add(finding_key)
        return dedupe_keys

    def add_finding(self, finding: Dict[str, Any]) -> bool:
        """记录一条漏洞 finding，保存失败时回滚。"""
        normalized_finding, finding_key = self._normalize_finding(finding)
        if finding_key in self._build_existing_finding_keys():
            return False
        previous_findings = list(self.memory.findings)
        self.memory.findings.append(normalized_finding)
        try:
            self.save()
        except Exception:
            self.memory.findings = previous_findings
            raise
        return True

    def add_findings(self, findings: List[Dict[str, Any]]) -> int:
        """一次去重记录多条 findings，并支持保存失败回滚。"""
        if not findings:
            return 0
        normalized_batch = [self._normalize_finding(finding) for finding in findings]
        dedupe_keys = self._build_existing_finding_keys()
        pending_findings: List[Dict[str, Any]] = []
        for normalized_finding, finding_key in normalized_batch:
            if finding_key in dedupe_keys:
                continue
            pending_findings.append(normalized_finding)
            dedupe_keys.add(finding_key)
        if not pending_findings:
            return 0
        previous_findings = list(self.memory.findings)
        self.memory.findings.extend(pending_findings)
        try:
            self.save()
        except Exception:
            self.memory.findings = previous_findings
            raise
        return len(pending_findings)

    def add_findings_with_first_touches(
        self,
        findings: List[Dict[str, Any]],
        file_paths: List[str],
    ) -> int:
        """在一次可回滚转换中保存路径触达及其 findings。"""
        if not isinstance(findings, list) or not isinstance(file_paths, list):
            raise ValueError("atomic finding transition requires list inputs")
        normalized_paths = [str(path).strip() for path in file_paths]
        if any(not path for path in normalized_paths):
            raise ValueError("atomic finding transition contains an empty path")
        path_set = set(normalized_paths)
        normalized_findings: List[
            tuple[Dict[str, Any], tuple[str, str, str, Optional[int]]]
        ] = []
        for finding in findings:
            if not isinstance(finding, dict):
                raise ValueError("atomic finding transition contains an invalid finding")
            normalized_finding, finding_key = self._normalize_finding(finding)
            finding_path = normalized_finding.get("file_path", "")
            if not finding_path or finding_path not in path_set:
                raise ValueError("atomic finding transition has an unbound finding path")
            normalized_findings.append((normalized_finding, finding_key))

        dedupe_keys = self._build_existing_finding_keys()
        pending_findings: List[Dict[str, Any]] = []
        for normalized_finding, finding_key in normalized_findings:
            if finding_key in dedupe_keys:
                continue
            pending_findings.append(normalized_finding)
            dedupe_keys.add(finding_key)
        seen_touches = set(self.memory.coverage_first_touches)
        pending_touches: List[str] = []
        for path in normalized_paths:
            if path in seen_touches:
                continue
            seen_touches.add(path)
            pending_touches.append(path)
        if not pending_findings and not pending_touches:
            return 0

        previous_findings = list(self.memory.findings)
        previous_touches = list(self.memory.coverage_first_touches)
        self.memory.coverage_first_touches.extend(pending_touches)
        self.memory.findings.extend(pending_findings)
        try:
            self.save()
        except Exception:
            self.memory.findings = previous_findings
            self.memory.coverage_first_touches = previous_touches
            raise
        return len(pending_findings)

    def add_issue(self, issue: str):
        """记录扫描问题，保存失败时回滚。"""
        previous_issues = list(self.memory.issues)
        self.memory.issues.append(issue)
        try:
            self.save()
        except Exception:
            self.memory.issues = previous_issues
            raise

    def get_scanned_files(self) -> List[str]:
        """Get list of files that have been scanned (completed status)."""
        return [f for f, s in self.memory.file_status.items() if s == "completed"]
    
    def get_findings_summary(self) -> List[Dict[str, str]]:
        """Get a brief summary of all findings for context."""
        return [
            {
                "file": f.get("file_path", "unknown"),
                "type": f.get("vulnerability_type", "unknown"),
                "confidence": f.get("confidence", "unknown"),
            }
            for f in self.memory.findings
        ]
    

    def count_statuses(self, file_status: Dict[str, str]) -> Dict[str, int]:
        """Count file status values used for scan progress summaries."""
        completed = sum(1 for s in file_status.values() if s == "completed")
        pending = sum(1 for s in file_status.values() if s == "pending")
        skipped = sum(1 for s in file_status.values() if s == "skipped")
        not_tracked = sum(1 for s in file_status.values() if s == "not_tracked")
        return {
            "completed": completed,
            "pending": pending,
            "skipped": skipped,
            "not_tracked": not_tracked,
            "total": len(file_status),
        }

    def summarize_statuses(self, file_status: Dict[str, str]) -> str:
        """Format a compact status summary string from a status map."""
        counts = self.count_statuses(file_status)
        return (
            f"{counts['completed']} completed, {counts['pending']} pending, "
            f"{counts['skipped']} skipped, "
            f"{counts['not_tracked']} not tracked"
        )

    def format_progress_info(self) -> str:
        """Format scan progress in a reusable human-readable form."""
        progress = self.get_progress()
        return (
            f"{progress['completed']}/{progress['total_files']} files scanned, "
            f"{progress['findings']} findings. "
            f"Priority-1: {progress['priority_1']['completed']}/{progress['priority_1']['total']}, "
            f"Priority-2: {progress['priority_2']['completed']}/{progress['priority_2']['total']}."
        )
    
    def get_pending_files(self, max_priority: int = 3) -> List[str]:
        """Get pending files up to given priority, sorted by priority."""
        pending = []
        for f, status in self.memory.file_status.items():
            if status != "pending":
                continue
            module = self.memory.file_to_module.get(f, "")
            priority = self.memory.module_priorities.get(module, 3)
            if priority <= max_priority:
                pending.append((priority, f))
        pending.sort(key=lambda x: x[0])
        return [f for _, f in pending]
    
    def get_progress(self) -> Dict[str, Any]:
        """Get scan progress statistics."""
        total = len(self.memory.file_status)
        counts = self.count_statuses(self.memory.file_status)
        
        # Priority breakdown
        priority_stats = {1: {"total": 0, "completed": 0}, 2: {"total": 0, "completed": 0}}
        for f, status in self.memory.file_status.items():
            module = self.memory.file_to_module.get(f, "")
            priority = self.memory.module_priorities.get(module, 3)
            if priority <= 2:
                priority_stats[priority]["total"] += 1
                if status == "completed":
                    priority_stats[priority]["completed"] += 1
        
        return {
            "total_files": total,
            "completed": counts["completed"],
            "pending": counts["pending"],
            "findings": len(self.memory.findings),
            "priority_1": priority_stats[1],
            "priority_2": priority_stats[2],
        }
    
    def is_critical_complete(self, max_priority: int = 2) -> bool:
        """仅当非空关键范围内的文件全部完成时返回真。"""
        normalized_max_priority = 1 if max_priority <= 1 else 2
        critical_total = 0
        for f, status in self.memory.file_status.items():
            module = self.memory.file_to_module.get(f, "")
            priority = self.memory.module_priorities.get(module, 3)
            if priority > normalized_max_priority:
                continue
            critical_total += 1
            if status == "pending":
                return False
        return critical_total > 0
    
    def generate_summary(self) -> str:
        """Generate summary using LLM."""
        if not self.llm_client:
            return ""
        
        progress = self.get_progress()
        critical_stop_max_priority = self._normalize_critical_stop_max_priority(
            self.memory.critical_stop_max_priority
        )
        critical_complete = self.is_critical_complete(max_priority=critical_stop_max_priority)
        if critical_complete:
            coverage_status = "complete"
        elif int(progress.get("completed", 0)) > 0 or int(progress.get("findings", 0)) > 0:
            coverage_status = "partial"
        else:
            coverage_status = "empty"
        prompt = f"""Summarize this vulnerability scan in 3-5 sentences:

Target: {self.memory.target_repo}@{self.memory.target_commit}
CVE: {self.memory.cve_id}
Coverage status: {coverage_status}
Critical scope complete: {critical_complete}
Files scanned: {progress['completed']}/{progress['total_files']}
Vulnerabilities found: {progress['findings']}
Priority-1 modules: {progress['priority_1']['completed']}/{progress['priority_1']['total']} complete
Issues encountered: {len(self.memory.issues)}

Findings: {json.dumps(self.memory.findings[-5:], indent=2) if self.memory.findings else 'None'}
Issues: {self.memory.issues[-5:] if self.memory.issues else 'None'}

Provide a concise technical summary.
Treat the findings as scan-stage candidates, not confirmed exploitable vulnerabilities.
If coverage status is partial or empty, explicitly say the scan is incomplete and avoid definitive language such as confirmed flaw, critical flaw, or no other vulnerabilities remain."""

        try:
            response = self.llm_client.complete(prompt)
            content = response.content if hasattr(response, 'content') else str(response)
            self.memory.summary = content
            self.save()
            return content
        except Exception as e:
            logger.warning(f"Failed to generate summary: {e}")
            return ""
    
    def to_markdown(self) -> str:
        """Generate markdown report."""
        progress = self.get_progress()
        critical_stop_max_priority = self._normalize_critical_stop_max_priority(
            self.memory.critical_stop_max_priority
        )
        critical_scope_label = (
            "priority-1 (directly affected or embedding-similar) only"
            if critical_stop_max_priority == 1
            else "priority-1/2 (directly affected or embedding-similar + related)"
        )
        
        lines = [
            "# Vulnerability Scan Memory",
            "",
            "## Scan Info",
            f"- **Target**: {self.memory.target_repo}@{self.memory.target_commit}",
            f"- **CVE**: {self.memory.cve_id}",
            f"- **Started**: {self.memory.started_at}",
            f"- **Critical Scope**: {critical_scope_label}",
            "",
            "## Progress",
            f"- Total files: {progress['total_files']}",
            f"- Completed: {progress['completed']}",
            f"- Pending: {progress['pending']}",
            f"- Findings: {progress['findings']}",
            "",
            "### Priority Breakdown",
            (
                f"- Priority 1 (directly affected or embedding-similar): "
                f"{progress['priority_1']['completed']}/{progress['priority_1']['total']}"
            ),
            f"- Priority 2 (related): {progress['priority_2']['completed']}/{progress['priority_2']['total']}",
            "",
        ]
        
        # Critical files status
        if not self.is_critical_complete(max_priority=critical_stop_max_priority):
            lines.extend([
                "### ⚠️ Incomplete Critical Files",
                "",
            ])
            pending_critical_files = 0
            for f, status in self.memory.file_status.items():
                module = self.memory.file_to_module.get(f, "")
                priority = self.memory.module_priorities.get(module, 3)
                if priority <= critical_stop_max_priority and status == "pending":
                    pending_critical_files += 1
                    lines.append(f"- [ ] `{f}`")
            if pending_critical_files == 0:
                lines.append("- No files are bound to the configured critical scope.")
            lines.append("")
        
        # Findings
        if self.memory.findings:
            lines.extend(["## Findings", ""])
            for i, f in enumerate(self.memory.findings, 1):
                lines.append(f"{i}. **{f.get('file_path', 'unknown')}**: {f.get('vulnerability_type', 'unknown')}")
            lines.append("")
        
        # Issues
        if self.memory.issues:
            lines.extend(["## Issues Encountered", ""])
            for issue in self.memory.issues:
                lines.append(f"- {issue}")
            lines.append("")
        
        # Summary
        if self.memory.summary:
            lines.extend(["## Summary", "", self.memory.summary, ""])
        
        return "\n".join(lines)
    
    def save_markdown(self):
        """Save markdown report."""
        md_path = self.output_dir / "scan_memory.md"
        md_path.write_text(self.to_markdown(), encoding="utf-8")
