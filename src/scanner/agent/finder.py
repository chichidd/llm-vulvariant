"""Agentic vulnerability finder core logic."""

from __future__ import annotations

import copy
import json
import time
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List, Optional, Tuple

from config_snapshot import consumed_scanner_config_hashes
from config import (
    _scanner_config,  # noqa: F401 - compatibility export used by tests and callers
)
from llm import BaseLLMClient, LLMResponseIdentityError
from llm.tool_arguments import normalize_tool_arguments
from profiler.fingerprint import (
    hash_python_source_tree,
    stable_data_hash,
)
from scanner.evaluation_contract import (
    module_similarity_byte_binding,
    observed_module_similarity_metadata,
)
from scanner.similarity.embedding import embedding_model_artifact_signature
from utils.logger import get_logger
from utils.number_utils import to_int
from utils.llm_utils import extract_json_from_text
from scanner.agent.utils import (
    clear_reasoning_content,
    compress_iteration_conversation,
    estimate_serialized_tokens,
    make_serializable,
)

from .memory import AgentMemoryManager
from .priority import calculate_module_priorities, resolve_module_similarity_config
from .prompts import (
    build_initial_user_message,
    build_intermediate_user_message,
    build_system_prompt,
)
from .schedule_window import (
    FROZEN_SCHEDULE_CONTRACT,
    FROZEN_SCHEDULE_PAGE_ALGORITHM,
    FROZEN_SCHEDULE_PAGE_SIZE,
    build_schedule_page,
    schedule_contract_metadata,
)
from .toolkit import AgenticToolkit

logger = get_logger(__name__)

_CONTEXT_LIMIT_ERROR_PATTERNS = (
    "maximum context length",
    "context length exceeded",
    "context window exceeded",
    "prompt is too long",
    "too many tokens",
    "input is too long",
)
_PREFLIGHT_CONTEXT_THRESHOLD = 0.8
_MODEL_VISIBLE_INPUT_RUNTIME_PROJECTION_KEYS = (
    "raw_reference_sha256",
    "projected_reference_sha256",
    "raw_static_input_sha256",
    "projected_static_input_sha256",
    "invariant_projected_static_input_sha256",
    "policy_visible_static_input_sha256",
    "policy_preserved_fields",
)
_DECODING_CONFIG_KEYS = frozenset({
    "temperature",
    "top_p",
    "max_tokens",
    "enable_thinking",
    "reasoning_effort",
    "service_tier",
})


def _validate_decoding_config_binding(
    payload: Optional[Dict[str, Any]],
    sha256: Optional[str],
    *,
    label: str,
) -> Tuple[Dict[str, Any], Optional[str]]:
    """校验续跑身份的规范解码对象与哈希。"""
    if (payload is None) != (sha256 is None):
        raise ValueError(f"{label} payload and SHA-256 must be provided together")
    if payload is None:
        return {}, None
    if not isinstance(payload, dict) or set(payload) != _DECODING_CONFIG_KEYS:
        raise ValueError(f"{label} must contain exactly the decoding key set")
    try:
        json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} must be finite canonical JSON") from exc
    if (
        not isinstance(sha256, str)
        or len(sha256) != 64
        or any(character not in "0123456789abcdef" for character in sha256)
        or stable_data_hash(payload) != sha256
    ):
        raise ValueError(f"{label} SHA-256 binding is invalid")
    return dict(payload), sha256


def _validate_model_revision_attestation_binding(
    binding: Optional[Dict[str, str]],
) -> Dict[str, str]:
    """校验可移植的操作员证明续跑绑定。"""
    if binding is None:
        return {}
    if not isinstance(binding, dict) or set(binding) != {
        "path",
        "file_sha256",
        "payload_sha256",
    }:
        raise ValueError("model revision attestation binding is malformed")
    raw_path = binding.get("path")
    path = PurePosixPath(raw_path) if isinstance(raw_path, str) else None
    if (
        path is None
        or not raw_path
        or raw_path.startswith("/")
        or ".." in path.parts
        or path.as_posix() != raw_path
        or chr(92) in raw_path
    ):
        raise ValueError(
            "model revision attestation path must be canonical workspace-relative POSIX"
        )
    for key in ("file_sha256", "payload_sha256"):
        value = binding.get(key)
        if (
            not isinstance(value, str)
            or len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)
        ):
            raise ValueError(
                f"model revision attestation {key} is invalid"
            )
    return {
        "path": raw_path,
        "file_sha256": binding["file_sha256"],
        "payload_sha256": binding["payload_sha256"],
    }


class AgenticVulnFinder:
    def __init__(
        self,
        llm_client: BaseLLMClient,
        repo_path: Path,
        software_profile,
        vulnerability_profile,
        max_iterations: int = 300,
        max_sub_turns: int = 64,
        stop_when_critical_complete: bool = False,
        critical_stop_mode: str = "max",
        critical_stop_max_priority: int = 2,
        require_full_universe_completion: bool = False,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        verbose: bool = True,
        output_dir: Optional[Path] = None,
        languages: Optional[List[str]] = None,
        codeql_database_names: Optional[Dict[str, str]] = None,
        shared_public_memory_manager: Optional[Any] = None,
        shared_public_memory_scope: Optional[Dict[str, Any]] = None,
        module_similarity_config: Optional[Dict[str, Any]] = None,
        ablation_config: Optional[Dict[str, bool]] = None,
        host_priority_plan: Optional[Dict[str, Any]] = None,
        unprioritized_file_schedule: Optional[Dict[str, Any]] = None,
        target_path_projection: Optional[Dict[str, Any]] = None,
        model_revision: Optional[str] = None,
        model_revision_attestation_binding: Optional[Dict[str, str]] = None,
        endpoint_snapshot: Optional[Dict[str, str]] = None,
        endpoint_snapshot_sha256: Optional[str] = None,
        decoding_config_requested: Optional[Dict[str, Any]] = None,
        decoding_config_requested_sha256: Optional[str] = None,
        decoding_config_effective: Optional[Dict[str, Any]] = None,
        decoding_config_effective_sha256: Optional[str] = None,
    ):
        self.llm_client = llm_client
        if model_revision is not None and (
            not isinstance(model_revision, str)
            or not model_revision
            or model_revision != model_revision.strip()
        ):
            raise ValueError("model_revision must be a non-empty exact string")
        self.model_revision = model_revision
        self.model_revision_attestation_binding = (
            _validate_model_revision_attestation_binding(
                model_revision_attestation_binding
            )
        )
        if (endpoint_snapshot is None) != (endpoint_snapshot_sha256 is None):
            raise ValueError(
                "endpoint snapshot payload and SHA-256 must be provided together"
            )
        if endpoint_snapshot is not None:
            if (
                not isinstance(endpoint_snapshot, dict)
                or set(endpoint_snapshot)
                != {"snapshot_id", "base_url", "api_family"}
                or not isinstance(endpoint_snapshot_sha256, str)
                or len(endpoint_snapshot_sha256) != 64
                or any(
                    character not in "0123456789abcdef"
                    for character in endpoint_snapshot_sha256
                )
                or stable_data_hash(endpoint_snapshot)
                != endpoint_snapshot_sha256
            ):
                raise ValueError("endpoint snapshot binding is invalid")
        self.endpoint_snapshot = dict(endpoint_snapshot or {})
        self.endpoint_snapshot_sha256 = endpoint_snapshot_sha256
        (
            self.decoding_config_requested,
            self.decoding_config_requested_sha256,
        ) = _validate_decoding_config_binding(
            decoding_config_requested,
            decoding_config_requested_sha256,
            label="requested decoding config",
        )
        (
            self.decoding_config_effective,
            self.decoding_config_effective_sha256,
        ) = _validate_decoding_config_binding(
            decoding_config_effective,
            decoding_config_effective_sha256,
            label="effective decoding config",
        )
        if self.decoding_config_requested and (
            self.decoding_config_requested
            != self.decoding_config_effective
            or self.decoding_config_requested_sha256
            != self.decoding_config_effective_sha256
        ):
            raise ValueError(
                "requested decoding config does not match effective config"
            )
        self.repo_path = repo_path
        self.software_profile = software_profile
        self.vulnerability_profile = vulnerability_profile
        self.max_iterations = max_iterations
        self.max_sub_turns = max(1, int(max_sub_turns))
        self.stop_when_critical_complete = stop_when_critical_complete
        normalized_stop_mode = (critical_stop_mode or "max").lower()
        if normalized_stop_mode not in {"min", "max"}:
            logger.warning(
                f"Invalid critical_stop_mode={critical_stop_mode!r}; fallback to 'max'"
            )
            normalized_stop_mode = "max"
        self.critical_stop_mode = normalized_stop_mode
        if critical_stop_max_priority not in {1, 2}:
            logger.warning(
                "Invalid critical_stop_max_priority=%r; fallback to 2",
                critical_stop_max_priority,
            )
        self.critical_stop_max_priority = 1 if critical_stop_max_priority == 1 else 2
        self.require_full_universe_completion = bool(
            require_full_universe_completion
        )
        llm_config = getattr(self.llm_client, "config", None)
        default_temperature = getattr(llm_config, "temperature", 0.0) if llm_config is not None else 0.0
        self.temperature = default_temperature if temperature is None else temperature
        default_max_tokens = to_int(getattr(llm_config, "max_tokens", 0)) if llm_config is not None else 0
        self.max_tokens = default_max_tokens if max_tokens is None else max_tokens
        self.verbose = verbose
        self.output_dir = output_dir
        self.scan_languages = list(languages or [])
        self.codeql_database_names = dict(codeql_database_names or {})
        self.shared_public_memory_scope = dict(shared_public_memory_scope or {})
        self.module_similarity_config = resolve_module_similarity_config(module_similarity_config)
        raw_ablation_config = ablation_config if isinstance(ablation_config, dict) else {}
        self.ablation_config = {
            "repo_semantics": bool(raw_ablation_config.get("repo_semantics", False)),
            "reference_semantics": bool(raw_ablation_config.get("reference_semantics", False)),
            "candidate_priority": bool(raw_ablation_config.get("candidate_priority", False)),
            "memory": bool(raw_ablation_config.get("memory", False)),
            "verifier": bool(raw_ablation_config.get("verifier", False)),
        }
        self.candidate_priority_enabled = not self.ablation_config["candidate_priority"]
        self.verifier_enabled = not self.ablation_config["verifier"]
        self.memory_guidance_enabled = not self.ablation_config["memory"]
        self.module_similarity_provenance: Dict[str, Any] = {}
        self._host_priority_plan = dict(host_priority_plan or {})
        self.target_path_projection = dict(target_path_projection or {})
        self.model_visible_input_projection_provenance: Dict[str, Any] = {}
        self.model_visible_input_runtime_projection: Dict[str, Any] = {}
        self._model_visible_software_profile = software_profile
        self._model_visible_vulnerability_profile = vulnerability_profile
        self.unprioritized_file_schedule = dict(unprioritized_file_schedule or {})
        self.candidate_order_provenance: Dict[str, Any] = {}
        self.toolkit = AgenticToolkit(
            repo_path,
            shared_public_memory_manager=shared_public_memory_manager,
            languages=languages,
            codeql_database_names=codeql_database_names,
            memory_guidance_enabled=self.memory_guidance_enabled,
            verifier_enabled=self.verifier_enabled,
        )
        self.found_vulnerabilities: List[Dict[str, Any]] = []
        self.conversation_history: List[Dict[str, Any]] = []
        
        # Initialize memory manager
        self.memory: Optional[AgentMemoryManager] = None
        self.module_priorities: Dict[str, int] = {}
        self.file_to_module: Dict[str, str] = {}
        self._schedule_window_cursor: Optional[int] = None
        self._schedule_window_page: Optional[Dict[str, Any]] = None
        self._schedule_window_events: List[Dict[str, Any]] = []
        self._schedule_presented_page_indices: List[int] = []
        self._schedule_resume_start_index = 0
        self._schedule_resumed = False
        self._initialize_model_visible_input_projection()
        self._init_memory()

    @staticmethod
    def _static_profile_payload(value: Any) -> Any:
        """把画像规范化为独立的 JSON 兼容静态 payload。"""
        payload = value.to_dict() if hasattr(value, "to_dict") else value
        return json.loads(
            json.dumps(make_serializable(payload), ensure_ascii=False)
        )

    @staticmethod
    def _restore_policy_file_lists(raw_profile: Any, projected_profile: Any) -> Any:
        """保留模块文件列表，由候选展示阶段处理。"""
        if not isinstance(raw_profile, dict) or not isinstance(projected_profile, dict):
            return projected_profile
        raw_modules = raw_profile.get("modules", [])
        projected_modules = projected_profile.get("modules", [])
        if not isinstance(raw_modules, list) or not isinstance(projected_modules, list):
            return projected_profile
        for index, raw_module in enumerate(raw_modules):
            if index >= len(projected_modules):
                break
            projected_module = projected_modules[index]
            if not isinstance(raw_module, dict) or not isinstance(projected_module, dict):
                continue
            if "files" in raw_module:
                projected_module["files"] = json.loads(
                    json.dumps(raw_module["files"], ensure_ascii=False)
                )
        return projected_profile

    def _initialize_model_visible_input_projection(self) -> None:
        """投影非策略静态输入，并保留策略管理的文件列表。"""
        projection_files = self.target_path_projection.get("files", [])
        projection_provenance = self.target_path_projection.get("provenance", {})
        if not projection_files:
            if self.target_path_projection:
                raise ValueError("Target path projection is missing its file universe")
            return
        if not isinstance(projection_files, list) or not isinstance(
            projection_provenance,
            dict,
        ):
            raise ValueError("Target path projection has an invalid shape")
        configure_projection = getattr(
            self.toolkit,
            "set_model_path_projection_order",
            None,
        )
        if not callable(configure_projection):
            raise ValueError("Target path projection support is unavailable")
        configure_projection(projection_files)
        projector = getattr(self.toolkit, "sanitize_invariant_model_value", None)
        if not callable(projector):
            raise ValueError("Target path projection sanitizer is unavailable")

        raw_reference = self._static_profile_payload(self.vulnerability_profile)
        raw_software = self._static_profile_payload(self.software_profile)
        projected_reference = projector(raw_reference)
        invariant_projected_software = projector(raw_software)
        raw_static = {
            "reference": raw_reference,
            "target_software": raw_software,
        }
        invariant_projected_static = {
            "reference": projected_reference,
            "target_software": invariant_projected_software,
        }
        projected_software = self._restore_policy_file_lists(
            raw_software,
            copy.deepcopy(invariant_projected_software),
        )
        policy_visible_static = {
            "reference": projected_reference,
            "target_software": projected_software,
        }
        self._model_visible_vulnerability_profile = projected_reference
        self._model_visible_software_profile = projected_software
        self.model_visible_input_projection_provenance = {
            **dict(projection_provenance),
            "raw_reference_sha256": stable_data_hash(raw_reference),
            "projected_reference_sha256": stable_data_hash(projected_reference),
            "raw_static_input_sha256": stable_data_hash(raw_static),
            "projected_static_input_sha256": stable_data_hash(
                invariant_projected_static
            ),
            "invariant_projected_static_input_sha256": stable_data_hash(
                invariant_projected_static
            ),
            "policy_visible_static_input_sha256": stable_data_hash(
                policy_visible_static
            ),
            "policy_preserved_fields": ["target_software.modules[].files"],
        }
        self.model_visible_input_runtime_projection = {
            key: copy.deepcopy(
                self.model_visible_input_projection_provenance[key]
            )
            for key in _MODEL_VISIBLE_INPUT_RUNTIME_PROJECTION_KEYS
        }

    
    def _init_memory(self):
        """Initialize memory manager with priority information."""
        scheduled_files = list(
            self.unprioritized_file_schedule.get("files", [])
        )
        if not self.candidate_priority_enabled and not scheduled_files:
            raise ValueError(
                "candidate-priority ablation requires a frozen global file schedule"
            )
        if not self.candidate_priority_enabled and self.output_dir is None:
            raise ValueError(
                "candidate-priority ablation requires output_dir for its durable host ledger"
            )
        if (
            self.require_full_universe_completion
            and self.candidate_priority_enabled
            and not self._host_priority_plan
        ):
            raise ValueError(
                "full-universe completion requires a frozen host priority plan"
            )
        if not self.candidate_priority_enabled:
            schedule_scope = "__frozen_global_file_schedule__"
            self.module_priorities = {schedule_scope: 1}
            self.file_to_module = {
                file_path: schedule_scope for file_path in scheduled_files
            }
            raw_schedule_provenance = dict(
                self.unprioritized_file_schedule.get("provenance", {})
            )
            schedule_metadata = schedule_contract_metadata(
                scheduled_files,
                raw_schedule_provenance,
            )
            self.candidate_order_provenance = {
                **dict(
                    raw_schedule_provenance
                ),
                "contract": FROZEN_SCHEDULE_CONTRACT,
                "page_algorithm": FROZEN_SCHEDULE_PAGE_ALGORITHM,
                "page_size": FROZEN_SCHEDULE_PAGE_SIZE,
                "file_count": schedule_metadata["file_count"],
                "universe_sha256": schedule_metadata["universe_sha256"],
                "order_sha256": schedule_metadata["order_sha256"],
                "files": scheduled_files,
            }
            self.module_similarity_provenance = {
                "source": "frozen_unprioritized_file_schedule",
                "universe_sha256": str(
                    self.candidate_order_provenance.get("universe_sha256", "")
                ),
                "order_sha256": str(
                    self.candidate_order_provenance.get("order_sha256", "")
                ),
            }
        elif self._host_priority_plan:
            frozen_priorities = dict(
                self._host_priority_plan.get("module_priorities", {})
            )
            frozen_file_to_module = dict(
                self._host_priority_plan.get("file_to_module", {})
            )
            self.module_priorities = (
                frozen_priorities
                if self.candidate_priority_enabled
                else {module_name: 1 for module_name in frozen_priorities}
            )
            self.file_to_module = frozen_file_to_module
            self.module_similarity_provenance = {
                "source": "frozen_host_priority_plan",
                "host_priority_plan_sha256": stable_data_hash(
                    self._host_priority_plan
                ),
            }
        else:
            try:
                self.module_priorities, self.file_to_module = calculate_module_priorities(
                    self.software_profile,
                    self.vulnerability_profile,
                    module_similarity_config=self.module_similarity_config,
                    candidate_priority_enabled=self.candidate_priority_enabled,
                    embedding_provenance=self.module_similarity_provenance,
                )
            except TypeError as exc:
                if "unexpected keyword argument" not in str(exc):
                    raise
                self.module_priorities, self.file_to_module = calculate_module_priorities(
                    self.software_profile,
                    self.vulnerability_profile,
                )
        self.toolkit.set_software_profile(self.software_profile)
        if self.candidate_order_provenance:
            self.toolkit.set_file_enumeration_order(
                self.candidate_order_provenance["files"]
            )
        if not self.output_dir:
            return

        # Initialize memory
        self.memory = AgentMemoryManager(self.output_dir, self.llm_client)
        
        # Get CVE ID
        cve_id = getattr(self.vulnerability_profile, 'cve_id', '') or ''
        if hasattr(self.vulnerability_profile, 'to_dict'):
            cve_id = self.vulnerability_profile.to_dict().get('cve_id', cve_id)
        
        # Get repo info
        repo_name = self.repo_path.name
        target_commit = ""
        if hasattr(self.software_profile, 'version'):
            target_commit = self.software_profile.version or ""
        elif isinstance(self.software_profile, dict):
            basic = self.software_profile.get('basic_info', {})
            target_commit = basic.get('version', '')
        
        resumed = self.memory.initialize(
            target_repo=repo_name,
            target_commit=target_commit,
            cve_id=cve_id,
            module_priorities=self.module_priorities,
            file_to_module=self.file_to_module,
            critical_stop_max_priority=self.critical_stop_max_priority,
            scan_signature=self._build_scan_signature(),
            resume_enabled=self.memory_guidance_enabled,
        )
        
        # Connect memory to toolkit for status checking
        self.toolkit.set_memory_manager(self.memory)
        self._schedule_resumed = bool(resumed and not self.candidate_priority_enabled)
        if not self.candidate_priority_enabled:
            memory_payload = getattr(self.memory, "memory", None)
            self._schedule_window_events = list(
                getattr(memory_payload, "schedule_window_events", [])
            )
            if self._schedule_window_events:
                last_cursor = self._schedule_window_events[-1].get("cursor_index")
                if isinstance(last_cursor, bool) or not isinstance(last_cursor, int):
                    raise ValueError("durable schedule window cursor is invalid")
                self._schedule_window_cursor = last_cursor
            self._schedule_presented_page_indices = list(
                getattr(memory_payload, "schedule_presented_page_indices", [])
            )
            self._sync_schedule_window()
            self._schedule_resume_start_index = int(
                self._schedule_window_cursor or 0
            )
        
        if resumed:
            memory_payload = getattr(self.memory, "memory", None)
            persisted_findings = getattr(memory_payload, "findings", [])
            self.found_vulnerabilities = [
                dict(finding)
                for finding in persisted_findings
                if isinstance(finding, dict)
                and str(finding.get("source", "") or "").strip().lower()
                != "codeql"
            ]
            logger.info(
                "Resumed scan with %s pending files and %s persisted agent findings",
                len(self.memory.get_pending_files()),
                len(self.found_vulnerabilities),
            )

    def _schedule_status_snapshot(self) -> Dict[str, str]:
        """返回冻结 schedule 的结构有效私有 ledger。"""
        if self.candidate_priority_enabled:
            return {}
        scheduled_files = list(self.candidate_order_provenance.get("files", []))
        scheduled_set = set(scheduled_files)
        if self.memory is None:
            return {path: "pending" for path in scheduled_files}
        memory_payload = getattr(self.memory, "memory", None)
        statuses = getattr(memory_payload, "file_status", None)
        if not isinstance(statuses, dict) or set(statuses) != scheduled_set:
            raise ValueError(
                "frozen schedule ledger file_status keys do not match the schedule"
            )
        if any(status not in {"pending", "completed"} for status in statuses.values()):
            raise ValueError("frozen schedule ledger contains an invalid file status")
        completion_reasons = getattr(
            memory_payload,
            "file_completion_reasons",
            {},
        )
        if not isinstance(completion_reasons, dict) or any(
            path not in scheduled_set or statuses.get(path) != "completed"
            for path in completion_reasons
        ):
            raise ValueError("frozen schedule ledger completion reasons are invalid")
        findings = getattr(memory_payload, "findings", [])
        if not isinstance(findings, list):
            raise ValueError("frozen schedule ledger findings must be a list")
        finding_paths: List[str] = []
        for finding in findings:
            if not isinstance(finding, dict):
                raise ValueError("frozen schedule ledger finding is invalid")
            locators: List[str] = []
            for locator_name in ("file_path", "file"):
                if locator_name not in finding:
                    continue
                locator = str(finding.get(locator_name) or "").strip()
                if not locator:
                    raise ValueError("frozen schedule ledger finding path is invalid")
                locators.append(locator)
            if not locators or len(set(locators)) != 1:
                raise ValueError("frozen schedule ledger finding path is invalid")
            finding_path = locators[0]
            if finding_path not in scheduled_set:
                raise ValueError("frozen schedule ledger contains an off-schedule finding")
            finding_paths.append(finding_path)

        raw_touches = getattr(memory_payload, "coverage_first_touches", [])
        if not isinstance(raw_touches, list):
            raise ValueError("frozen schedule first-touch ledger must be a list")
        touches = [str(path).strip() for path in raw_touches]
        if (
            any(not path or path not in scheduled_set for path in touches)
            or len(set(touches)) != len(touches)
        ):
            raise ValueError("frozen schedule first-touch ledger is invalid")
        touch_set = set(touches)
        if not set(finding_paths).issubset(touch_set):
            raise ValueError("frozen schedule finding is missing a durable first touch")
        completed_paths = {
            path for path, status in statuses.items() if status == "completed"
        }
        if not completed_paths.issubset(touch_set):
            raise ValueError("frozen schedule completion is missing a durable first touch")

        raw_presented = getattr(
            memory_payload,
            "schedule_presented_page_indices",
            [],
        )
        if not isinstance(raw_presented, list) or any(
            isinstance(index, bool) or not isinstance(index, int) or index < 0
            for index in raw_presented
        ):
            raise ValueError("frozen schedule presented-page ledger is invalid")
        if raw_presented != list(range(len(raw_presented))):
            raise ValueError("frozen schedule presented pages must form a contiguous prefix")
        total_pages = (
            len(scheduled_files) + FROZEN_SCHEDULE_PAGE_SIZE - 1
        ) // FROZEN_SCHEDULE_PAGE_SIZE
        if any(index >= total_pages for index in raw_presented):
            raise ValueError("frozen schedule presented-page index is out of range")
        schedule_rank = {
            path: index for index, path in enumerate(scheduled_files)
        }
        touched_page_indices = set()
        previous_touch_page = -1
        for path in touches:
            page_index = schedule_rank[path] // FROZEN_SCHEDULE_PAGE_SIZE
            if page_index < previous_touch_page:
                raise ValueError(
                    "frozen schedule first-touch pages are not chronological"
                )
            previous_touch_page = page_index
            touched_page_indices.add(page_index)
        presented_set = set(raw_presented)
        if not touched_page_indices.issubset(presented_set):
            raise ValueError("frozen schedule touch belongs to an unpresented page")

        raw_events = getattr(memory_payload, "schedule_window_events", [])
        if not isinstance(raw_events, list):
            raise ValueError("frozen schedule window-event ledger must be a list")
        expected_event_keys = {
            "schema_version",
            "cursor_index",
            "window_end_index_exclusive",
            "window_file_count",
            "active_pending_file_count",
            "completed_window_count",
            "window_sha256",
        }
        expected_cursor = 0
        derived_cursor = self._derive_schedule_cursor(
            {path: str(statuses[path]) for path in scheduled_files}
        )
        event_cursors: List[int] = []
        for event in raw_events:
            if not isinstance(event, dict) or set(event) != expected_event_keys:
                raise ValueError("frozen schedule window event has an invalid shape")
            cursor = event.get("cursor_index")
            if (
                event.get("schema_version") != 1
                or isinstance(cursor, bool)
                or not isinstance(cursor, int)
                or cursor != expected_cursor
                or cursor > derived_cursor
            ):
                raise ValueError("frozen schedule window event cursor is invalid")
            window_files = scheduled_files[
                cursor : cursor + FROZEN_SCHEDULE_PAGE_SIZE
            ]
            window_end = cursor + len(window_files)
            active_count = event.get("active_pending_file_count")
            completed_count = event.get("completed_window_count")
            if (
                event.get("window_end_index_exclusive") != window_end
                or event.get("window_file_count") != len(window_files)
                or isinstance(active_count, bool)
                or not isinstance(active_count, int)
                or isinstance(completed_count, bool)
                or not isinstance(completed_count, int)
                or active_count != len(window_files)
                or completed_count != 0
                or event.get("window_sha256") != stable_data_hash(window_files)
            ):
                raise ValueError("frozen schedule window event content is invalid")
            event_cursors.append(cursor)
            expected_cursor = window_end
        real_page_starts = list(
            range(0, len(scheduled_files), FROZEN_SCHEDULE_PAGE_SIZE)
        )
        completed_page_count = sum(
            page_start < derived_cursor for page_start in real_page_starts
        )
        required_last_page = completed_page_count - 1
        required_last_page = max(
            required_last_page,
            max(touched_page_indices, default=-1),
            max(raw_presented, default=-1),
        )
        required_cursors = real_page_starts[: required_last_page + 1]
        allowed_cursor_sequences = [required_cursors]
        if (
            derived_cursor < len(scheduled_files)
            and derived_cursor in real_page_starts
            and derived_cursor not in required_cursors
        ):
            allowed_cursor_sequences.append(required_cursors + [derived_cursor])
        if event_cursors not in allowed_cursor_sequences:
            raise ValueError(
                "frozen schedule window events do not match the entered-page prefix"
            )
        return {path: str(statuses[path]) for path in scheduled_files}

    def _derive_schedule_cursor(self, statuses: Dict[str, str]) -> int:
        """推导首个未完成页并拒绝未来页完成状态。"""
        scheduled_files = list(self.candidate_order_provenance.get("files", []))
        cursor = 0
        while cursor < len(scheduled_files):
            end = min(cursor + FROZEN_SCHEDULE_PAGE_SIZE, len(scheduled_files))
            page_files = scheduled_files[cursor:end]
            if all(statuses[path] == "completed" for path in page_files):
                cursor = end
                continue
            if any(
                statuses[path] == "completed"
                for path in scheduled_files[end:]
            ):
                raise ValueError(
                    "frozen schedule ledger completes a future page before the active page"
                )
            break
        return cursor

    def _sync_schedule_window(self) -> Dict[str, Any]:
        """从私有 ledger 刷新仅含待处理项的 allowlist。"""
        if self.candidate_priority_enabled:
            return {}
        scheduled_files = list(self.candidate_order_provenance.get("files", []))
        statuses = self._schedule_status_snapshot()
        cursor = self._derive_schedule_cursor(statuses)
        completed_files = [
            path for path in scheduled_files if statuses[path] == "completed"
        ]
        page = build_schedule_page(
            scheduled_files,
            cursor=cursor,
            completed_files=completed_files,
        )
        full_page_files = scheduled_files[
            cursor : cursor + FROZEN_SCHEDULE_PAGE_SIZE
        ]
        prior_cursor = self._schedule_window_cursor
        if prior_cursor is not None and cursor < prior_cursor:
            raise ValueError("frozen schedule cursor cannot move backwards")
        self.toolkit.set_active_file_window(
            full_page_files,
            cursor=cursor,
            completed_files=[
                full_page_files[offset]
                for offset in page["completed_window_offsets"]
            ],
            page_size=FROZEN_SCHEDULE_PAGE_SIZE,
            page_algorithm=FROZEN_SCHEDULE_PAGE_ALGORITHM,
        )
        self._schedule_window_cursor = cursor
        self._schedule_window_page = page
        if prior_cursor != cursor and full_page_files:
            event = {
                "schema_version": 1,
                "cursor_index": cursor,
                "window_end_index_exclusive": page[
                    "window_end_index_exclusive"
                ],
                "window_file_count": page["window_file_count"],
                "active_pending_file_count": page[
                    "active_pending_file_count"
                ],
                "completed_window_count": len(
                    page["completed_window_offsets"]
                ),
                "window_sha256": stable_data_hash(full_page_files),
            }
            record_event = getattr(
                self.memory,
                "record_schedule_window_event",
                None,
            )
            if callable(record_event):
                record_event(event)
                self._schedule_window_events = list(
                    self.memory.memory.schedule_window_events
                )
            else:
                self._schedule_window_events.append(event)
        return dict(page)

    def _record_presented_schedule_page(self) -> None:
        """仅在含页 LLM 请求成功后记录该页。"""
        if self.candidate_priority_enabled:
            return
        if self._schedule_window_cursor is None or not self._schedule_window_page:
            raise ValueError("frozen schedule page is unavailable for presentation")
        if not self._schedule_window_page.get("files"):
            raise ValueError("terminal frozen schedule state cannot be presented")
        page_index = self._schedule_window_cursor // FROZEN_SCHEDULE_PAGE_SIZE
        record_page = getattr(
            self.memory,
            "record_schedule_presented_page",
            None,
        )
        if callable(record_page):
            record_page(page_index)
            self._schedule_presented_page_indices = list(
                self.memory.memory.schedule_presented_page_indices
            )
        elif page_index not in self._schedule_presented_page_indices:
            expected = len(self._schedule_presented_page_indices)
            if page_index != expected:
                raise ValueError("presented schedule pages must form a contiguous prefix")
            self._schedule_presented_page_indices.append(page_index)

    def _schedule_is_complete(self) -> bool:
        if self.candidate_priority_enabled:
            return False
        statuses = self._schedule_status_snapshot()
        return bool(statuses) and all(
            status == "completed" for status in statuses.values()
        )

    def _build_scan_signature(self) -> Dict[str, Any]:
        """Build the scan-shaping signature used for resume compatibility checks."""
        llm_config = getattr(self.llm_client, "config", None)
        languages = self.scan_languages
        if not languages and hasattr(self.toolkit, "_languages"):
            toolkit_languages = getattr(self.toolkit, "_languages", [])
            if isinstance(toolkit_languages, list):
                languages = toolkit_languages
        codeql_database_names = self.codeql_database_names
        if not codeql_database_names and hasattr(self.toolkit, "_codeql_database_names"):
            toolkit_codeql_database_names = getattr(self.toolkit, "_codeql_database_names", {})
            if isinstance(toolkit_codeql_database_names, dict):
                codeql_database_names = toolkit_codeql_database_names
        normalized_codeql_database_names = {}
        for language, db_name in codeql_database_names.items():
            language_key = str(language).strip().lower()
            db_name_value = str(db_name).strip()
            if language_key and db_name_value:
                normalized_codeql_database_names[language_key] = db_name_value

        project_root = Path(__file__).resolve().parents[2]
        module_similarity_model = str(
            self.module_similarity_config.get("model_name", "")
        ).strip()
        observed_module_similarity = observed_module_similarity_metadata(
            self.module_similarity_config,
            embedding_model_artifact_signature(
                module_similarity_model or None
            ),
        )
        return {
            "llm": {
                "provider": getattr(llm_config, "provider", ""),
                "model": getattr(llm_config, "model", ""),
                "model_revision": self.model_revision,
                "model_revision_attestation": dict(
                    self.model_revision_attestation_binding
                ),
                "endpoint_snapshot": dict(self.endpoint_snapshot),
                "endpoint_snapshot_sha256": self.endpoint_snapshot_sha256,
                "decoding_config_requested": dict(
                    self.decoding_config_requested
                ),
                "decoding_config_requested_sha256": (
                    self.decoding_config_requested_sha256
                ),
                "decoding_config_effective": dict(
                    self.decoding_config_effective
                ),
                "decoding_config_effective_sha256": (
                    self.decoding_config_effective_sha256
                ),
                "base_url": getattr(llm_config, "base_url", ""),
                "temperature": getattr(llm_config, "temperature", None),
                "top_p": getattr(llm_config, "top_p", None),
                "max_tokens": getattr(llm_config, "max_tokens", None),
                "enable_thinking": getattr(llm_config, "enable_thinking", None),
                "reasoning_effort": getattr(
                    llm_config,
                    "reasoning_effort",
                    None,
                ),
                "service_tier": getattr(llm_config, "service_tier", None),
                "fallback_on_retry_exhausted": bool(
                    getattr(
                        llm_config,
                        "fallback_on_retry_exhausted",
                        False,
                    )
                ),
                "exact_decoding_enforced": bool(
                    getattr(
                        llm_config,
                        "enforce_exact_decoding",
                        False,
                    )
                ),
            },
            "scan_config": {
                "max_iterations": int(self.max_iterations),
                "stop_when_critical_complete": bool(self.stop_when_critical_complete),
                "critical_stop_mode": self.critical_stop_mode,
                "critical_stop_max_priority": self.critical_stop_max_priority,
                "require_full_universe_completion": (
                    self.require_full_universe_completion
                ),
                "scan_languages": sorted({
                    str(lang).strip().lower()
                    for lang in languages
                    if str(lang).strip()
                }),
                "codeql_database_names": normalized_codeql_database_names,
                "shared_public_memory": {
                    "enabled": bool(self.shared_public_memory_scope.get("enabled", False)),
                    "root_hash": str(self.shared_public_memory_scope.get("root_hash", "")).strip(),
                    "scope_key": str(self.shared_public_memory_scope.get("scope_key", "")).strip(),
                    "state_hash": str(self.shared_public_memory_scope.get("state_hash", "")).strip(),
                },
                "module_similarity": observed_module_similarity,
                "module_similarity_byte_binding": (
                    module_similarity_byte_binding()
                ),
                "ablations": dict(self.ablation_config),
                "model_revision_attestation": dict(
                    self.model_revision_attestation_binding
                ),
                "endpoint_snapshot": dict(self.endpoint_snapshot),
                "endpoint_snapshot_sha256": self.endpoint_snapshot_sha256,
                "decoding_config_requested": dict(
                    self.decoding_config_requested
                ),
                "decoding_config_requested_sha256": (
                    self.decoding_config_requested_sha256
                ),
                "decoding_config_effective": dict(
                    self.decoding_config_effective
                ),
                "decoding_config_effective_sha256": (
                    self.decoding_config_effective_sha256
                ),
                "reference_profile_hash": stable_data_hash(
                    self.vulnerability_profile.to_dict()
                    if hasattr(self.vulnerability_profile, "to_dict")
                    else self.vulnerability_profile
                ),
                "model_visible_input_projection": dict(
                    self.target_path_projection.get("provenance", {})
                ),
                "model_visible_input_runtime_projection": dict(
                    self.model_visible_input_runtime_projection
                ),
                "model_input_stage_hashes": dict(
                    self.target_path_projection.get("provenance", {}).get(
                        "model_input_stage_hashes",
                        {},
                    )
                ),
                "candidate_file_schedule": dict(self.candidate_order_provenance),
            },
            "config_hashes": consumed_scanner_config_hashes(),
            "source_hashes": hash_python_source_tree(project_root),
        }

    def _critical_scope_label(self) -> str:
        """Return the human-readable label for the configured critical scope."""
        return "priority-1" if self.critical_stop_max_priority == 1 else "priority-1/2"

    def _is_full_universe_complete(self) -> bool:
        """返回全部冻结主机任务是否已持久完成。"""
        if not self.candidate_priority_enabled:
            return self._schedule_is_complete()
        if not self._host_priority_plan or self.memory is None:
            return False
        expected_files = set(self.file_to_module)
        statuses = getattr(self.memory.memory, "file_status", None)
        return bool(expected_files) and isinstance(statuses, dict) and (
            set(statuses) == expected_files
            and all(statuses[path] == "completed" for path in expected_files)
        )

    def _is_critical_complete(self) -> bool:
        """仅允许非空 critical scope 进入完成状态。"""
        if not self.memory:
            return False
        progress_fn = getattr(self.memory, "get_progress", None)
        if not callable(progress_fn):
            return False
        progress = progress_fn()
        if not isinstance(progress, dict):
            return False
        priority_1 = progress.get("priority_1", {})
        priority_2 = progress.get("priority_2", {})
        critical_total = int(
            priority_1.get("total", 0)
            if isinstance(priority_1, dict)
            else 0
        )
        if self.critical_stop_max_priority >= 2:
            critical_total += int(
                priority_2.get("total", 0)
                if isinstance(priority_2, dict)
                else 0
            )
        if critical_total <= 0:
            return False
        check_fn = getattr(self.memory, "is_critical_complete", None)
        if not callable(check_fn):
            return False
        try:
            return bool(check_fn(max_priority=self.critical_stop_max_priority))
        except TypeError:
            return bool(check_fn())

    def _clear_reasoning_content(self) -> List[Dict[str, Any]]:
        return clear_reasoning_content(self.conversation_history)

    def _commit_messages(self, messages: List[Dict[str, Any]]) -> None:
        self.conversation_history += messages[len(self.conversation_history):]

    def _truncate_tool_content_for_model(
        self,
        content: str,
        limit: int = 10000,
    ) -> str:
        """仅在完整行边界截断 schedule 输出。"""
        text = str(content)
        text = str(self._project_scheduled_model_value(text))
        if len(text) <= limit:
            return text
        suffix = "\n... [truncated at complete line boundary]"
        if not self.candidate_order_provenance:
            return text[:limit] + "\n... [truncated]"
        budget = max(0, limit - len(suffix))
        retained_lines = []
        retained_length = 0
        for line in text.splitlines(keepends=True):
            if retained_length + len(line) > budget:
                break
            retained_lines.append(line)
            retained_length += len(line)
        return "".join(retained_lines).rstrip("\n") + suffix

    def _mark_current_turn_start(self) -> None:
        self._current_turn_start_index = len(self.conversation_history)

    def _estimate_request_input_tokens(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
    ) -> int:
        return estimate_serialized_tokens(
            {
                "messages": messages,
                "tools": tools or [],
            }
        )

    def _get_last_request_input_tokens(self) -> int:
        return max(0, to_int(self.llm_client.get_last_request_input_tokens()))

    def _get_last_request_output_tokens(self) -> int:
        return max(0, to_int(self.llm_client.get_last_request_output_tokens()))

    def _get_last_request_context_limit(self) -> int:
        return max(0, to_int(self.llm_client.get_last_request_context_limit()))

    def _get_effective_context_limit(self) -> int:
        context_limit = self._get_last_request_context_limit()
        if context_limit > 0:
            return context_limit
        llm_config = getattr(self.llm_client, "config", None)
        if llm_config is not None:
            context_limit = to_int(getattr(llm_config, "context_limit", 0))
            if context_limit > 0:
                return context_limit
        return max(0, to_int(getattr(self.llm_client, "context_limit", 0)))

    def _needs_preflight_compaction(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        planned_output_tokens: int = 0,
        context_limit: int = 0,
    ) -> bool:
        if context_limit <= 0 or planned_output_tokens <= 0:
            return False
        estimated_input_tokens = self._estimate_request_input_tokens(messages, tools)
        return estimated_input_tokens + planned_output_tokens > int(_PREFLIGHT_CONTEXT_THRESHOLD * context_limit)

    def _compact_previous_history_locally(self) -> bool:
        if len(self.conversation_history) <= 2:
            return False
        latest_message = self.conversation_history[-1] if self.conversation_history else None
        has_current_user = isinstance(latest_message, dict) and latest_message.get("role") == "user"
        history_end = len(self.conversation_history) - 1 if has_current_user else len(self.conversation_history)
        prior_messages = self.conversation_history[1:history_end]
        if not prior_messages:
            return False

        assistant_summary_count = sum(
            1
            for message in prior_messages
            if isinstance(message, dict) and message.get("role") == "assistant"
        )
        compacted_summary = "Previous scan context was compacted locally before this query."
        if self.memory_guidance_enabled:
            compacted_summary += (
                " Use the current progress snapshot and memory-backed tools as the source of truth."
            )
        if assistant_summary_count > 0:
            compacted_summary += f" Prior assistant summaries compacted: {assistant_summary_count}."
        else:
            compacted_summary += f" Prior messages compacted: {len(prior_messages)}."

        new_history = [self.conversation_history[0], {"role": "assistant", "content": compacted_summary}]
        if has_current_user:
            new_history.append(latest_message)
        self.conversation_history = new_history
        return True

    def _compact_current_user_message(self, iteration: int) -> bool:
        if not self.conversation_history:
            return False
        latest_message = self.conversation_history[-1]
        if not isinstance(latest_message, dict) or latest_message.get("role") != "user":
            return False
        compact_message = self._get_user_message(iteration, compact=True)
        if compact_message == latest_message.get("content", ""):
            return False
        self.conversation_history[-1] = {"role": "user", "content": compact_message}
        return True

    def _prepare_preflight_messages(
        self,
        iteration: int,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
    ) -> Tuple[List[Dict[str, Any]], bool]:
        context_limit = self._get_effective_context_limit()
        planned_output_tokens = max(0, to_int(self.max_tokens))
        if not self._needs_preflight_compaction(
            messages,
            tools,
            planned_output_tokens=planned_output_tokens,
            context_limit=context_limit,
        ):
            return messages, False

        if self.verbose:
            logger.info(
                "Preflight compaction triggered before query: estimated_input_tokens=%s planned_output_tokens=%s context_limit=%s",
                self._estimate_request_input_tokens(messages, tools),
                planned_output_tokens,
                context_limit,
            )

        original_history_len = len(self.conversation_history)
        current_turn_additions = messages[original_history_len:]

        compacted_history = self._compact_previous_history_locally()
        if compacted_history:
            messages = self._clear_reasoning_content() + current_turn_additions
            self._mark_current_turn_start()

        if self._needs_preflight_compaction(
            messages,
            tools,
            planned_output_tokens=planned_output_tokens,
            context_limit=context_limit,
        ):
            compacted_user = self._compact_current_user_message(iteration)
            if compacted_user:
                messages = self._clear_reasoning_content() + current_turn_additions
                self._mark_current_turn_start()

        if self._needs_preflight_compaction(
            messages,
            tools,
            planned_output_tokens=planned_output_tokens,
            context_limit=context_limit,
        ):
            logger.warning(
                "Skipping LLM query because the preflight request budget remains above %.0f%% of the context limit "
                "after local compaction",
                _PREFLIGHT_CONTEXT_THRESHOLD * 100,
            )
            return messages, True

        return messages, False

    def _is_near_context_limit(
        self,
        input_tokens: int,
        context_limit: int,
        reserved_output_tokens: int = 0,
    ) -> bool:
        if input_tokens <= 0 or context_limit <= 0:
            return False

        reserved_output_tokens = max(0, reserved_output_tokens)
        projected_total = input_tokens + min(reserved_output_tokens, context_limit)
        threshold = int(0.8 * context_limit)
        return projected_total >= threshold or projected_total >= context_limit

    @staticmethod
    def _is_context_limit_error(exc: Exception) -> bool:
        message = str(exc).lower()
        return any(pattern in message for pattern in _CONTEXT_LIMIT_ERROR_PATTERNS)

    @staticmethod
    def _parse_tool_arguments(
        raw_arguments: Any,
        parameter_schema: Optional[Dict[str, Any]] = None,
        provider: Optional[str] = None,
    ) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        """Normalize one tool-call argument payload into a JSON object."""
        return normalize_tool_arguments(
            raw_arguments,
            parameters_schema=parameter_schema,
            provider=provider,
        )

    def _run_turn(self, iteration: int) -> int:
        sub_turn = 1
        messages = self._clear_reasoning_content()
        self._mark_current_turn_start()
        turn_schedule_cursor = self._schedule_window_cursor
        while True:
            if not self.candidate_priority_enabled:
                self._sync_schedule_window()
                if self._schedule_window_cursor != turn_schedule_cursor:
                    self._commit_messages(messages)
                    return sub_turn
            tools = self.toolkit.get_available_tools()
            tools = self._project_scheduled_model_value(tools)
            tool_parameter_schemas = {
                tool_definition.get("function", {}).get("name"): tool_definition.get("function", {}).get("parameters")
                for tool_definition in tools
                if isinstance(tool_definition, dict) and isinstance(tool_definition.get("function"), dict)
            }
            llm_provider = getattr(getattr(self.llm_client, "config", None), "provider", None)
            messages, skip_query = self._prepare_preflight_messages(iteration, messages, tools)
            if skip_query:
                self._commit_messages(messages)
                return sub_turn
            try:
                message = self.llm_client.chat(
                    messages,
                    tools=tools,
                    tool_choice="auto",
                    temperature=self.temperature,
                    max_tokens=self.max_tokens,
                )
            except LLMResponseIdentityError:
                raise
            except Exception as exc:  # pylint: disable=broad-except
                if self._is_context_limit_error(exc):
                    if bool(
                        getattr(
                            getattr(self.llm_client, "config", None),
                            "enforce_exact_decoding",
                            False,
                        )
                    ):
                        logger.error(
                            "Exact-decoding LLM request exceeded the context limit"
                        )
                        raise
                    logger.warning(
                        "LLM request hit the context limit; ending the current turn and rolling conversation forward"
                    )
                    self._commit_messages(messages)
                    return sub_turn
                logger.error("LLM call failed: %s", exc)
                raise
            self._record_presented_schedule_page()
            reasoning_content = getattr(message, "reasoning_content", None)
            content = getattr(message, "content", None)
            tool_calls = getattr(message, "tool_calls", None)
            if content is None and tool_calls is None:
                logger.error("LLM returned no content and no tool calls.")
                self._commit_messages(messages)
                return sub_turn
            messages.append(message)
            request_input_tokens = self._get_last_request_input_tokens()
            request_output_tokens = self._get_last_request_output_tokens()
            request_context_limit = self._get_last_request_context_limit()

            if self.verbose:
                logger.info(
                    f"[Iteration {iteration + 1}.{sub_turn}]\n"
                    f"- API input_tokens: {request_input_tokens}\n"
                    f"- API output_tokens: {request_output_tokens}\n"
                    f"- API context_limit: {request_context_limit}\n"
                    f"- {reasoning_content=}\n"
                    f"- {content=}\n"
                )
                if tool_calls:
                    logger.info(f"- {tool_calls[0].function.name=}\n- {tool_calls[0].function.arguments=}\n")

            if not tool_calls:
                if self._is_completion_signal(content):
                    logger.debug("LLM signaled completion.")
                self._commit_messages(messages)
                return sub_turn
            if hasattr(self.vulnerability_profile, "to_dict"):
                vulnerability_dict = self.vulnerability_profile.to_dict()
            elif isinstance(self.vulnerability_profile, dict):
                vulnerability_dict = self.vulnerability_profile
            else:
                vulnerability_dict = {}

            # A completion call retires its file from the active schedule window.
            # Execute it after every other call from the same assistant response
            # so a model-emitted mark-before-report order cannot suppress a valid
            # report or a final evidence read for that file.
            ordered_tool_calls = [
                tool
                for tool in tool_calls
                if tool.function.name != "mark_file_completed"
            ]
            ordered_tool_calls.extend(
                tool
                for tool in tool_calls
                if tool.function.name == "mark_file_completed"
            )
            for tool in ordered_tool_calls:
                tool_name = tool.function.name
                parameters, argument_error = self._parse_tool_arguments(
                    tool.function.arguments,
                    parameter_schema=tool_parameter_schemas.get(tool_name),
                    provider=llm_provider,
                )
                if argument_error:
                    logger.error(argument_error)
                    tool_result_content = f"Error: {argument_error}"
                    tool_result_content = self._truncate_tool_content_for_model(
                        tool_result_content
                    )
                    messages.append({"role": "tool", "tool_call_id": tool.id, "content": tool_result_content})
                    continue
                if self.verbose:
                    logger.debug(
                        f"  [TOOL] {tool_name}: {json.dumps(parameters, ensure_ascii=False)[:500]}..."
                    )
                result = self.toolkit.execute_tool(tool_name, parameters)
                if self.verbose:
                    logger.debug(f"  [TOOL RESULT] {result}...")
                
                if tool_name == "report_vulnerability" and result.success:
                    vuln_report = json.loads(result.content)
                    sink_features = vulnerability_dict.get("sink_features", {})
                    raw_known_type = ""
                    if isinstance(sink_features, dict):
                        raw_known_type = str(sink_features.get("type", "") or "")
                    normalized_known_type = raw_known_type.strip().lower().replace("-", "_").replace(" ", "_")
                    normalized_reported_type = str(
                        vuln_report.get("vulnerability_type", "") or ""
                    ).strip().lower().replace("-", "_").replace(" ", "_")
                    type_aliases = {
                        "cmd_injection": "command_injection",
                        "os_command_injection": "command_injection",
                        "unsafe_deserialization": "deserialization",
                        "directory_traversal": "path_traversal",
                        "server_side_request_forgery": "ssrf",
                    }
                    normalized_known_type = type_aliases.get(
                        normalized_known_type,
                        normalized_known_type,
                    )
                    normalized_reported_type = type_aliases.get(
                        normalized_reported_type,
                        normalized_reported_type,
                    )
                    if (
                        self.verifier_enabled
                        and
                        normalized_known_type
                        and normalized_reported_type
                        and normalized_reported_type != normalized_known_type
                    ):
                        tool_result_content = (
                            "Error: report_vulnerability must keep the same vulnerability type as "
                            f"the known vulnerability ({normalized_known_type}); got "
                            f"{vuln_report.get('vulnerability_type', 'unknown')}."
                        )
                        tool_result_content = self._truncate_tool_content_for_model(
                            tool_result_content
                        )
                        messages.append(
                            {"role": "tool", "tool_call_id": tool.id, "content": tool_result_content}
                        )
                        continue
                    # Check for duplicate before adding
                    is_duplicate = False
                    if self.memory:
                        is_duplicate = not self.memory.add_finding(vuln_report)
                    
                    if is_duplicate:
                        if self.verbose:
                            logger.info(
                                f"  [DUPLICATE] Skipping already reported: {vuln_report.get('file_path', 'unknown')} - {vuln_report.get('vulnerability_type', 'unknown')}"
                            )
                        # Modify result to indicate duplicate
                        tool_result_content = (
                            "Note: This vulnerability was already reported. Do not report duplicates."
                            if self.memory_guidance_enabled
                            else result.content
                        )
                    else:
                        self.found_vulnerabilities.append(vuln_report)
                        if self.verbose:
                            logger.warning(
                                f"  [VULN FOUND] {vuln_report.get('file_path', 'unknown')} - {vuln_report.get('vulnerability_type', 'unknown')}"
                            )
                        tool_result_content = result.content
                else:
                    tool_result_content = result.content if result.success else f"Error: {result.error}"
                    
                tool_result_content = self._truncate_tool_content_for_model(
                    tool_result_content
                )
                messages.append({"role": "tool", "tool_call_id": tool.id, "content": tool_result_content})

            if self._is_near_context_limit(
                request_input_tokens,
                request_context_limit,
                # Use actual output usage from the last request. Reserving the full configured
                # max_tokens budget here can prematurely end every turn for providers whose
                # max_tokens equals the context window.
                reserved_output_tokens=request_output_tokens,
            ):
                if self.verbose:
                    logger.info(
                        "Stopping current turn because the last successful request is already near the model context limit"
                    )
                self._commit_messages(messages)
                return sub_turn
            if sub_turn >= self.max_sub_turns:
                logger.warning(
                    "Stopping current turn after reaching max_sub_turns=%s",
                    self.max_sub_turns,
                )
                self._commit_messages(messages)
                return sub_turn
            sub_turn += 1

    def _is_completion_signal(self, content: Optional[str]) -> bool:
        """Check whether assistant response is an explicit completion signal."""
        if not content:
            return False
        normalized = content.lower()
        if "analysis complete" in normalized:
            return True
        parsed = extract_json_from_text(
            response_text=content,
            required_keys=["analysis_complete", "summary"],
            validator=lambda payload: isinstance(payload.get("analysis_complete"), bool),
            prefer_last=True,
        )
        return bool(parsed and parsed.get("analysis_complete"))

    def _extract_complementary_summary(self, summarized: Dict[str, Any]) -> str:
        """Extract only information complementary to _get_user_message.
        
        _get_user_message provides:
        - progress_info: scan progress statistics
        - findings: already reported vulnerabilities (file, type, confidence)
        - scanned_files: already scanned file paths
        
        This method extracts only:
        - reasoning: motivation, analysis logic, conclusions
        - shared_memory_hits: reusable shared-memory queries or observations
        - rejected_hypotheses: dead ends or false positives worth avoiding
        - next_best_queries: focused follow-up searches
        - evidence_gaps: missing proof blocking confirmation
        - files_completed_this_iteration: newly completed files
        - summary: one-sentence summary
        """
        content = summarized.get("content", summarized)
        if not isinstance(content, dict):
            # Fallback if content is not a dict
            return str(content)
        
        complementary_parts = []
        
        # 1. Summary - concise overview
        summary = content.get("summary", "")
        if summary:
            complementary_parts.append(f"**Summary**: {summary}")
        
        # 2. Reasoning - the analysis logic (not tracked elsewhere)
        reasoning = content.get("reasoning", {})
        if reasoning:
            reasoning_lines = []
            if reasoning.get("motivation"):
                reasoning_lines.append(f"- Motivation: {reasoning['motivation']}")
            if reasoning.get("analysis"):
                reasoning_lines.append(f"- Analysis: {reasoning['analysis']}")
            if reasoning.get("conclusions"):
                conclusions = reasoning["conclusions"]
                if isinstance(conclusions, list):
                    reasoning_lines.append("- Conclusions: " + "; ".join(conclusions))
                else:
                    reasoning_lines.append(f"- Conclusions: {conclusions}")
            if reasoning_lines:
                complementary_parts.append("**Reasoning**:\n" + "\n".join(reasoning_lines))

        rejected_hypotheses = content.get("rejected_hypotheses", [])
        if not rejected_hypotheses:
            for attempt in content.get("failed_attempts", [])[:5]:
                if isinstance(attempt, dict):
                    what = str(attempt.get("what", "")).strip()
                    why = str(attempt.get("why_failed", "")).strip()
                    if what and why:
                        rejected_hypotheses.append(f"{what}: {why}")
                    elif what:
                        rejected_hypotheses.append(what)
                elif isinstance(attempt, str) and attempt.strip():
                    rejected_hypotheses.append(attempt.strip())

        next_best_queries = content.get(
            "next_best_queries",
            content.get("next_step_insights", content.get("next_steps", [])),
        )
        list_sections = [
            ("Shared Memory Hits", content.get("shared_memory_hits", [])),
            ("Rejected Hypotheses", rejected_hypotheses),
            ("Next Best Queries", next_best_queries),
            ("Evidence Gaps", content.get("evidence_gaps", [])),
            (
                "Files Completed This Iteration",
                content.get("files_completed_this_iteration", []),
            ),
        ]
        for title, values in list_sections:
            if isinstance(values, list):
                lines = [
                    f"- {item}"
                    for item in values[:5]
                    if isinstance(item, str) and item.strip()
                ]
            elif isinstance(values, str) and values.strip():
                lines = [f"- {values.strip()}"]
            else:
                lines = []
            if lines:
                complementary_parts.append(f"**{title}**:\n" + "\n".join(lines))
        
        if not complementary_parts:
            return (
                "Iteration completed. Check progress for details."
                if self.memory_guidance_enabled
                else "Iteration completed."
            )
        
        return "\n\n".join(complementary_parts)


    def _project_scheduled_model_value(
        self,
        value: Any,
        *,
        preserve_active: bool = True,
    ) -> Any:
        """在模型可见边界应用规范 schedule matcher。"""
        if self.candidate_priority_enabled:
            return value
        projector = getattr(self.toolkit, "sanitize_scheduled_model_value", None)
        if not callable(projector):
            raise ValueError("Scheduled model-payload sanitizer is unavailable")
        return projector(value, preserve_active=preserve_active)

    def _get_user_message(self, iteration: int, compact: bool = False) -> str:
        schedule_page = (
            self._sync_schedule_window()
            if not self.candidate_priority_enabled
            else None
        )
        shared_observation_count = (
            0
            if not self.memory_guidance_enabled
            else max(
                0,
                to_int(self.shared_public_memory_scope.get("observation_count", 0)),
            )
        )
        vulnerability_payload = self._model_visible_vulnerability_profile
        if isinstance(vulnerability_payload, dict):
            vulnerability_dict: Dict[str, Any] = vulnerability_payload
        else:
            vulnerability_dict = {}
        structured_guidance = {
            field_name: field_value
            for field_name, field_value in {
                "query_terms": vulnerability_dict.get("query_terms", []),
                "dangerous_apis": vulnerability_dict.get("dangerous_apis", []),
                "source_indicators": vulnerability_dict.get("source_indicators", []),
                "sink_indicators": vulnerability_dict.get("sink_indicators", []),
                "variant_hypotheses": vulnerability_dict.get("variant_hypotheses", []),
                "negative_constraints": vulnerability_dict.get("negative_constraints", []),
                "likely_false_positive_patterns": vulnerability_dict.get(
                    "likely_false_positive_patterns", []
                ),
                "scan_start_points": vulnerability_dict.get("scan_start_points", []),
                "open_questions": vulnerability_dict.get("open_questions", []),
                "assumptions": vulnerability_dict.get("assumptions", []),
            }.items()
            if field_value
        }
        if self.ablation_config["reference_semantics"]:
            structured_guidance = {}
        if not self.candidate_priority_enabled:
            structured_guidance.pop("scan_start_points", None)
            guidance_scope = (
                "shared-memory queries, frozen-schedule files, and search patterns"
                if self.memory_guidance_enabled
                else "frozen-schedule files and search patterns"
            )
        else:
            guidance_scope = (
                "shared-memory queries, modules, and search patterns"
                if self.memory_guidance_enabled
                else "modules and search patterns"
            )
        guidance_prefix = ""
        if structured_guidance and iteration == 0:
            guidance_prefix = (
                "## Structured Vulnerability Guidance\n"
                f"Use these concrete anchors when choosing {guidance_scope}.\n"
                f"{json.dumps(structured_guidance, indent=2, ensure_ascii=False)}\n\n"
            )
        if self.require_full_universe_completion:
            guidance_prefix += (
                "## Full-Universe Completion Contract\n"
                "The host accepts completion only after every frozen host-plan "
                "work item is durably marked completed. The iteration limit remains "
                "a safety ceiling and may terminate this run as partial.\n\n"
            )
        if iteration == 0:
            initial_kwargs = {
                "critical_stop_max_priority": self.critical_stop_max_priority,
                "shared_observation_count": shared_observation_count,
            }
            if not self.memory_guidance_enabled:
                initial_kwargs["memory_guidance_enabled"] = False
            if self.ablation_config["reference_semantics"]:
                initial_kwargs["reference_semantics_enabled"] = False
            if self.candidate_order_provenance:
                initial_kwargs["candidate_file_order"] = list(
                    self.candidate_order_provenance.get("files", [])
                )
                initial_kwargs["candidate_schedule_provenance"] = dict(
                    self.candidate_order_provenance
                )
            if not self.candidate_priority_enabled:
                initial_kwargs["candidate_priority_enabled"] = False
                initial_kwargs["candidate_schedule_page"] = schedule_page
            message = guidance_prefix + build_initial_user_message(
                self._model_visible_software_profile,
                self.module_priorities,
                **initial_kwargs,
            )
            return self._project_scheduled_model_value(message)
        # Include progress info and already-scanned context for subsequent iterations
        progress_info = ""
        scanned_files = []
        findings = []
        pending: List[str] = []
        
        if self.memory and self.memory_guidance_enabled:
            pending = self.memory.get_pending_files(
                max_priority=self.critical_stop_max_priority
            )
            if not self.candidate_priority_enabled:
                scheduled_files = list(
                    self.candidate_order_provenance.get("files", [])
                )
                pending_set = {str(path) for path in pending}
                pending = [
                    path for path in scheduled_files if path in pending_set
                ]
                progress = self.memory.get_progress()
                progress_info = (
                    f"{progress['completed']}/{progress['total_files']} "
                    f"scheduled files scanned, {progress['findings']} findings."
                )
            else:
                progress_info = self.memory.format_progress_info()
                if self.critical_stop_max_priority == 1 and pending:
                    progress_info = (
                        "Critical scope: priority-1 modules only "
                        "(directly affected or embedding-similar). "
                        "Do not spend turns on RELATED modules until all "
                        "priority-1 files are complete.\n"
                        f"{progress_info}"
                    )
            if pending and self.candidate_priority_enabled:
                if compact:
                    progress_info += f" Pending: {len(pending)} files remain."
                    progress_info += (
                        "\nUse check_file_status to inspect specific files as needed."
                    )
                else:
                    progress_info += f" Pending: {pending[:50]}"
                    progress_info += (
                        "\nUse check_file_status to get the status of specific files."
                    )
            # Get already scanned files and findings to avoid duplicates
            scanned_files = self.memory.get_scanned_files()
            findings = self.memory.get_findings_summary()
        pending_module_priorities = {
            self.module_priorities.get(self.file_to_module.get(file_path, ""), 3)
            for file_path in pending
        }
        if pending_module_priorities:
            has_priority_one = 1 in pending_module_priorities
            has_related = 2 in pending_module_priorities
        elif self.memory and self.memory_guidance_enabled:
            has_priority_one = False
            has_related = False
        else:
            has_priority_one = any(priority == 1 for priority in self.module_priorities.values())
            has_related = any(priority == 2 for priority in self.module_priorities.values())
        
        intermediate_kwargs = {
            "scanned_files": scanned_files,
            "findings": findings,
            "progress_info": progress_info,
            "critical_stop_max_priority": self.critical_stop_max_priority,
            "shared_observation_count": shared_observation_count,
            "has_priority_one": has_priority_one,
            "has_related": has_related,
        }
        if not self.memory_guidance_enabled:
            intermediate_kwargs["memory_guidance_enabled"] = False
        if self.ablation_config["reference_semantics"]:
            intermediate_kwargs["reference_semantics_enabled"] = False
        if self.candidate_order_provenance:
            intermediate_kwargs["candidate_file_order"] = list(
                self.candidate_order_provenance.get("files", [])
            )
            intermediate_kwargs["candidate_schedule_provenance"] = dict(
                self.candidate_order_provenance
            )
        if not self.candidate_priority_enabled:
            intermediate_kwargs["candidate_priority_enabled"] = False
            intermediate_kwargs["pending_files"] = pending
            intermediate_kwargs["candidate_schedule_page"] = schedule_page
        if compact:
            intermediate_kwargs["compact"] = True

        message = guidance_prefix + build_intermediate_user_message(
            **intermediate_kwargs,
        )
        return self._project_scheduled_model_value(message)

    def _finalize_iteration_progress(self, iteration: int) -> None:
        """Clear per-iteration read tracking without changing coverage state."""
        _ = iteration
        consume_tracked_files = getattr(self.toolkit, "consume_tracked_files", None)
        if not callable(consume_tracked_files):
            return
        consume_tracked_files()

    def _build_host_schedule_coverage(
        self,
        termination_reason: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """为 adapter 和 provenance 校验构造严格主机控制覆盖。"""
        if not self.candidate_order_provenance:
            return None
        expected_files = list(self.candidate_order_provenance.get("files", []))
        expected_set = set(expected_files)
        observed_all = self._durable_first_touch_order()
        observed_out_of_universe = [
            path for path in observed_all if path not in expected_set
        ]
        if observed_out_of_universe:
            raise ValueError(
                "frozen schedule first-touch ledger contains off-schedule paths"
            )
        observed = list(observed_all)
        observed_set = set(observed)
        untouched_files = [
            path for path in expected_files if path not in observed_set
        ]
        statuses = self._schedule_status_snapshot()
        completed_files = [
            path for path in expected_files if statuses[path] == "completed"
        ]
        completed_count = len(completed_files)
        if not set(completed_files).issubset(observed_set):
            raise ValueError("frozen schedule completed work exceeds reached work")
        cursor = self._derive_schedule_cursor(statuses)
        total_pages = (
            len(expected_files) + FROZEN_SCHEDULE_PAGE_SIZE - 1
        ) // FROZEN_SCHEDULE_PAGE_SIZE
        schedule_exhausted = completed_count == len(expected_files)
        completed_pages = (
            total_pages
            if schedule_exhausted
            else cursor // FROZEN_SCHEDULE_PAGE_SIZE
        )
        current_page = build_schedule_page(
            expected_files,
            cursor=cursor,
            completed_files=completed_files,
        )
        presented_page_indices = self._durable_presented_page_indices()
        presented_files = [
            path
            for page_index in presented_page_indices
            for path in expected_files[
                page_index * FROZEN_SCHEDULE_PAGE_SIZE :
                (page_index + 1) * FROZEN_SCHEDULE_PAGE_SIZE
            ]
        ]
        rank_by_path = {path: index for index, path in enumerate(expected_files)}
        return {
            "schema_version": 1,
            "source": "frozen_unprioritized_schedule_host_ledger",
            "contract": FROZEN_SCHEDULE_CONTRACT,
            "page_algorithm": FROZEN_SCHEDULE_PAGE_ALGORITHM,
            "page_size": FROZEN_SCHEDULE_PAGE_SIZE,
            "order_sha256": str(
                self.candidate_order_provenance.get("order_sha256", "")
            ),
            "universe_sha256": str(
                self.candidate_order_provenance.get("universe_sha256", "")
            ),
            "total_file_count": len(expected_files),
            "completed_file_count": completed_count,
            "pending_file_count": len(expected_files) - completed_count,
            "completed_page_count": completed_pages,
            "total_page_count": total_pages,
            "current_cursor_index": cursor,
            "current_window_end_index_exclusive": current_page[
                "window_end_index_exclusive"
            ],
            "current_active_pending_file_count": current_page[
                "active_pending_file_count"
            ],
            "schedule_exhausted": schedule_exhausted,
            "coverage_status": "complete" if schedule_exhausted else "partial",
            "termination_reason": termination_reason,
            "first_touch_order": observed,
            "first_touch_order_sha256": stable_data_hash(observed),
            "first_touch_global_ranks": [
                rank_by_path[path] for path in observed
            ],
            "first_touch_count": len(observed),
            "out_of_universe_first_touches": observed_out_of_universe,
            "completed_files_sha256": stable_data_hash(completed_files),
            "untouched_file_count": len(untouched_files),
            "untouched_files_sha256": stable_data_hash(untouched_files),
            "presented_page_indices": presented_page_indices,
            "presented_work_item_count": len(presented_files),
            "presented_work_items_sha256": stable_data_hash(presented_files),
            "window_events": self._durable_schedule_window_events(),
            "claim_boundary": (
                "deterministic contiguous first-presentation order and current "
                "pending-only structured repository-path enumeration and eligibility; "
                "historical transcript may retain old-page text without reactivation; "
                "within-window visitation is model-controlled"
            ),
        }

    def _durable_first_touch_order(self) -> List[str]:
        """返回已验证的跨续跑触达任务顺序。"""
        memory_payload = getattr(self.memory, "memory", None)
        if memory_payload is not None:
            raw_touches = getattr(memory_payload, "coverage_first_touches", [])
        else:
            get_touches = getattr(self.toolkit, "get_observed_first_touches", None)
            raw_touches = list(get_touches()) if callable(get_touches) else []
        if not isinstance(raw_touches, list):
            raise ValueError("coverage first-touch ledger must be a list")
        touches = [str(path).strip() for path in raw_touches]
        if any(not path for path in touches) or len(set(touches)) != len(touches):
            raise ValueError("coverage first-touch ledger contains invalid or duplicate paths")
        if memory_payload is not None:
            get_touches = getattr(self.toolkit, "get_observed_first_touches", None)
            if callable(get_touches) and list(get_touches()) != touches:
                raise ValueError("toolkit first-touch state diverges from durable scan memory")
        return touches

    def _durable_presented_page_indices(self) -> List[int]:
        """返回已验证的跨续跑 schedule 页展示。"""
        memory_payload = getattr(self.memory, "memory", None)
        raw_indices = (
            getattr(memory_payload, "schedule_presented_page_indices", [])
            if memory_payload is not None
            else self._schedule_presented_page_indices
        )
        if not isinstance(raw_indices, list) or any(
            isinstance(index, bool) or not isinstance(index, int) or index < 0
            for index in raw_indices
        ):
            raise ValueError("presented schedule page ledger is invalid")
        indices = list(raw_indices)
        if indices != list(range(len(indices))):
            raise ValueError("presented schedule pages must form a contiguous prefix")
        return indices

    def _durable_schedule_window_events(self) -> List[Dict[str, Any]]:
        """返回跨续跑的主机 schedule 窗口转换。"""
        memory_payload = getattr(self.memory, "memory", None)
        raw_events = (
            getattr(memory_payload, "schedule_window_events", [])
            if memory_payload is not None
            else self._schedule_window_events
        )
        if not isinstance(raw_events, list) or any(
            not isinstance(event, dict) for event in raw_events
        ):
            raise ValueError("schedule window-event ledger is invalid")
        return json.loads(json.dumps(raw_events, ensure_ascii=False))

    def _build_host_priority_coverage(
        self,
        termination_reason: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """为冻结优先级主机计划全集构造持久覆盖。"""
        if not self.candidate_priority_enabled or not self._host_priority_plan:
            return None
        expected_files = sorted(str(path) for path in self.file_to_module)
        expected_set = set(expected_files)
        if not expected_files or len(expected_set) != len(expected_files):
            raise ValueError("frozen host priority-plan universe is empty or duplicated")
        if self.memory is None:
            statuses = {path: "pending" for path in expected_files}
        else:
            raw_statuses = getattr(self.memory.memory, "file_status", None)
            if not isinstance(raw_statuses, dict) or set(raw_statuses) != expected_set:
                raise ValueError("frozen host priority-plan status keys do not match its universe")
            if any(
                status not in {"pending", "completed", "skipped"}
                for status in raw_statuses.values()
            ):
                raise ValueError("frozen host priority-plan contains an invalid status")
            statuses = {path: str(raw_statuses[path]) for path in expected_files}
        observed_all = self._durable_first_touch_order()
        observed_out_of_universe = [
            path for path in observed_all if path not in expected_set
        ]
        observed = [path for path in observed_all if path in expected_set]
        observed_set = set(observed)
        completed_files = [
            path for path in expected_files if statuses[path] == "completed"
        ]
        if not set(completed_files).issubset(observed_set):
            raise ValueError("frozen host priority-plan completed work exceeds reached work")
        untouched_files = [path for path in expected_files if path not in observed_set]
        exhausted = len(completed_files) == len(expected_files)
        return {
            "schema_version": 1,
            "source": "frozen_host_priority_plan_host_ledger",
            "contract": "exact_frozen_host_priority_plan_universe",
            "host_priority_plan_sha256": stable_data_hash(self._host_priority_plan),
            "order_sha256": stable_data_hash(expected_files),
            "universe_sha256": stable_data_hash(expected_files),
            "total_file_count": len(expected_files),
            "completed_file_count": len(completed_files),
            "pending_file_count": len(expected_files) - len(completed_files),
            "schedule_exhausted": exhausted,
            "coverage_status": "complete" if exhausted else "partial",
            "termination_reason": termination_reason,
            "first_touch_order": observed,
            "first_touch_order_sha256": stable_data_hash(observed),
            "first_touch_count": len(observed),
            "out_of_universe_first_touches": observed_out_of_universe,
            "completed_files_sha256": stable_data_hash(completed_files),
            "untouched_file_count": len(untouched_files),
            "untouched_files_sha256": stable_data_hash(untouched_files),
            "presented_page_indices": [],
            "presented_work_item_count": 0,
            "presented_work_items_sha256": stable_data_hash([]),
            "window_events": [],
            "claim_boundary": (
                "host-priority membership is deterministic; model visitation "
                "within the frozen universe is model-controlled"
            ),
        }

    def _build_host_coverage_evidence(
        self,
        termination_reason: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """返回用于导出规范哈希的完整证据对象。"""
        if self.candidate_order_provenance:
            return self._build_host_schedule_coverage(termination_reason)
        return self._build_host_priority_coverage(termination_reason)

    def _build_candidate_order_provenance(
        self,
        termination_reason: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """合并冻结 schedule 与主机窗口覆盖证据。"""
        if not self.candidate_order_provenance:
            return None
        coverage = self._build_host_schedule_coverage(termination_reason)
        return {
            **dict(self.candidate_order_provenance),
            "window_policy": {
                "schema_version": 1,
                "page_algorithm": FROZEN_SCHEDULE_PAGE_ALGORITHM,
                "page_size": FROZEN_SCHEDULE_PAGE_SIZE,
                "advance_condition": "all_active_page_files_persisted_completed",
                "active_allowlist": "current_page_pending_only",
            },
            "host_schedule_coverage": coverage,
        }

    def _build_host_coverage_ledger(
        self,
        termination_reason: Optional[str],
    ) -> Optional[Dict[str, Any]]:
        """构造稳定的精确键 adapter 覆盖 ledger。"""
        coverage = self._build_host_coverage_evidence(termination_reason)
        if coverage is None:
            return None
        return {
            "schema_version": 1,
            "source": coverage["source"],
            "total_work_items": coverage["total_file_count"],
            "reached_work_items": coverage["first_touch_count"],
            "completed_work_items": coverage["completed_file_count"],
            "untouched_work_items": coverage["untouched_file_count"],
            "all_work_exhausted": coverage["schedule_exhausted"],
            "termination_reason": termination_reason,
            "evidence_sha256": stable_data_hash(coverage),
        }


    def run(self) -> Dict[str, Any]:
        if self.verbose:
            logger.info("Starting agentic vulnerability analysis with native tool calling...")
        shared_observation_count = (
            0
            if not self.memory_guidance_enabled
            else max(
                0,
                to_int(self.shared_public_memory_scope.get("observation_count", 0)),
            )
        )
        system_prompt_kwargs = {
            "shared_observation_count": shared_observation_count,
        }
        if not self.memory_guidance_enabled:
            system_prompt_kwargs["memory_guidance_enabled"] = False
        if self.ablation_config["reference_semantics"]:
            system_prompt_kwargs["reference_semantics_enabled"] = False
        if self.candidate_order_provenance:
            system_prompt_kwargs["candidate_file_order"] = list(
                self.candidate_order_provenance.get("files", [])
            )
            system_prompt_kwargs["candidate_schedule_provenance"] = dict(
                self.candidate_order_provenance
            )
        if not self.verifier_enabled:
            system_prompt_kwargs["verifier_enabled"] = False
        if not self.candidate_priority_enabled:
            system_prompt_kwargs["candidate_priority_enabled"] = False
        self.conversation_history = [
            {
                "role": "system",
                "content": build_system_prompt(
                    self._model_visible_vulnerability_profile,
                    self.toolkit,
                    **system_prompt_kwargs,
                ),
            }
        ]
        iteration = 0  # iteration index
        termination_reason: Optional[str] = None
        iteration_durations_seconds: List[float] = []

        while True:
            if not self.candidate_priority_enabled:
                self._sync_schedule_window()
            full_universe_complete = self._is_full_universe_complete()
            base_iteration_reached = iteration >= self.max_iterations
            if self.require_full_universe_completion:
                if full_universe_complete:
                    termination_reason = "full_universe_complete"
                    break
                if base_iteration_reached:
                    termination_reason = "full_universe_iteration_cap"
                    break
            elif not self.candidate_priority_enabled:
                if full_universe_complete:
                    termination_reason = "frozen_schedule_complete"
                    break
            critical_complete = self._is_critical_complete()
            if self.require_full_universe_completion:
                pass
            elif not self.stop_when_critical_complete:
                if base_iteration_reached:
                    termination_reason = "max_iterations"
                    break
            elif self.critical_stop_mode == "max":
                if base_iteration_reached and critical_complete:
                    if self.verbose:
                        logger.info(
                            "Reached stop condition: iterations >= baseline and %s scope complete",
                            self._critical_scope_label(),
                        )
                    termination_reason = "baseline_and_critical_scope_complete"
                    break
            else:
                # min mode: stop when either baseline iteration cap is reached
                # or critical scope is complete
                if base_iteration_reached:
                    if self.verbose:
                        logger.warning(f"Reached maximum iterations ({self.max_iterations})")
                    termination_reason = "max_iterations"
                    break
                if critical_complete and iteration > 0:
                    if self.verbose:
                        logger.info(
                            "- %s scan scope is complete; stopping (critical-stop-mode=min)",
                            self._critical_scope_label(),
                        )
                    termination_reason = "critical_scope_complete"
                    break

            iteration_started_perf = time.perf_counter()
            if self.verbose:
                if self.stop_when_critical_complete and self.critical_stop_mode == "max":
                    logger.info(
                        f"\n[ITERATION {iteration + 1}] "
                        f"(baseline={self.max_iterations}, "
                        f"stop when baseline reached AND {self._critical_scope_label()} complete)"
                    )
                elif self.stop_when_critical_complete and self.critical_stop_mode == "min":
                    logger.info(
                        f"\n[ITERATION {iteration + 1}/{self.max_iterations}] "
                        f"(stop when baseline reached OR {self._critical_scope_label()} complete)"
                    )
                else:
                    logger.info(f"\n[ITERATION {iteration + 1}/{self.max_iterations}]")
            start_iteration_tracking = getattr(self.toolkit, "start_iteration_tracking", None)
            if callable(start_iteration_tracking):
                start_iteration_tracking()
            self.conversation_history.append(
                {"role": "user", "content": self._get_user_message(iteration)}
            )
            prev_conv_length = len(self.conversation_history)
            _ = self._run_turn(iteration)
            self._finalize_iteration_progress(iteration)
            turn_start_index = min(
                max(0, to_int(getattr(self, "_current_turn_start_index", prev_conv_length))),
                len(self.conversation_history),
            )
            response = ""
            # Only inspect assistant messages produced in the current turn.
            for message in reversed(self.conversation_history[turn_start_index:]):
                role = getattr(message, "role", None)
                if role is None and isinstance(message, dict):
                    role = message.get("role")
                if role != "assistant":
                    continue
                response = (
                    message.content
                    if hasattr(message, "content")
                    else message.get("content", "")
                )
                break
            completion_keywords = ["analysis complete"]  # currently only "analysis complete" as stop words
            should_stop = bool(
                response
                and (
                    any(keyword in response.lower() for keyword in completion_keywords)
                    or self._is_completion_signal(str(response))
                )
            )
            if (
                should_stop
                and (
                    (
                        not self.candidate_priority_enabled
                        and not self._schedule_is_complete()
                    )
                    or (
                        self.require_full_universe_completion
                        and not self._is_full_universe_complete()
                    )
                )
            ):
                if self.verbose:
                    logger.info(
                        "Ignoring model completion signal while the required host universe remains incomplete"
                    )
                should_stop = False
            critical_complete = self._is_critical_complete()
            if should_stop and self.verbose:
                logger.info("- LLM indicates analysis is complete")
            if self.stop_when_critical_complete and critical_complete and self.verbose:
                logger.info("- %s scan scope is complete", self._critical_scope_label())

            if self.output_dir:
                conversations_dir = self.output_dir / "conversations"
                conversations_dir.mkdir(parents=True, exist_ok=True)
                iteration_file = conversations_dir / f"iteration_{iteration}.json"
                with open(iteration_file, "w", encoding="utf-8") as handle:
                    json.dump(make_serializable(self.conversation_history), handle, indent=2, ensure_ascii=False)
                iteration_history = self._project_scheduled_model_value(
                    self.conversation_history[turn_start_index:]
                )
                summarized = compress_iteration_conversation(
                    self.llm_client,
                    iteration,
                    iteration_history,
                    verbose=self.verbose,
                )
                summarized = self._project_scheduled_model_value(summarized)
                summary_file = conversations_dir / f"iteration_{iteration}_output_summary.json"
                with open(summary_file, "w", encoding="utf-8") as handle:
                    json.dump(summarized, handle, indent=2, ensure_ascii=False)
                self.conversation_history = self.conversation_history[:turn_start_index]

                # Keep history bounded even if compression returns a failure stub.
                assistant_summary = self._extract_complementary_summary(summarized)
                if assistant_summary:
                    self.conversation_history.append(
                        {"role": "assistant", "content": assistant_summary}
                    )
            
            iteration_durations_seconds.append(
                round(time.perf_counter() - iteration_started_perf, 6)
            )
            iteration += 1
            if should_stop:
                if self.require_full_universe_completion:
                    termination_reason = "full_universe_complete"
                    break
                if not self.stop_when_critical_complete:
                    termination_reason = "llm_completion_signal"
                    break
                if critical_complete and self.critical_stop_mode == "min":
                    termination_reason = "llm_completion_signal_and_critical_scope_complete"
                    break
                if self.verbose:
                    logger.info(
                        "- Ignore 'analysis complete' because %s scope is still incomplete",
                        self._critical_scope_label(),
                    )
            if should_stop and self.stop_when_critical_complete and self.critical_stop_mode == "max" and self.verbose:
                logger.info(
                    "- Continue scanning until both conditions are met: "
                    f"iterations >= {self.max_iterations} and {self._critical_scope_label()} scope complete"
                )

        if (
            not self.stop_when_critical_complete
            and iteration >= self.max_iterations
            and self.verbose
        ):
            logger.warning(f"Reached maximum iterations ({self.max_iterations})")
        
        # Finalize memory
        self._finalize_memory()

        host_coverage_evidence = self._build_host_coverage_evidence(
            termination_reason
        )
        
        return {
            "vulnerabilities": self.found_vulnerabilities,
            "iterations": iteration,
            "termination_reason": termination_reason,
            "iteration_durations_seconds": iteration_durations_seconds,
            "module_similarity_provenance": dict(self.module_similarity_provenance) or None,
            "candidate_order_provenance": self._build_candidate_order_provenance(
                termination_reason
            ),
            "host_coverage_ledger": self._build_host_coverage_ledger(
                termination_reason
            ),
            "host_coverage_evidence": host_coverage_evidence,
            "conversation_length": len(self.conversation_history),
        }
    
    def _finalize_memory(self):
        """Generate summary and save final memory state."""
        if not self.memory:
            return

        # Generate LLM summary
        if self.llm_client and self.memory_guidance_enabled:
            logger.info("Generating scan summary...")
            generate_summary_fn = getattr(self.memory, "generate_summary", None)
            if callable(generate_summary_fn):
                generate_summary_fn()

        # Save markdown report
        save_markdown_fn = getattr(self.memory, "save_markdown", None)
        if callable(save_markdown_fn):
            save_markdown_fn()
        
        # Log completion status
        progress = self.memory.get_progress()
        priority_1 = progress.get("priority_1", {})
        priority_2 = progress.get("priority_2", {})
        critical_scope_total = int(priority_1.get("total", 0))
        critical_scope_completed = int(priority_1.get("completed", 0))
        if self.critical_stop_max_priority >= 2:
            critical_scope_total += int(priority_2.get("total", 0))
            critical_scope_completed += int(priority_2.get("completed", 0))

        if self._is_critical_complete():
            logger.info("✅ All %s files have been scanned", self._critical_scope_label())
        else:
            logger.warning(
                "⚠️ Some %s files not scanned: %s/%s",
                self._critical_scope_label(),
                critical_scope_completed,
                critical_scope_total,
            )
        
        logger.info(
            f"Scan complete: {progress['completed']}/{progress['total_files']} files, "
            f"{progress['findings']} findings"
        )
