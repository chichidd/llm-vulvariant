"""Skill-based exploitability checker using Claude Code.

This module uses the .claude/skills/check-exploitability skill to verify
whether detected vulnerabilities are actually exploitable.

Key design:
- Process each vulnerability individually for better reliability
- Use --output-format json to get structured results from stdout
- Save intermediate results after each vulnerability
- Support resume from partial progress
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from config import _path_config
from utils.claude_cli import (
    DEFAULT_SELECTED_MODEL_HINT,
    apply_claude_cli_usage_counters,
    aggregate_usage_summaries,
    coerce_aggregated_usage_summary,
    merge_aggregated_usage_summaries,
    run_claude_cli,
)
from utils.io_utils import write_atomic_json
from utils.logger import get_logger
from utils.llm_utils import extract_json_from_text, extract_json_object_matches

logger = get_logger(__name__)

VALID_EXPLOITABILITY_VERDICTS = {
    "EXPLOITABLE",
    "CONDITIONALLY_EXPLOITABLE",
    "LIBRARY_RISK",
    "NOT_EXPLOITABLE",
}
VALID_CONFIDENCE_VALUES = {"high", "medium", "low"}
RETRYABLE_RESULT_VERDICTS = {"ERROR", "UNKNOWN"}
STRUCTURED_EXPLOITABILITY_VERDICTS = VALID_EXPLOITABILITY_VERDICTS | RETRYABLE_RESULT_VERDICTS
STRUCTURED_ANALYSIS_LIST_FIELDS = (
    "preconditions",
    "static_evidence",
    "dynamic_plan",
    "open_questions",
)
EXPLOITABILITY_OUTPUT_STATE_MISSING = "missing"
EXPLOITABILITY_OUTPUT_STATE_INVALID = "invalid"
EXPLOITABILITY_OUTPUT_STATE_IN_PROGRESS = "in_progress"
EXPLOITABILITY_OUTPUT_STATE_COMPLETE = "complete"
FINDINGS_FRESHNESS_STATE_MISSING = "missing"
FINDINGS_FRESHNESS_STATE_READY = "ready"
FINDINGS_FRESHNESS_STATE_INVALID = "invalid"


def normalize_exploitability_verdict(verdict: Any) -> str:
    """Normalize verdict text into the persisted underscore enum format."""
    if not isinstance(verdict, str):
        return ""
    normalized = re.sub(r"[\s-]+", "_", verdict.strip().upper())
    return re.sub(r"_+", "_", normalized)


def order_findings_stably(vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Return findings sorted by canonical payload so ids stay stable across reruns."""
    ordered_pairs = sorted(
        enumerate(vulnerabilities),
        key=lambda item: (
            json.dumps(item[1], sort_keys=True, ensure_ascii=False, separators=(",", ":")),
            item[0],
        ),
    )
    return [vulnerability for _, vulnerability in ordered_pairs]


def compute_findings_signature(vulnerabilities: List[Dict[str, Any]]) -> str:
    """Build a stable signature for the current findings set."""
    payload = json.dumps(
        order_findings_stably(vulnerabilities),
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def load_findings_freshness(findings_path: Path) -> Tuple[str, Optional[int], Optional[str]]:
    """Load the current findings freshness state, count, and signature."""
    if not findings_path.exists():
        return FINDINGS_FRESHNESS_STATE_MISSING, None, None
    try:
        findings_data = json.loads(findings_path.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.warning(f"Failed to load findings {findings_path}: {exc}")
        return FINDINGS_FRESHNESS_STATE_INVALID, None, None
    if not isinstance(findings_data, dict):
        logger.warning(f"Findings payload is not a JSON object: {findings_path}")
        return FINDINGS_FRESHNESS_STATE_INVALID, None, None
    vulnerabilities = findings_data.get("vulnerabilities", [])
    if not isinstance(vulnerabilities, list):
        logger.warning(f"Findings payload is missing a valid vulnerabilities list: {findings_path}")
        return FINDINGS_FRESHNESS_STATE_INVALID, None, None
    return FINDINGS_FRESHNESS_STATE_READY, len(vulnerabilities), compute_findings_signature(vulnerabilities)


def get_exploitability_output_state(exploitability_data: Optional[Dict[str, Any]]) -> str:
    """Return whether exploitability output is missing, in progress, invalid, or complete."""
    if exploitability_data is None:
        return EXPLOITABILITY_OUTPUT_STATE_MISSING

    metadata = exploitability_data.get("metadata")
    results = exploitability_data.get("results")
    if not isinstance(metadata, dict) or not isinstance(results, list):
        return EXPLOITABILITY_OUTPUT_STATE_INVALID

    completed_at = metadata.get("completed_at")
    total_vulnerabilities = metadata.get("total_vulnerabilities")
    if not isinstance(completed_at, str) or not completed_at.strip():
        return EXPLOITABILITY_OUTPUT_STATE_IN_PROGRESS
    if not isinstance(total_vulnerabilities, int) or total_vulnerabilities < 0:
        return EXPLOITABILITY_OUTPUT_STATE_INVALID
    if len(results) != total_vulnerabilities:
        return EXPLOITABILITY_OUTPUT_STATE_IN_PROGRESS
    if any(
        isinstance(item, dict)
        and normalize_exploitability_verdict(item.get("verdict")) in RETRYABLE_RESULT_VERDICTS
        for item in results
    ):
        return EXPLOITABILITY_OUTPUT_STATE_IN_PROGRESS
    return EXPLOITABILITY_OUTPUT_STATE_COMPLETE


def get_exploitability_output_state_for_findings(
    exploitability_data: Optional[Dict[str, Any]],
    findings_path: Path,
) -> str:
    """Resolve exploitability output state against the current findings file."""
    output_state = get_exploitability_output_state(exploitability_data)
    if output_state != EXPLOITABILITY_OUTPUT_STATE_COMPLETE or exploitability_data is None:
        return output_state

    findings_state, _, current_findings_signature = load_findings_freshness(findings_path)
    if findings_state == FINDINGS_FRESHNESS_STATE_MISSING:
        return output_state
    if findings_state != FINDINGS_FRESHNESS_STATE_READY:
        return EXPLOITABILITY_OUTPUT_STATE_IN_PROGRESS

    metadata = exploitability_data.get("metadata", {})
    saved_signature = metadata.get("findings_signature") if isinstance(metadata, dict) else None
    if isinstance(saved_signature, str) and saved_signature.strip():
        if saved_signature == current_findings_signature:
            return output_state
        return EXPLOITABILITY_OUTPUT_STATE_IN_PROGRESS
    return EXPLOITABILITY_OUTPUT_STATE_IN_PROGRESS


class SkillExploitabilityChecker:
    """Check vulnerability exploitability using Claude Code skill."""

    def __init__(self, timeout: int = 600, claude_config_dir: str | Path | None = None):
        """Initialize the checker.
        
        Args:
            timeout: Timeout in seconds for each Claude CLI call (default: 600 = 10 minutes)
            claude_config_dir: Base Claude runtime directory (default: <repo_root>/.claude-runtime)
        """
        self.timeout = timeout
        self.skill_name = "check-exploitability"
        self._default_claude_config_dir = Path(claude_config_dir) if claude_config_dir else (
            _path_config["repo_root"] / ".claude-runtime"
        )
        self._active_claude_config_dir = self._default_claude_config_dir
        self._ensure_claude_runtime_dir(self._default_claude_config_dir)
        
        if not self._skill_exists():
            logger.warning(f"Skill '{self.skill_name}' not found at {self._get_skill_path()}")

    @staticmethod
    def _ensure_claude_runtime_dir(runtime_dir: Path) -> None:
        """Ensure runtime dir has expected writable structure."""
        runtime_dir.mkdir(parents=True, exist_ok=True)
        (runtime_dir / "debug").mkdir(parents=True, exist_ok=True)

    def _get_skill_path(self) -> Path:
        """Get the path to the skill directory."""
        return _path_config['skill_path'] / self.skill_name

    def _skill_exists(self) -> bool:
        """Check if the skill exists."""
        return self._get_skill_path().exists()

    @staticmethod
    def _normalize_finding_id(finding_id: Any) -> str:
        """Normalize finding identifiers used in persisted result rows."""
        if isinstance(finding_id, str):
            return finding_id.strip()
        return ""

    @classmethod
    def _finding_id_within_scope(cls, finding_id: Any, total_vulns: int) -> bool:
        """Return whether a persisted finding id still belongs to the current findings set."""
        normalized = cls._normalize_finding_id(finding_id)
        match = re.fullmatch(r"vuln_(\d+)", normalized)
        if match is None:
            return True
        return int(match.group(1)) < total_vulns

    @staticmethod
    def _finding_matches_current(saved_finding: Any, current_finding: Dict[str, Any]) -> bool:
        """Return whether a saved finding still matches the current finding payload."""
        if not isinstance(saved_finding, dict):
            return False
        return saved_finding == current_finding

    @classmethod
    def _classify_persisted_result(
        cls,
        item: Dict[str, Any],
        current_total_vulns: Optional[int] = None,
        current_findings: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> str:
        """Classify one persisted result row against the current findings set."""
        finding_id = cls._normalize_finding_id(item.get("finding_id"))
        if finding_id:
            if current_total_vulns is not None and not cls._finding_id_within_scope(
                finding_id,
                current_total_vulns,
            ):
                return "stale_scope"
            if current_findings is not None:
                current_finding = current_findings.get(finding_id)
                if current_finding is None:
                    return "stale_scope"
                saved_finding = item.get("original_finding")
                if isinstance(saved_finding, dict) and not cls._finding_matches_current(
                    saved_finding,
                    current_finding,
                ):
                    return "stale_changed"
            if cls._is_retryable_result(item):
                return "retryable"
        return "keep"

    @staticmethod
    def _is_retryable_result(item: Dict[str, Any]) -> bool:
        """Return whether a saved result should be retried on resume."""
        verdict = normalize_exploitability_verdict(item.get("verdict"))
        return verdict in RETRYABLE_RESULT_VERDICTS

    @classmethod
    def _get_processed_ids(cls, results: List[Dict[str, Any]]) -> set[str]:
        """Return finding ids that should count as completed for this run."""
        processed_ids: set[str] = set()
        for item in results:
            if cls._is_retryable_result(item):
                continue
            finding_id = cls._normalize_finding_id(item.get("finding_id"))
            if finding_id:
                processed_ids.add(finding_id)
        return processed_ids

    @staticmethod
    def _is_analysis_payload(payload: Dict[str, Any]) -> bool:
        """Return whether the parsed JSON looks like a concrete analysis payload."""
        verdict = normalize_exploitability_verdict(payload.get("verdict"))
        confidence = str(payload.get("confidence", "")).strip().lower()

        # Reject schema echoes like "EXPLOITABLE|...|NOT_EXPLOITABLE" and
        # only accept concrete verdicts produced by the skill, including
        # structured retryable states that resume logic persists on disk.
        if confidence not in VALID_CONFIDENCE_VALUES:
            return False
        return verdict in STRUCTURED_EXPLOITABILITY_VERDICTS

    @staticmethod
    def _normalize_analysis_list(value: Any) -> List[str]:
        """Normalize list-shaped evidence sections into non-empty strings."""
        if not isinstance(value, list):
            return []

        normalized_items: List[str] = []
        for item in value:
            if isinstance(item, dict):
                rendered = str(
                    item.get("step")
                    or item.get("description")
                    or item.get("summary")
                    or item.get("location")
                    or item.get("function")
                    or ""
                ).strip()
                if not rendered:
                    rendered = json.dumps(item, ensure_ascii=False, sort_keys=True)
            else:
                rendered = str(item).strip()

            if rendered:
                normalized_items.append(rendered)
        return normalized_items

    @classmethod
    def _normalize_analysis_contract(cls, payload: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Fill the richer evidence contract while preserving legacy fields."""
        if not isinstance(payload, dict):
            return None

        normalized = dict(payload)
        normalized["verdict"] = normalize_exploitability_verdict(normalized.get("verdict"))
        normalized["confidence"] = str(normalized.get("confidence", "")).strip().lower()
        normalized["verdict_rationale"] = str(normalized.get("verdict_rationale") or "").strip()
        for field in STRUCTURED_ANALYSIS_LIST_FIELDS:
            normalized[field] = cls._normalize_analysis_list(normalized.get(field))

        docker_verification = normalized.get("docker_verification")
        normalized["docker_verification"] = docker_verification if isinstance(docker_verification, dict) else None
        return normalized

    @staticmethod
    def _looks_like_example_payload(
        text: str,
        start: int,
        end: int,
        previous_object_end: Optional[int] = None,
    ) -> bool:
        """Return whether a JSON object appears to be an inline example instead of the final answer."""
        prefix_start = max(previous_object_end or 0, start - 160)
        prefix_window = text[prefix_start:start]

        if re.search(r"\b(final|actual|answer|result|conclusion)\b", prefix_window, flags=re.IGNORECASE):
            return False
        # Only reject clearly illustrative prefixes. Bare "Schema:" / "Output schema:"
        # are ambiguous in Claude output and can prefix the final concrete payload.
        if re.search(
            r"\bexample\b|\bsample\b|e\.g\.",
            prefix_window,
            flags=re.IGNORECASE,
        ):
            return True
        return False

    @classmethod
    def _extract_analysis_payload(cls, text: str) -> Optional[Dict[str, Any]]:
        """Extract a structured exploitability analysis payload from text."""
        return extract_json_from_text(
            text,
            required_keys=["verdict"],
            validator=cls._is_analysis_payload,
            prefer_last=True,
            match_filter=lambda match, previous_match, full_text: not cls._looks_like_example_payload(
                full_text,
                match.start,
                match.end,
                previous_object_end=None if previous_match is None else previous_match.end,
            ),
        )

    @staticmethod
    def _strip_inline_json_objects(text: str) -> str:
        """Remove inline JSON objects so verdict inference only sees prose."""
        top_level_matches: List[Any] = []
        for match in extract_json_object_matches(text):
            if top_level_matches and match.start >= top_level_matches[-1].start and match.end <= top_level_matches[-1].end:
                continue
            top_level_matches.append(match)

        chunks: List[str] = []
        cursor = 0
        for match in top_level_matches:
            chunks.append(text[cursor:match.start])
            cursor = match.end

        chunks.append(text[cursor:])
        return " ".join(chunk.strip() for chunk in chunks if chunk.strip())

    def check_single(
        self,
        findings_path: Path,
        repo_path: Path,
        output_path: Path,
        software_profile_path: Optional[Path] = None,
        commit_hash: str = "",
        run_id: Optional[str] = None,
        claude_config_dir: str | Path | None = None,
    ) -> Dict[str, Any]:
        """Check exploitability of vulnerabilities in a findings file.
        
        Processes each vulnerability individually and saves progress.
        For EXPLOITABLE findings, Phase 5 Docker PoC verification is always
        performed by the skill (Claude uses bash to docker build/run).
        
        Args:
            findings_path: Path to agentic_vuln_findings.json
            repo_path: Path to the target repository
            output_path: Path to write exploitability.json
            software_profile_path: Optional path to software_profile.json
            commit_hash: Full or prefix commit hash for reproducible Docker builds.
            run_id: Optional batch run identifier persisted into metadata
            claude_config_dir: Runtime directory used by Claude CLI for this check
            
        Returns:
            Dictionary with analysis results and metadata
        """
        # Validate inputs
        if not findings_path.exists():
            logger.error(f"Findings file not found: {findings_path}")
            return self._error_result(f"Findings file not found: {findings_path}")

        if not self._skill_exists():
            logger.error(f"Skill not found: {self._get_skill_path()}")
            return self._error_result("Skill not found")

        # Load vulnerabilities
        try:
            findings = json.loads(findings_path.read_text(encoding="utf-8"))
            vulnerabilities = findings.get("vulnerabilities", [])
        except Exception as e:
            logger.error(f"Failed to load findings: {e}")
            return self._error_result(f"Failed to load findings: {e}")

        ordered_vulnerabilities = order_findings_stably(vulnerabilities)
        current_findings_by_id = {
            f"vuln_{idx:03d}": vuln
            for idx, vuln in enumerate(ordered_vulnerabilities)
            if isinstance(vuln, dict)
        }
        findings_signature = compute_findings_signature(ordered_vulnerabilities)

        runtime_dir = Path(claude_config_dir) if claude_config_dir else self._default_claude_config_dir
        self._ensure_claude_runtime_dir(runtime_dir)
        self._active_claude_config_dir = runtime_dir

        if not ordered_vulnerabilities:
            logger.info(f"No vulnerabilities found in {findings_path}")
            try:
                result_doc = self._init_or_load_results(
                    output_path=output_path,
                    findings_path=findings_path,
                    repo_path=repo_path,
                    software_profile_path=software_profile_path,
                    total_vulns=0,
                    current_findings=current_findings_by_id,
                    findings_signature=findings_signature,
                    run_id=run_id,
                    claude_config_dir=runtime_dir,
                )
            except RuntimeError as exc:
                logger.error(str(exc))
                return self._error_result(str(exc))
            result_doc["metadata"]["completed_at"] = datetime.now().isoformat()
            result_doc = self._save_results(
                output_path,
                result_doc,
                current_findings=current_findings_by_id,
            )
            return {
                "status": "success",
                "message": "No vulnerabilities to analyze",
                "findings_path": str(findings_path),
                "output_path": str(output_path),
                "num_analyzed": 0,
                "summary": result_doc.get("summary", {}),
                "llm_usage_summary": result_doc.get("metadata", {}).get("llm_usage_summary", {}),
                "results": [],
            }

        logger.info(f"Analyzing {len(ordered_vulnerabilities)} vulnerabilities from {findings_path}")

        # Initialize or load existing results
        try:
            result_doc = self._init_or_load_results(
                output_path=output_path,
                findings_path=findings_path,
                repo_path=repo_path,
                software_profile_path=software_profile_path,
                total_vulns=len(ordered_vulnerabilities),
                current_findings=current_findings_by_id,
                findings_signature=findings_signature,
                run_id=run_id,
                claude_config_dir=runtime_dir,
            )
        except RuntimeError as exc:
            logger.error(str(exc))
            return self._error_result(str(exc))

        # Get already processed indices
        # Keep retryable rows out of the processed set so resumed runs revisit them.
        processed_ids = self._get_processed_ids(result_doc.get("results", []))
        
        # Process each vulnerability
        for idx, vuln in enumerate(ordered_vulnerabilities):
            finding_id = f"vuln_{idx:03d}"
            
            if finding_id in processed_ids:
                logger.info(f"[{idx+1}/{len(ordered_vulnerabilities)}] Skipping {finding_id} (already processed)")
                continue
            
            logger.info(
                f"[{idx+1}/{len(ordered_vulnerabilities)}] Analyzing {finding_id}: "
                f"{vuln.get('file_path', 'unknown')}"
            )
            
            # Prepare evidence directory for Docker PoC verification
            evidence_dir = output_path.parent / "evidence" / finding_id
            evidence_dir.mkdir(parents=True, exist_ok=True)
            
            # Analyze single vulnerability
            vuln_result = self._analyze_single_vuln(
                vuln=vuln,
                finding_id=finding_id,
                repo_path=repo_path,
                commit_hash=commit_hash,
                evidence_dir=evidence_dir,
            )
            
            # Replace any stale in-memory entry before saving the refreshed result.
            result_doc["results"] = [
                item for item in result_doc.get("results", [])
                if item.get("finding_id") != finding_id
            ]
            result_doc["results"].append(vuln_result)
            self._update_summary(result_doc)
            result_doc = self._save_results(
                output_path,
                result_doc,
                current_findings=current_findings_by_id,
            )
            processed_ids = self._get_processed_ids(result_doc.get("results", []))
            
            logger.info(f"  -> Verdict: {vuln_result.get('verdict', 'UNKNOWN')}")
            if vuln_result.get('verdict') == 'EXPLOITABLE':
                logger.info(f"     Source: {vuln_result.get('source_analysis')}")
        # Final update
        result_doc["metadata"]["completed_at"] = datetime.now().isoformat()
        result_doc = self._save_results(
            output_path,
            result_doc,
            current_findings=current_findings_by_id,
        )
        
        return {
            "status": "success",
            "findings_path": str(findings_path),
            "output_path": str(output_path),
            "num_analyzed": len(ordered_vulnerabilities),
            "summary": result_doc.get("summary", {}),
            "llm_usage_summary": result_doc.get("metadata", {}).get("llm_usage_summary", {}),
        }

    def _analyze_single_vuln(
        self,
        vuln: Dict[str, Any],
        finding_id: str,
        repo_path: Path,
        commit_hash: str = "",
        evidence_dir: Optional[Path] = None,
    ) -> Dict[str, Any]:
        """Analyze a single vulnerability using Claude.
        
        Args:
            vuln: Vulnerability dictionary from findings
            finding_id: Unique ID for this vulnerability
            repo_path: Path to the repository
            commit_hash: Commit hash to check out inside Docker
            evidence_dir: Directory for PoC script and Docker build artefacts
            
        Returns:
            Analysis result dictionary
        """
        result_json_path: Optional[Path] = None
        claude_record_path: Optional[Path] = None
        if evidence_dir:
            result_json_path = evidence_dir / "analysis_output.json"
            claude_record_path = evidence_dir / "claude_cli_invocation.json"
            try:
                self._prepare_result_json_path(result_json_path)
            except RuntimeError as exc:
                analysis = self._create_error_vuln_result(vuln, finding_id, str(exc))
                analysis["finding_id"] = finding_id
                analysis["original_finding"] = vuln
                if claude_record_path:
                    analysis["claude_cli_record_path"] = str(claude_record_path)
                return analysis

        prompt = self._build_prompt(
            vuln, repo_path,
            commit_hash=commit_hash,
            evidence_dir=evidence_dir,
            result_json_path=result_json_path,
        )
        
        # Run Claude and get JSON result
        success, claude_result, llm_usage = self._run_claude(
            prompt,
            record_path=claude_record_path,
        )

        analysis: Optional[Dict[str, Any]] = None
        if success and claude_result:
            # Parse the result text from Claude's JSON output
            analysis = self._parse_claude_result(claude_result)

        # File fallback: if stdout is missing/invalid (or only UNKNOWN/ERROR),
        # try loading structured JSON from RESULT_JSON_PATH.
        needs_fallback = not analysis or normalize_exploitability_verdict(
            analysis.get("verdict")
        ) in {"UNKNOWN", "ERROR"}
        if needs_fallback and result_json_path:
            file_analysis = self._load_analysis_from_output_path(result_json_path)
            if file_analysis:
                analysis = file_analysis

        if not analysis:
            analysis = self._create_error_vuln_result(vuln, finding_id, "Claude analysis failed")

        analysis["finding_id"] = finding_id
        analysis["original_finding"] = vuln
        analysis["llm_usage"] = llm_usage
        if claude_record_path:
            analysis["claude_cli_record_path"] = str(claude_record_path)

        # Recover and normalize docker verification using on-disk evidence.
        # This makes results robust when Claude returns non-JSON output,
        # or when Docker verification only partially completes.
        analysis = self._recover_docker_verification(
            analysis=analysis,
            evidence_dir=evidence_dir,
            commit_hash=commit_hash,
        )

        return self._normalize_analysis_contract(analysis) or analysis

    def _build_prompt(
        self,
        vuln: Dict[str, Any],
        repo_path: Path,
        commit_hash: str = "",
        evidence_dir: Optional[Path] = None,
        result_json_path: Optional[Path] = None,
    ) -> str:
        """Build Claude prompt for single vulnerability analysis."""
        # Build concise vulnerability summary
        file_path = vuln.get('file_path', 'unknown')
        vuln_type = vuln.get('vulnerability_type', 'unknown')
        evidence = vuln.get('evidence', '')[:400]
        description = vuln.get('description', '')[:200]
        
        lines = [
            f"Quick vulnerability check using {self.skill_name} skill:",
            f"File: {file_path}",
            f"Type: {vuln_type}",
            f"Evidence: {evidence}",
            f"Description: {description}",
            "",
            f"Repository: {repo_path.resolve()}",
            "", 
            "Verify the code path exists and return strictly ONE JSON object on stdout.",
            "Do not emit markdown, code fences, or prose.",
            "If any required evidence is missing, use the most conservative verdict ",
            "and set confidence to low, with explicit unknown gaps.",
            "Ground every claim in the provided repository evidence.",
            "If evidence is missing, say so explicitly in the relevant field.",
            "Never invent sink/source details or verdicts not supported by code evidence.",
            "Do not emit prose; return one single JSON object only.",
            "Do not add explanatory text outside the JSON object.",
            '{"verdict":"EXPLOITABLE|CONDITIONALLY_EXPLOITABLE|LIBRARY_RISK|NOT_EXPLOITABLE",',
            '"confidence":"high|medium|low",',
            '"verdict_rationale":"...",',
            '"preconditions":["..."],',
            '"static_evidence":["..."],',
            '"dynamic_plan":["..."],',
            '"docker_verification":{"verification_verdict":"VERIFIED_EXPLOITABLE|PARTIAL_VERIFICATION|VERIFICATION_FAILED|NOT_VERIFIED|GENERATION_FAILED"},',
            '"open_questions":["..."],',
            '"sink_analysis":{"confirmed":true/false,"sink_type":"...","protection_status":"none|partial|full"},',
            '"source_analysis":{"sources_found":[{"type":"cli|file|api","location":"..."}],"attack_path":["..."]},',
            '"attack_scenario":{"description":"...","steps":["..."],"impact":"..."},',
            '"remediation":{"recommendation":"..."}}',
            "Keep the legacy compatibility sections above when you have concrete evidence for them.",
        ]

        if result_json_path:
            lines.extend([
                f"RESULT_JSON_PATH: {result_json_path.resolve()}",
                "If RESULT_JSON_PATH is provided, write the same final JSON object to that path,",
                "and still return JSON only on stdout.",
            ])

        lines.extend([
            "",
            "--- DOCKER VERIFICATION ---",
            "DOCKER_VERIFY: true",
            f"COMMIT_HASH: {commit_hash}" if commit_hash else "COMMIT_HASH: HEAD",
            f"REPO_PATH: {repo_path.resolve()}",
            f"EVIDENCE_DIR: {evidence_dir.resolve() if evidence_dir else str(repo_path.resolve() / 'evidence')}",
            "If Docker verification needs provider credentials, forward the host environment into the container with",
            "`docker run -e DEEPSEEK_API_KEY -e OPENAI_API_KEY -e NY_API_KEY ...` so Docker copies the current values.",
            "Do not leave `<API_KEY>` placeholders in the command.",
            "Do not print or copy secret values into stdout, files, or the final JSON.",
            "",
            "After the static analysis (phases 1-4), if verdict is EXPLOITABLE, also run",
            "Phase 5 (Docker PoC Verification) from the skill and include the",
            "'docker_verification' object in the output JSON.",
        ])
        
        return "\n".join(lines)

    def _prepare_result_json_path(self, result_json_path: Path) -> None:
        """Prepare result file path and clear stale output from previous attempts."""
        try:
            result_json_path.parent.mkdir(parents=True, exist_ok=True)
            if result_json_path.exists():
                result_json_path.unlink()
        except Exception as exc:  # pylint: disable=broad-except
            raise RuntimeError(
                f"Failed to prepare result file {result_json_path}: {exc}"
            ) from exc

    def _load_analysis_from_output_path(
        self,
        output_json_path: Path,
    ) -> Optional[Dict[str, Any]]:
        """Load analysis JSON from a result file path provided in the prompt."""
        if not output_json_path.exists():
            return None

        try:
            text = output_json_path.read_text(encoding="utf-8")
        except Exception as exc:  # pylint: disable=broad-except
            logger.warning(f"Failed to read analysis output file {output_json_path}: {exc}")
            return None

        text = text.strip()
        if not text:
            return None

        payload = self._extract_analysis_payload(text)

        if payload is not None:
            payload = self._normalize_analysis_contract(payload)
            logger.info(f"Loaded analysis JSON from file fallback: {output_json_path}")
        return payload

    def _run_claude(
        self,
        prompt: str,
        record_path: Optional[Path] = None,
    ) -> Tuple[bool, Optional[Dict], Dict[str, Any]]:
        """Run Claude CLI and return the result.
        
        Returns:
            Tuple of (success, claude_json_output, llm_usage_summary)
        """
        try:
            logger.debug(f"Running Claude with prompt length: {len(prompt)}")
            claude_env = os.environ.copy()
            claude_env["CLAUDE_CONFIG_DIR"] = str(self._active_claude_config_dir)
            response = run_claude_cli(
                prompt=prompt,
                cwd=str(_path_config['repo_root']),
                env=claude_env,
                timeout=self.timeout,
                extra_args=["--dangerously-skip-permissions"],
                record_path=record_path,
                preferred_model_hint=DEFAULT_SELECTED_MODEL_HINT,
            )
            llm_usage = apply_claude_cli_usage_counters(response.usage_summary, response)
            
            logger.debug(f"Claude exit code: {response.returncode}")
            
            if response.returncode != 0:
                if response.error_type == "FileNotFoundError":
                    logger.error("Claude CLI not found")
                elif response.timed_out:
                    logger.error(f"Claude timed out after {self.timeout}s")
                logger.warning(f"Claude returned code {response.returncode}")
                if response.stderr:
                    logger.warning(f"Claude stderr: {response.stderr[:500]}")
                if response.stdout:
                    logger.debug(f"Claude stdout (truncated): {response.stdout[:500]}")
                return False, None, llm_usage
            
            # Parse Claude's JSON output
            if response.parsed_output:
                logger.debug(
                    f"Claude output parsed successfully, type: {response.parsed_output.get('type')}"
                )
                return True, response.parsed_output, llm_usage
            if response.stdout:
                logger.warning(f"Failed to parse Claude output: {response.parse_error}")
                logger.debug(f"Raw output: {response.stdout[:500]}")
            else:
                logger.warning("Claude returned empty stdout")
            
            return False, None, llm_usage
        except Exception as e:
            logger.error(f"Claude execution error: {e}")
            return False, None, {}

    def _parse_claude_result(self, claude_output: Dict) -> Optional[Dict[str, Any]]:
        """Parse the analysis result from Claude's JSON output.
        
        Claude returns a structure like:
        {"type": "result", "result": "```json\n{...}\n```", ...}
        
        We need to extract the JSON from the result text.
        """
        if not claude_output.get("result"):
            logger.warning("No result in Claude output")
            return None
        
        result_text = claude_output["result"]
        parsed = self._extract_analysis_payload(result_text)
        if parsed is not None:
            return self._normalize_analysis_contract(parsed)

        logger.warning("Failed to parse analysis JSON: no concrete analysis payload found")
        logger.debug(f"JSON text: {str(result_text)[:500]}")
        return None

    def _infer_verdict_from_text(self, text: str) -> Optional[str]:
        """Infer verdict from free-form Claude text."""
        if not text:
            return None

        # Match longer tokens first to avoid EXPLOITABLE matching inside
        # CONDITIONALLY_EXPLOITABLE / NOT_EXPLOITABLE.
        patterns = [
            ("CONDITIONALLY_EXPLOITABLE", r"\bCONDITIONALLY[_\s-]?EXPLOITABLE\b"),
            ("NOT_EXPLOITABLE", r"\bNOT[_\s-]?EXPLOITABLE\b"),
            ("LIBRARY_RISK", r"\bLIBRARY[_\s-]?RISK\b"),
            ("EXPLOITABLE", r"\bEXPLOITABLE\b"),
        ]
        for verdict, pattern in patterns:
            if re.search(pattern, text, flags=re.IGNORECASE):
                return verdict
        return None

    def _infer_confidence_from_text(self, text: str) -> Optional[str]:
        """Infer confidence level from free-form Claude text."""
        if not text:
            return None
        m = re.search(r"\b(high|medium|low)\s+confidence\b", text, flags=re.IGNORECASE)
        if m:
            return m.group(1).lower()
        return None

    def _recover_docker_verification(
        self,
        analysis: Dict[str, Any],
        evidence_dir: Optional[Path],
        commit_hash: str,
    ) -> Dict[str, Any]:
        """Recover docker_verification from evidence files when needed.

        Handles cases where Docker build/run started but Claude output is not
        strict JSON, timed out, or omitted docker_verification.
        """
        if not evidence_dir:
            return analysis

        evidence = self._build_docker_verification_from_evidence(
            evidence_dir=evidence_dir,
            commit_hash=commit_hash,
        )
        if not evidence:
            return analysis

        existing = analysis.get("docker_verification")
        if isinstance(existing, dict):
            # Keep Claude-provided structured result, but fill any empty fields
            # from filesystem evidence for better resilience.
            for key, value in evidence.items():
                if key not in existing or existing.get(key) is None:
                    existing[key] = value
            analysis["docker_verification"] = existing
        else:
            analysis["docker_verification"] = evidence

        # If Claude failed to return structured JSON but evidence shows exploit
        # confirmation, upgrade UNKNOWN/ERROR to EXPLOITABLE.
        verdict = normalize_exploitability_verdict(analysis.get("verdict"))
        if verdict in {"", "UNKNOWN", "ERROR"}:
            if analysis["docker_verification"].get("exploit_confirmed"):
                analysis["verdict"] = "EXPLOITABLE"
                analysis["confidence"] = analysis.get("confidence") or "high"

        return analysis

    def _build_docker_verification_from_evidence(
        self,
        evidence_dir: Path,
        commit_hash: str,
    ) -> Optional[Dict[str, Any]]:
        """Construct docker_verification using generated evidence files."""
        if not evidence_dir.exists():
            return None

        dockerfile = evidence_dir / "Dockerfile.exploit"
        build_log = evidence_dir / "docker_build.log"
        exec_out = evidence_dir / "execution_output.txt"

        poc_candidates = [
            evidence_dir / "exploit.py",
            evidence_dir / "exploit_simple.py",
            evidence_dir / "exploit.go",
            evidence_dir / "exploit.c",
            evidence_dir / "Exploit.java",
            evidence_dir / "exploit.js",
            evidence_dir / "exploit.rb",
            evidence_dir / "exploit.rs",
        ]
        poc_path = next((p for p in poc_candidates if p.exists()), None)

        has_activity = dockerfile.exists() or build_log.exists() or exec_out.exists() or (poc_path is not None)
        if not has_activity:
            return None

        build_text = ""
        if build_log.exists():
            try:
                build_text = build_log.read_text(encoding="utf-8", errors="replace")
            except Exception:
                build_text = ""

        run_text = ""
        if exec_out.exists():
            try:
                run_text = exec_out.read_text(encoding="utf-8", errors="replace")
            except Exception:
                run_text = ""

        build_success = False
        if build_text:
            build_success = bool(
                re.search(r"writing image sha256:|naming to docker\.io/library/", build_text, flags=re.IGNORECASE)
            )

        # If execution output exists, docker run likely started. Keep it robust
        # even when PoC itself reports EXPLOIT_FAILED.
        run_success = exec_out.exists()
        exploit_confirmed = bool(re.search(r"VULNERABILITY_CONFIRMED", run_text))

        short_hash = (commit_hash or "HEAD")[:8]
        execution_excerpt = (run_text[:2000] if run_text else "")
        error: Optional[str] = None

        if not build_success:
            if build_log.exists():
                if run_success:
                    # Build was likely successful enough to run, but the log may
                    # be truncated or lack final markers.
                    build_success = True
                else:
                    error = "Docker build did not complete (likely timeout/interruption)."
                    execution_excerpt = execution_excerpt or "Docker build did not complete."
            else:
                error = "Docker build log not found."

        if build_success and not run_success:
            error = "Docker run output not found; exploit command may not have executed."

        if run_success and not exploit_confirmed:
            error = error or "PoC executed but did not confirm exploitation."

        return {
            "enabled": True,
            "commit_hash": commit_hash or "HEAD",
            "build_success": bool(build_success),
            "run_success": bool(run_success),
            "exploit_confirmed": bool(exploit_confirmed),
            "execution_output": execution_excerpt or None,
            "poc_script_path": str(poc_path) if poc_path else None,
            "docker_image": f"exploit-test:{short_hash}",
            "error": error,
        }

    def _init_or_load_results(
        self,
        output_path: Path,
        findings_path: Path,
        repo_path: Path,
        software_profile_path: Optional[Path],
        total_vulns: int,
        current_findings: Dict[str, Dict[str, Any]],
        findings_signature: str,
        run_id: Optional[str] = None,
        claude_config_dir: Optional[Path] = None,
    ) -> Dict[str, Any]:
        """Initialize new results or load existing for resume."""
        if output_path.exists():
            try:
                existing = json.loads(output_path.read_text(encoding="utf-8"))
                if "results" in existing and "metadata" in existing:
                    original_count = len(existing.get("results", []))
                    retained_results = []
                    retry_dropped_results = []
                    stale_changed_count = 0
                    stale_scope_count = 0
                    retry_count = 0
                    existing_metadata = existing.setdefault("metadata", {})
                    previous_findings_signature = existing_metadata.get("findings_signature")
                    findings_signature_changed = (
                        isinstance(previous_findings_signature, str)
                        and previous_findings_signature != findings_signature
                    )
                    for item in existing.get("results", []):
                        classification = self._classify_persisted_result(
                            item,
                            current_total_vulns=total_vulns,
                            current_findings=current_findings,
                        )
                        if classification == "retryable":
                            retry_count += 1
                            retry_dropped_results.append(item)
                            continue
                        if classification == "stale_scope":
                            stale_scope_count += 1
                            continue
                        if classification == "stale_changed":
                            stale_changed_count += 1
                            continue
                        retained_results.append(item)

                    metadata = existing_metadata
                    previous_total_vulns = metadata.get("total_vulnerabilities")
                    metadata["total_vulnerabilities"] = total_vulns
                    metadata["findings_signature"] = findings_signature
                    metadata.setdefault(
                        "llm_usage_retried_attempts_summary",
                        aggregate_usage_summaries([]),
                    )
                    findings_changed = (
                        previous_total_vulns != total_vulns
                        or findings_signature_changed
                        or stale_scope_count > 0
                        or stale_changed_count > 0
                    )
                    if findings_changed:
                        logger.info(
                            "Findings set changed, refreshing resume metadata (%s -> %s)",
                            previous_total_vulns,
                            total_vulns,
                        )
                        metadata["completed_at"] = None
                    if retry_count > 0:
                        logger.info(
                            f"Resuming with retry: dropping {retry_count} ERROR/UNKNOWN results, "
                            f"retaining {len(retained_results)}/{original_count}"
                        )
                        existing["results"] = retained_results
                        metadata["llm_usage_retried_attempts_summary"] = merge_aggregated_usage_summaries(
                            [
                                metadata.get("llm_usage_retried_attempts_summary"),
                                self._aggregate_result_llm_usage_summary(retry_dropped_results),
                            ]
                        )
                        metadata["completed_at"] = None
                        self._update_summary(existing)
                    elif stale_scope_count > 0 or stale_changed_count > 0:
                        logger.info(
                            "Dropping %s stale results outside the current findings set",
                            stale_scope_count + stale_changed_count,
                        )
                        existing["results"] = retained_results
                        self._update_summary(existing)
                    else:
                        logger.info(f"Resuming from {original_count} existing results")
                        metadata["llm_usage_summary"] = self._build_llm_usage_summary(existing)
                    if run_id:
                        metadata["run_id"] = run_id
                    if claude_config_dir:
                        metadata["claude_runtime_dir"] = str(claude_config_dir)
                    return existing
            except Exception as exc:
                logger.warning(
                    "Failed to resume existing exploitability results from %s; reinitializing output: %s",
                    output_path,
                    exc,
                )
        
        return {
            "metadata": {
                "findings_source": str(findings_path),
                "software_profile": str(software_profile_path) if software_profile_path else None,
                "repository": str(repo_path),
                "total_vulnerabilities": total_vulns,
                "findings_signature": findings_signature,
                "started_at": datetime.now().isoformat(),
                "completed_at": None,
                "run_id": run_id,
                "claude_runtime_dir": str(claude_config_dir) if claude_config_dir else None,
                "llm_usage_retried_attempts_summary": aggregate_usage_summaries([]),
                "llm_usage_summary": aggregate_usage_summaries([]),
            },
            "summary": {
                "exploitable": 0,
                "conditionally_exploitable": 0,
                "library_risk": 0,
                "not_exploitable": 0,
                "error": 0,
            },
            "results": [],
        }

    def _update_summary(self, result_doc: Dict[str, Any]) -> None:
        """Update summary counts from results."""
        summary = {
            "exploitable": 0,
            "conditionally_exploitable": 0,
            "library_risk": 0,
            "not_exploitable": 0,
            "error": 0,
        }
        
        verdict_map = {
            "EXPLOITABLE": "exploitable",
            "CONDITIONALLY_EXPLOITABLE": "conditionally_exploitable",
            "LIBRARY_RISK": "library_risk",
            "NOT_EXPLOITABLE": "not_exploitable",
            "ERROR": "error",
            "UNKNOWN": "error",
        }
        
        for r in result_doc.get("results", []):
            verdict = normalize_exploitability_verdict(r.get("verdict")) or "ERROR"
            key = verdict_map.get(verdict, "error")
            summary[key] += 1
        
        result_doc["summary"] = summary
        metadata = result_doc.setdefault("metadata", {})
        metadata.setdefault("llm_usage_retried_attempts_summary", aggregate_usage_summaries([]))
        metadata["llm_usage_summary"] = self._build_llm_usage_summary(result_doc)

    @staticmethod
    def _coerce_result_llm_usage_summary(llm_usage: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        return coerce_aggregated_usage_summary(llm_usage)

    @classmethod
    def _aggregate_result_llm_usage_summary(cls, results: Any) -> Dict[str, Any]:
        return merge_aggregated_usage_summaries(
            cls._coerce_result_llm_usage_summary(item.get("llm_usage"))
            for item in (results or [])
            if isinstance(item, dict)
        )

    def _build_llm_usage_summary(self, result_doc: Dict[str, Any]) -> Dict[str, Any]:
        """Build cumulative LLM usage summary including retried attempts."""
        metadata = result_doc.setdefault("metadata", {})
        current_results_summary = self._aggregate_result_llm_usage_summary(result_doc.get("results", []))
        return merge_aggregated_usage_summaries(
            [
                metadata.get("llm_usage_retried_attempts_summary"),
                current_results_summary,
            ]
        )

    @staticmethod
    def _merge_results_for_save(
        existing_results: List[Dict[str, Any]],
        current_results: List[Dict[str, Any]],
        current_total_vulns: Optional[int] = None,
        current_findings: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> List[Dict[str, Any]]:
        """Merge current in-memory results with the latest on-disk results by finding id."""
        current_by_id: Dict[str, Dict[str, Any]] = {}
        merged_results: List[Dict[str, Any]] = []
        seen_ids: set[str] = set()

        for item in current_results:
            finding_id = SkillExploitabilityChecker._normalize_finding_id(item.get("finding_id"))
            if finding_id:
                current_by_id[finding_id] = item

        for item in existing_results:
            finding_id = SkillExploitabilityChecker._normalize_finding_id(item.get("finding_id"))
            if finding_id:
                if finding_id in seen_ids:
                    continue
                classification = SkillExploitabilityChecker._classify_persisted_result(
                    item,
                    current_total_vulns=current_total_vulns,
                    current_findings=current_findings,
                )
                if classification not in {"keep", "retryable"}:
                    continue
                if finding_id in current_by_id:
                    merged_results.append(current_by_id[finding_id])
                    seen_ids.add(finding_id)
                    continue
                # Do not resurrect stale ERROR/UNKNOWN rows that a resumed run
                # intentionally dropped for retry.
                if classification == "retryable":
                    continue
                merged_results.append(item)
                seen_ids.add(finding_id)
                continue
            merged_results.append(item)

        for item in current_results:
            finding_id = SkillExploitabilityChecker._normalize_finding_id(item.get("finding_id"))
            if finding_id and finding_id in seen_ids:
                continue
            if finding_id:
                seen_ids.add(finding_id)
            merged_results.append(item)

        return merged_results

    def _build_results_doc_for_save(
        self,
        output_path: Path,
        result_doc: Dict[str, Any],
        current_findings: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Build the merged result document that should be written to disk."""
        merged_doc: Dict[str, Any] = dict(result_doc)
        merged_doc["metadata"] = dict(result_doc.get("metadata", {}))
        merged_doc["summary"] = dict(result_doc.get("summary", {}))
        merged_doc["results"] = list(result_doc.get("results", []))

        if output_path.exists():
            try:
                existing = json.loads(output_path.read_text(encoding="utf-8"))
                existing_results = existing.get("results", [])
                if isinstance(existing_results, list):
                    current_total_vulns = merged_doc.get("metadata", {}).get("total_vulnerabilities")
                    merged_doc["results"] = self._merge_results_for_save(
                        existing_results=existing_results,
                        current_results=merged_doc["results"],
                        current_total_vulns=current_total_vulns if isinstance(current_total_vulns, int) else None,
                        current_findings=current_findings,
                    )
                    existing_metadata = existing.get("metadata", {})
                    if (
                        isinstance(existing_metadata, dict)
                        and get_exploitability_output_state(existing) == EXPLOITABILITY_OUTPUT_STATE_COMPLETE
                    ):
                        merged_metadata = merged_doc.setdefault("metadata", {})
                        merged_completed_at = merged_metadata.get("completed_at")
                        if not isinstance(merged_completed_at, str) or not merged_completed_at.strip():
                            merged_metadata["completed_at"] = existing_metadata["completed_at"]
                            if (
                                get_exploitability_output_state(merged_doc)
                                != EXPLOITABILITY_OUTPUT_STATE_COMPLETE
                            ):
                                merged_metadata["completed_at"] = None
            except Exception as exc:
                logger.warning(f"Failed to merge existing exploitability results from {output_path}: {exc}")

        self._update_summary(merged_doc)
        return merged_doc

    def _save_results(
        self,
        output_path: Path,
        result_doc: Dict[str, Any],
        current_findings: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Save results to file and return the merged document that was written."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        merged_doc = self._build_results_doc_for_save(
            output_path,
            result_doc,
            current_findings=current_findings,
        )
        write_atomic_json(output_path, merged_doc)
        return merged_doc

    def _create_error_vuln_result(
        self,
        vuln: Dict[str, Any],
        finding_id: str,
        error_msg: str,
    ) -> Dict[str, Any]:
        """Create error result for a failed vulnerability analysis."""
        normalized_result = self._normalize_analysis_contract({
            "finding_id": finding_id,
            "original_finding": vuln,
            "verdict": "ERROR",
            "confidence": "low",
            "error": error_msg,
            "verdict_rationale": error_msg,
            "preconditions": [],
            "static_evidence": [],
            "dynamic_plan": [],
            "docker_verification": None,
            "open_questions": [],
            "sink_analysis": None,
            "source_analysis": None,
            "sanitizer_analysis": None,
            "attack_scenario": None,
            "payload": None,
            "remediation": None,
        })
        if normalized_result is None:
            raise RuntimeError("Failed to build error result contract")
        return normalized_result

    def _error_result(self, message: str) -> Dict[str, Any]:
        """Create an error result."""
        return {
            "status": "error",
            "message": message,
            "results": []
        }
