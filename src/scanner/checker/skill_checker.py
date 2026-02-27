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

import json
import re
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from config import _path_config
from utils.logger import get_logger

logger = get_logger(__name__)


class SkillExploitabilityChecker:
    """Check vulnerability exploitability using Claude Code skill."""

    def __init__(self, timeout: int = 600):
        """Initialize the checker.
        
        Args:
            timeout: Timeout in seconds for each Claude CLI call (default: 600 = 10 minutes)
        """
        self.timeout = timeout
        self.skill_name = "check-exploitability"
        
        if not self._skill_exists():
            logger.warning(f"Skill '{self.skill_name}' not found at {self._get_skill_path()}")

    def _get_skill_path(self) -> Path:
        """Get the path to the skill directory."""
        return _path_config['skill_path'] / self.skill_name

    def _skill_exists(self) -> bool:
        """Check if the skill exists."""
        return self._get_skill_path().exists()

    def check_single(
        self,
        findings_path: Path,
        repo_path: Path,
        output_path: Path,
        software_profile_path: Optional[Path] = None,
        commit_hash: str = "",
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

        if not vulnerabilities:
            logger.info(f"No vulnerabilities found in {findings_path}")
            return self._create_empty_result(findings_path)

        logger.info(f"Analyzing {len(vulnerabilities)} vulnerabilities from {findings_path}")

        # Initialize or load existing results
        result_doc = self._init_or_load_results(
            output_path, findings_path, repo_path, software_profile_path, len(vulnerabilities)
        )

        # Get already processed indices
        processed_ids = {r.get("finding_id") for r in result_doc.get("results", [])}
        
        # Process each vulnerability
        for idx, vuln in enumerate(vulnerabilities):
            finding_id = f"vuln_{idx:03d}"
            
            if finding_id in processed_ids:
                logger.info(f"[{idx+1}/{len(vulnerabilities)}] Skipping {finding_id} (already processed)")
                continue
            
            logger.info(f"[{idx+1}/{len(vulnerabilities)}] Analyzing {finding_id}: {vuln.get('file_path', 'unknown')}")
            
            # Prepare evidence directory for Docker PoC verification
            evidence_dir = output_path.parent / "evidence" / finding_id
            evidence_dir.mkdir(parents=True, exist_ok=True)
            
            # Analyze single vulnerability
            vuln_result = self._analyze_single_vuln(
                vuln=vuln,
                finding_id=finding_id,
                repo_path=repo_path,
                software_profile_path=software_profile_path,
                commit_hash=commit_hash,
                evidence_dir=evidence_dir,
            )
            
            # Append result and save
            result_doc["results"].append(vuln_result)
            self._update_summary(result_doc)
            self._save_results(output_path, result_doc)
            
            logger.info(f"  -> Verdict: {vuln_result.get('verdict', 'UNKNOWN')}")
            if vuln_result.get('verdict') == 'EXPLOITABLE':
                logger.info(f"     Source: {vuln_result.get('source_analysis')}")
        # Final update
        result_doc["metadata"]["completed_at"] = datetime.now().isoformat()
        self._save_results(output_path, result_doc)
        
        return {
            "status": "success",
            "findings_path": str(findings_path),
            "output_path": str(output_path),
            "num_analyzed": len(vulnerabilities),
            "summary": result_doc.get("summary", {}),
        }

    def _analyze_single_vuln(
        self,
        vuln: Dict[str, Any],
        finding_id: str,
        repo_path: Path,
        software_profile_path: Optional[Path],
        commit_hash: str = "",
        evidence_dir: Optional[Path] = None,
    ) -> Dict[str, Any]:
        """Analyze a single vulnerability using Claude.
        
        Args:
            vuln: Vulnerability dictionary from findings
            finding_id: Unique ID for this vulnerability
            repo_path: Path to the repository
            software_profile_path: Optional path to software profile
            commit_hash: Commit hash to check out inside Docker
            evidence_dir: Directory for PoC script and Docker build artefacts
            
        Returns:
            Analysis result dictionary
        """
        prompt = self._build_prompt(
            vuln, repo_path, software_profile_path,
            commit_hash=commit_hash,
            evidence_dir=evidence_dir,
        )
        
        # Run Claude and get JSON result
        success, claude_result = self._run_claude(prompt)

        analysis: Optional[Dict[str, Any]] = None
        if success and claude_result:
            # Parse the result text from Claude's JSON output
            analysis = self._parse_claude_result(claude_result)

        if not analysis:
            analysis = self._create_error_vuln_result(vuln, finding_id, "Claude analysis failed")

        analysis["finding_id"] = finding_id
        analysis["original_finding"] = vuln

        # Recover and normalize docker verification using on-disk evidence.
        # This makes results robust when Claude returns non-JSON output,
        # or when Docker verification only partially completes.
        analysis = self._recover_docker_verification(
            analysis=analysis,
            evidence_dir=evidence_dir,
            commit_hash=commit_hash,
        )

        return analysis

    def _build_prompt(
        self,
        vuln: Dict[str, Any],
        repo_path: Path,
        software_profile_path: Optional[Path],
        commit_hash: str = "",
        evidence_dir: Optional[Path] = None,
    ) -> str:
        """Build Claude prompt for single vulnerability analysis."""
        import os

        # Build concise vulnerability summary
        file_path = vuln.get('file_path', 'unknown')
        vuln_type = vuln.get('vulnerability_type', 'unknown')
        evidence = vuln.get('evidence', '')[:400]
        description = vuln.get('description', '')[:200]

        # Collect host API key to forward into the container
        api_key = (
            os.environ.get("DEEPSEEK_API_KEY")
            or os.environ.get("OPENAI_API_KEY")
            or ""
        )
        
        lines = [
            f"Quick vulnerability check using {self.skill_name} skill:",
            f"File: {file_path}",
            f"Type: {vuln_type}",
            f"Evidence: {evidence}",
            f"Description: {description}",
            "",
            f"Repository: {repo_path.resolve()}",
            "",
            "Verify the code path exists. Output JSON only:",
            '{"verdict":"EXPLOITABLE|CONDITIONALLY_EXPLOITABLE|LIBRARY_RISK|NOT_EXPLOITABLE",',
            '"confidence":"high|medium|low",',
            '"sink_analysis":{"confirmed":true/false,"sink_type":"...","protection_status":"none|partial|full"},',
            '"source_analysis":{"sources_found":[{"type":"cli|file|api","location":"..."}],"attack_path":["..."]},',
            '"attack_scenario":{"description":"...","steps":["..."],"impact":"..."},',
            '"remediation":{"recommendation":"..."}}',
            "",
            "--- DOCKER VERIFICATION ---",
            "DOCKER_VERIFY: true",
            f"COMMIT_HASH: {commit_hash}" if commit_hash else "COMMIT_HASH: HEAD",
            f"REPO_PATH: {repo_path.resolve()}",
            f"EVIDENCE_DIR: {evidence_dir.resolve() if evidence_dir else str(repo_path.resolve() / 'evidence')}",
            f"API_KEY: {api_key}",
            "",
            "After the static analysis (phases 1-4), if verdict is EXPLOITABLE, also run",
            "Phase 5 (Docker PoC Verification) from the skill and include the",
            "'docker_verification' object in the output JSON.",
        ]
        
        return "\n".join(lines)

    def _run_claude(self, prompt: str) -> Tuple[bool, Optional[Dict]]:
        """Run Claude CLI and return the result.
        
        Returns:
            Tuple of (success, claude_json_output)
        """
        cmd = [
            "claude", "-p",
            "--dangerously-skip-permissions",
            "--output-format", "json",
            prompt
        ]
        
        try:
            logger.debug(f"Running Claude with prompt length: {len(prompt)}")
            result = subprocess.run(
                cmd,
                check=False,
                capture_output=True,
                text=True,
                cwd=str(_path_config['repo_root']),
                timeout=self.timeout,
            )
            
            logger.debug(f"Claude exit code: {result.returncode}")
            
            if result.returncode != 0:
                logger.warning(f"Claude returned code {result.returncode}")
                if result.stderr:
                    logger.warning(f"Claude stderr: {result.stderr[:500]}")
                if result.stdout:
                    logger.debug(f"Claude stdout (truncated): {result.stdout[:500]}")
                return False, None
            
            # Parse Claude's JSON output
            if result.stdout:
                try:
                    claude_output = json.loads(result.stdout)
                    logger.debug(f"Claude output parsed successfully, type: {claude_output.get('type')}")
                    return True, claude_output
                except json.JSONDecodeError as e:
                    logger.warning(f"Failed to parse Claude output: {e}")
                    logger.debug(f"Raw output: {result.stdout[:500]}")
            else:
                logger.warning("Claude returned empty stdout")
            
            return False, None
            
        except subprocess.TimeoutExpired:
            logger.error(f"Claude timed out after {self.timeout}s")
            return False, None
        except FileNotFoundError:
            logger.error("Claude CLI not found")
            return False, None
        except Exception as e:
            logger.error(f"Claude execution error: {e}")
            return False, None

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
        
        # Try to extract JSON from the result text
        # Remove markdown code blocks if present
        json_match = re.search(r'```(?:json)?\s*\n?(.*?)\n?```', result_text, re.DOTALL)
        if json_match:
            json_str = json_match.group(1).strip()
        else:
            # Try to parse the whole result as JSON
            json_str = result_text.strip()
        
        try:
            return json.loads(json_str)
        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse analysis JSON: {e}")
            logger.debug(f"JSON string: {json_str[:500]}")

            inferred_verdict = self._infer_verdict_from_text(result_text)
            inferred_confidence = self._infer_confidence_from_text(result_text)

            # Try to create a minimal result from the text
            return {
                "verdict": inferred_verdict or "UNKNOWN",
                "confidence": inferred_confidence or "low",
                "raw_result": result_text[:2000],
            }

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
        verdict = str(analysis.get("verdict", "")).upper()
        if verdict in {"", "UNKNOWN", "ERROR"}:
            if analysis["docker_verification"].get("exploit_confirmed"):
                analysis["verdict"] = "EXPLOITABLE"
                analysis["confidence"] = analysis.get("confidence") or "high"
            else:
                inferred = self._infer_verdict_from_text(str(analysis.get("raw_result", "")))
                if inferred:
                    analysis["verdict"] = inferred
                    analysis["confidence"] = analysis.get("confidence") or (
                        self._infer_confidence_from_text(str(analysis.get("raw_result", ""))) or "low"
                    )

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
    ) -> Dict[str, Any]:
        """Initialize new results or load existing for resume."""
        if output_path.exists():
            try:
                existing = json.loads(output_path.read_text(encoding="utf-8"))
                if "results" in existing and "metadata" in existing:
                    logger.info(f"Resuming from {len(existing['results'])} existing results")
                    return existing
            except Exception:
                pass
        
        return {
            "metadata": {
                "findings_source": str(findings_path),
                "software_profile": str(software_profile_path) if software_profile_path else None,
                "repository": str(repo_path),
                "total_vulnerabilities": total_vulns,
                "started_at": datetime.now().isoformat(),
                "completed_at": None,
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
            verdict = r.get("verdict", "ERROR").upper()
            key = verdict_map.get(verdict, "error")
            summary[key] += 1
        
        result_doc["summary"] = summary

    def _save_results(self, output_path: Path, result_doc: Dict[str, Any]) -> None:
        """Save results to file."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps(result_doc, indent=2, ensure_ascii=False), 
            encoding="utf-8"
        )

    def _create_empty_result(self, findings_path: Path) -> Dict[str, Any]:
        """Create result for empty findings."""
        return {
            "status": "success",
            "message": "No vulnerabilities to analyze",
            "findings_path": str(findings_path),
            "results": []
        }

    def _create_error_vuln_result(
        self,
        vuln: Dict[str, Any],
        finding_id: str,
        error_msg: str,
    ) -> Dict[str, Any]:
        """Create error result for a failed vulnerability analysis."""
        return {
            "finding_id": finding_id,
            "original_finding": vuln,
            "verdict": "ERROR",
            "confidence": "low",
            "error": error_msg,
            "sink_analysis": None,
            "source_analysis": None,
            "sanitizer_analysis": None,
            "attack_scenario": None,
            "payload": None,
            "remediation": None,
        }

    def _error_result(self, message: str) -> Dict[str, Any]:
        """Create an error result."""
        return {
            "status": "error",
            "message": message,
            "results": []
        }


def check_exploitability_single(
    findings_path: Path,
    repo_path: Path,
    output_path: Path,
    software_profile_path: Optional[Path] = None,
    timeout: int = 300,
    commit_hash: str = "",
) -> Dict[str, Any]:
    """Convenience function to check exploitability for a single findings file.
    
    Args:
        findings_path: Path to agentic_vuln_findings.json
        repo_path: Path to the target repository
        output_path: Path to write exploitability.json
        software_profile_path: Optional path to software_profile.json
        timeout: Timeout in seconds for each Claude CLI call
        commit_hash: Commit hash for reproducible Docker builds
        
    Returns:
        Analysis result dictionary
    """
    checker = SkillExploitabilityChecker(timeout=timeout)
    return checker.check_single(
        findings_path=findings_path,
        repo_path=repo_path,
        output_path=output_path,
        software_profile_path=software_profile_path,
        commit_hash=commit_hash,
    )
