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
    ) -> Dict[str, Any]:
        """Check exploitability of vulnerabilities in a findings file.
        
        Processes each vulnerability individually and saves progress.
        
        Args:
            findings_path: Path to agentic_vuln_findings.json
            repo_path: Path to the target repository
            output_path: Path to write exploitability.json
            software_profile_path: Optional path to software_profile.json
            
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
            
            # Analyze single vulnerability
            vuln_result = self._analyze_single_vuln(
                vuln=vuln,
                finding_id=finding_id,
                repo_path=repo_path,
                software_profile_path=software_profile_path,
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
    ) -> Dict[str, Any]:
        """Analyze a single vulnerability using Claude.
        
        Args:
            vuln: Vulnerability dictionary from findings
            finding_id: Unique ID for this vulnerability
            repo_path: Path to the repository
            software_profile_path: Optional path to software profile
            
        Returns:
            Analysis result dictionary
        """
        prompt = self._build_prompt(vuln, repo_path, software_profile_path)
        
        # Run Claude and get JSON result
        success, claude_result = self._run_claude(prompt)
        
        if success and claude_result:
            # Parse the result text from Claude's JSON output
            analysis = self._parse_claude_result(claude_result)
            if analysis:
                analysis["finding_id"] = finding_id
                analysis["original_finding"] = vuln
                return analysis
        
        return self._create_error_vuln_result(vuln, finding_id, "Claude analysis failed")

    def _build_prompt(
        self,
        vuln: Dict[str, Any],
        repo_path: Path,
        software_profile_path: Optional[Path],
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
            "Verify the code path exists. Output JSON only:",
            '{"verdict":"EXPLOITABLE|CONDITIONALLY_EXPLOITABLE|LIBRARY_RISK|NOT_EXPLOITABLE",',
            '"confidence":"high|medium|low",',
            '"sink_analysis":{"confirmed":true/false,"sink_type":"...","protection_status":"none|partial|full"},',
            '"source_analysis":{"sources_found":[{"type":"cli|file|api","location":"..."}],"attack_path":["..."]},',
            '"attack_scenario":{"description":"...","steps":["..."],"impact":"..."},',
            '"remediation":{"recommendation":"..."}}',
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
            
            # Try to create a minimal result from the text
            return {
                "verdict": "UNKNOWN",
                "confidence": "low",
                "raw_result": result_text[:1000],
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
) -> Dict[str, Any]:
    """Convenience function to check exploitability for a single findings file.
    
    Args:
        findings_path: Path to agentic_vuln_findings.json
        repo_path: Path to the target repository
        output_path: Path to write exploitability.json
        software_profile_path: Optional path to software_profile.json
        timeout: Timeout in seconds for each Claude CLI call
        
    Returns:
        Analysis result dictionary
    """
    checker = SkillExploitabilityChecker(timeout=timeout)
    return checker.check_single(
        findings_path=findings_path,
        repo_path=repo_path,
        output_path=output_path,
        software_profile_path=software_profile_path,
    )
