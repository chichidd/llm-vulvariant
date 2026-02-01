"""Skill-based exploitability checker using Claude Code.

This module uses the .claude/skills/check-exploitability skill to verify
whether detected vulnerabilities are actually exploitable.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from config import _path_config
from utils.logger import get_logger

logger = get_logger(__name__)


class SkillExploitabilityChecker:
    """Check vulnerability exploitability using Claude Code skill."""

    def __init__(self, timeout: int = 600):
        """Initialize the checker.
        
        Args:
            timeout: Timeout in seconds for Claude CLI execution (default: 600)
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
        """Check exploitability of vulnerabilities in a single findings file.
        
        Args:
            findings_path: Path to agentic_vuln_findings.json
            repo_path: Path to the target repository
            output_path: Path to write exploitability.json
            software_profile_path: Optional path to software_profile.json
            
        Returns:
            Dictionary with analysis results and metadata
        """
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
            return {
                "status": "success",
                "message": "No vulnerabilities to analyze",
                "findings_path": str(findings_path),
                "results": []
            }

        logger.info(f"Analyzing {len(vulnerabilities)} vulnerabilities from {findings_path}")

        # Build and run Claude prompt
        success = self._run_claude_analysis(
            findings_path=findings_path,
            repo_path=repo_path,
            output_path=output_path,
            software_profile_path=software_profile_path,
            num_vulnerabilities=len(vulnerabilities),
        )

        if not success:
            return self._error_result("Claude analysis failed")

        # Load and return results
        if output_path.exists():
            try:
                result = json.loads(output_path.read_text(encoding="utf-8"))
                logger.info(f"Exploitability analysis saved to {output_path}")
                return {
                    "status": "success",
                    "findings_path": str(findings_path),
                    "output_path": str(output_path),
                    "num_analyzed": len(vulnerabilities),
                    "results": result,
                }
            except Exception as e:
                logger.error(f"Failed to parse output: {e}")
                return self._error_result(f"Failed to parse output: {e}")
        else:
            return self._error_result(f"Output file not created: {output_path}")

    def _run_claude_analysis(
        self,
        findings_path: Path,
        repo_path: Path,
        output_path: Path,
        software_profile_path: Optional[Path],
        num_vulnerabilities: int,
    ) -> bool:
        """Run Claude CLI to perform exploitability analysis.
        
        Returns:
            True if analysis completed successfully, False otherwise
        """
        # Build prompt
        prompt_parts = [
            f"Use the `{self.skill_name}` skill to analyze the {num_vulnerabilities} vulnerabilities",
            f"described in {findings_path.resolve()}",
        ]

        if software_profile_path and software_profile_path.exists():
            prompt_parts.append(f"using the software profile at {software_profile_path.resolve()}")

        prompt_parts.extend([
            f"for the repository at {repo_path.resolve()}.",
            f"Write the complete exploitability analysis report as JSON to {output_path.resolve()}.",
            "Analyze each vulnerability following the skill's Procedure (Phase 1-5).",
            "The output must follow the Output Format specified in the skill documentation.",
        ])

        prompt = " ".join(prompt_parts)
        logger.info(f"Running Claude analysis: {prompt[:200]}...")

        cmd = ["claude", "-p", prompt]

        try:
            result = subprocess.run(
                cmd,
                check=True,
                capture_output=True,
                text=True,
                cwd=str(_path_config['repo_root']),
                timeout=self.timeout,
            )
            logger.debug(f"Claude stdout: {result.stdout[:500]}")
            return True
        except subprocess.TimeoutExpired:
            logger.error(f"Claude analysis timed out after {self.timeout}s")
            return False
        except subprocess.CalledProcessError as e:
            logger.error(f"Claude failed (code {e.returncode}): {e.stderr[:500]}")
            return False
        except FileNotFoundError:
            logger.error("Claude CLI not found. Install with: npm install -g @anthropic-ai/claude-code")
            return False

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
    timeout: int = 600,
) -> Dict[str, Any]:
    """Convenience function to check exploitability for a single findings file.
    
    Args:
        findings_path: Path to agentic_vuln_findings.json
        repo_path: Path to the target repository
        output_path: Path to write exploitability.json
        software_profile_path: Optional path to software_profile.json
        timeout: Timeout in seconds for Claude CLI
        
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
