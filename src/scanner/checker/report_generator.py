"""Security report generator for vulnerability findings.

Generates two types of reports:
1. GitHub Private Vulnerability Reporting (GHSA) format
2. Comprehensive security research report (Markdown)

Both reports are designed to be self-contained, reproducible, and suitable
for submission to project maintainers.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from utils.language import get_run_cmd
from utils.logger import get_logger

logger = get_logger(__name__)

# Exploit file name per language
_EXPLOIT_FILES = {
    "python": "exploit.py",
    "cpp": "exploit.c",
    "go": "exploit.go",
    "java": "Exploit.java",
    "javascript": "exploit.js",
    "ruby": "exploit.rb",
    "rust": "exploit.rs",
    "csharp": "Exploit.cs",
}


class ReportGenerator:
    """Generate security reports from vulnerability analysis and verification results.

    Produces:
    - GHSA advisory (Markdown suitable for GitHub's security advisory form)
    - Full security research report (detailed Markdown with reproduction steps)
    """

    def __init__(
        self,
        repo_name: str,
        commit_hash: str,
        repo_url: Optional[str] = None,
        language: str = "python",
    ):
        """Initialize the report generator.

        Args:
            repo_name: Target repository name.
            commit_hash: Commit hash analyzed.
            repo_url: GitHub repository URL (optional, auto-generated if None).
            language: Project language (python, cpp, go, java, javascript, etc.).
        """
        self.repo_name = repo_name
        self.commit_hash = commit_hash
        self.repo_url = repo_url or f"https://github.com/OWNER/{repo_name}"
        self.language = language
        self._exploit_file = _EXPLOIT_FILES.get(language, "exploit.py")

    def generate_all(
        self,
        exploitability_results: Dict[str, Any],
        output_dir: Optional[Path] = None,
        cve_id: Optional[str] = None,
        only_exploitable: bool = False,
    ) -> Dict[str, str]:
        """Generate all report types.

        Args:
            exploitability_results: Content of exploitability.json.
            output_dir: Directory to write reports. If None, only returns content.
            cve_id: CVE ID if assigned.

        Returns:
            Dict mapping report type to content string.
        """
        reports = {}

        # Generate GHSA report for each exploitable finding
        ghsa_reports = self.generate_ghsa_reports(
            exploitability_results,
            cve_id,
            only_exploitable=only_exploitable,
        )
        reports["ghsa_reports"] = ghsa_reports

        # Generate comprehensive research report
        full_report = self.generate_full_report(
            exploitability_results,
            cve_id,
            only_exploitable=only_exploitable,
        )
        reports["full_report"] = full_report

        # Write to files if output_dir specified
        if output_dir:
            output_dir.mkdir(parents=True, exist_ok=True)

            # Write individual GHSA reports
            for i, ghsa in enumerate(ghsa_reports):
                finding_id = ghsa.get("finding_id", f"vuln_{i:03d}")
                ghsa_path = output_dir / f"ghsa_{finding_id}.md"
                ghsa_path.write_text(ghsa["content"], encoding="utf-8")
                logger.info(f"GHSA report written: {ghsa_path}")

            # Write full report
            full_path = output_dir / "security_report.md"
            full_path.write_text(full_report, encoding="utf-8")
            logger.info(f"Full report written: {full_path}")

            # Write GHSA summary JSON (for easy form filling)
            ghsa_json_path = output_dir / "ghsa_advisory_data.json"
            ghsa_json_data = [
                {
                    "finding_id": g["finding_id"],
                    "title": g["title"],
                    "severity": g["severity"],
                    "cvss_vector": g.get("cvss_vector", ""),
                    "cwe_id": g.get("cwe_id", ""),
                    "affected_files": g.get("affected_files", []),
                }
                for g in ghsa_reports
            ]
            ghsa_json_path.write_text(
                json.dumps(ghsa_json_data, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )

        return reports

    # ---- GHSA Report Generation ----

    def generate_ghsa_reports(
        self,
        exploitability_results: Dict[str, Any],
        cve_id: Optional[str] = None,
        only_exploitable: bool = False,
    ) -> List[Dict[str, Any]]:
        """Generate GitHub Security Advisory reports for exploitable findings.

        Each GHSA report follows GitHub's private vulnerability reporting format.

        Returns:
            List of dicts with finding_id, title, content, severity, etc.
        """
        reports = []
        results = exploitability_results.get("results", [])
        verifications = self._extract_finding_verifications(exploitability_results)
        allowed_verdicts = {"EXPLOITABLE"} if only_exploitable else {
            "EXPLOITABLE",
            "CONDITIONALLY_EXPLOITABLE",
        }

        for result in results:
            verdict = result.get("verdict", "").upper()
            if verdict not in allowed_verdicts:
                continue

            finding_id = result.get("finding_id", "unknown")
            vuln_info = result.get("original_finding", {})
            docker_v = verifications.get(finding_id) or result.get("docker_verification")

            report = self._build_ghsa_report(
                finding_id=finding_id,
                vuln_info=vuln_info,
                exploitability=result,
                docker_verification=docker_v,
                cve_id=cve_id,
            )
            reports.append(report)

        return reports

    def _build_ghsa_report(
        self,
        finding_id: str,
        vuln_info: Dict[str, Any],
        exploitability: Dict[str, Any],
        docker_verification: Optional[Dict[str, Any]] = None,
        cve_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Build a single GHSA advisory report."""
        file_path = vuln_info.get("file_path", "unknown")
        vuln_type = vuln_info.get("vulnerability_type", "unknown")
        description = vuln_info.get("description", "")
        evidence = vuln_info.get("evidence", "")
        attack_scenario = vuln_info.get("attack_scenario", "")
        verdict = exploitability.get("verdict", "UNKNOWN")

        # Map vulnerability types to CWE IDs
        cwe_map = {
            "deserialization": ("CWE-502", "Deserialization of Untrusted Data"),
            "command_injection": ("CWE-78", "OS Command Injection"),
            "code_injection": ("CWE-94", "Code Injection"),
            "code_execution": ("CWE-94", "Code Injection"),
            "path_traversal": ("CWE-22", "Path Traversal"),
            "ssrf": ("CWE-918", "Server-Side Request Forgery"),
            "sql_injection": ("CWE-89", "SQL Injection"),
            "xxe": ("CWE-611", "XML External Entity"),
            "xss": ("CWE-79", "Cross-site Scripting"),
        }
        cwe_id, cwe_name = cwe_map.get(vuln_type.lower(), ("CWE-20", "Improper Input Validation"))

        # Determine severity
        severity = self._determine_severity(vuln_type, verdict, exploitability)
        cvss_vector = self._generate_cvss_vector(vuln_type, exploitability)

        # Title
        vuln_type_display = vuln_type.replace("_", " ").title()
        title = f"{vuln_type_display} in {file_path}"

        # Build attack path description
        source_analysis = exploitability.get("source_analysis", {})
        attack_path = source_analysis.get("attack_path", [])
        sources = source_analysis.get("sources_found", [])

        # Docker verification section
        docker_section = ""
        if self._docker_verification_verdict(docker_verification) == "VERIFIED_EXPLOITABLE":
            docker_section = self._build_docker_evidence_section(docker_verification)

        # Build the GHSA content
        content = self._render_ghsa_template(
            title=title,
            cve_id=cve_id,
            cwe_id=cwe_id,
            cwe_name=cwe_name,
            severity=severity,
            cvss_vector=cvss_vector,
            file_path=file_path,
            vuln_type=vuln_type,
            description=description,
            evidence=evidence,
            attack_scenario=attack_scenario,
            attack_path=attack_path,
            sources=sources,
            exploitability=exploitability,
            docker_section=docker_section,
        )

        return {
            "finding_id": finding_id,
            "title": title,
            "content": content,
            "severity": severity,
            "cvss_vector": cvss_vector,
            "cwe_id": cwe_id,
            "affected_files": [file_path],
        }

    def _render_ghsa_template(self, **kwargs) -> str:
        """Render the GHSA advisory Markdown template."""
        title = kwargs["title"]
        cve_id = kwargs.get("cve_id") or "Not yet assigned"
        cwe_id = kwargs["cwe_id"]
        cwe_name = kwargs["cwe_name"]
        severity = kwargs["severity"]
        cvss_vector = kwargs["cvss_vector"]
        file_path = kwargs["file_path"]
        vuln_type = kwargs["vuln_type"]
        description = kwargs["description"]
        evidence = kwargs["evidence"]
        attack_scenario = kwargs["attack_scenario"]
        attack_path = kwargs.get("attack_path", [])
        sources = kwargs.get("sources", [])
        exploitability = kwargs.get("exploitability", {})
        docker_section = kwargs.get("docker_section", "")

        # Build attack path text
        path_text = ""
        if attack_path:
            path_text = "\n### Attack Path (Call Chain)\n\n"
            for i, step in enumerate(attack_path, 1):
                path_text += f"{i}. `{step}`\n"

        # Build sources text
        sources_text = ""
        if sources:
            sources_text = "\n### User-Controllable Sources\n\n"
            for s in sources:
                sources_text += f"- **{s.get('type', 'unknown')}**: `{s.get('location', '')}` (controllability: {s.get('controllability', 'unknown')})\n"

        # Remediation
        remediation = exploitability.get("remediation", {})
        remediation_text = remediation.get("recommendation", "No specific remediation provided.")
        remediation_ref = remediation.get("reference", "")

        # Sink analysis
        sink = exploitability.get("sink_analysis", {})
        sink_text = ""
        if sink:
            sink_text = f"""
### Sink Analysis

- **Sink Type**: {sink.get('sink_type', 'N/A')}
- **Confirmed**: {sink.get('confirmed', False)}
- **Protection Status**: {sink.get('protection_status', 'N/A')}
- **Code Evidence**: `{sink.get('code_evidence', 'N/A')}`
"""

        return f"""# {title}

## Summary

| Field | Value |
|-------|-------|
| **CVE ID** | {cve_id} |
| **CWE** | {cwe_id}: {cwe_name} |
| **Severity** | {severity} |
| **CVSS Vector** | `{cvss_vector}` |
| **Affected Component** | `{file_path}` |
| **Vulnerability Type** | {vuln_type} |
| **Repository** | [{self.repo_name}]({self.repo_url}) |
| **Affected Commit** | `{self.commit_hash[:12]}` |

## Description

{description}

## Vulnerability Details

### Evidence

```
{evidence}
```
{sink_text}
{sources_text}
{path_text}

## Attack Scenario

{attack_scenario}

## Impact

An attacker could exploit this vulnerability to achieve:
- **{self._impact_description(vuln_type)}**

{docker_section}

## Reproduction Steps

### Prerequisites
1. Clone the repository at commit `{self.commit_hash[:12]}`:
   ```bash
   git clone {self.repo_url}.git
   cd {self.repo_name}
   git checkout {self.commit_hash}
   ```
2. Install dependencies as described in the project's README.

### Docker Reproduction (Recommended)

```bash
# Build the vulnerable environment
docker build -t vuln-{self.repo_name.lower()} -f Dockerfile .

# Run the PoC
docker run --rm --network=none -v $(pwd)/poc:/poc vuln-{self.repo_name.lower()} {get_run_cmd(self.language).replace('/evidence/', '/poc/')}
```

### Manual Reproduction
{self._manual_reproduction_steps(vuln_type, file_path, attack_scenario, evidence)}

## Remediation

{remediation_text}
{f'Reference: {remediation_ref}' if remediation_ref else ''}

## Timeline

- **Discovered**: {datetime.now().strftime('%Y-%m-%d')}
- **Reported**: {datetime.now().strftime('%Y-%m-%d')}

---
*This report was generated by LLM-VulVariant automated vulnerability analysis.*
"""

    def _build_docker_evidence_section(self, docker_verification: Dict[str, Any]) -> str:
        """Build the Docker verification evidence section."""
        lines = [
            "## Docker Verification Evidence",
            "",
            "This vulnerability has been **verified as exploitable** through automated Docker-based PoC execution.",
            "",
        ]

        # Execution rounds
        rounds = docker_verification.get("execution_rounds", [])
        if rounds:
            lines.append("### Execution Log")
            lines.append("")
            for r in rounds:
                round_num = r.get("round", 0)
                exit_code = r.get("exit_code", "N/A")
                confirmed = r.get("exploit_confirmed", False)
                stdout = r.get("stdout_excerpt", "").strip()

                lines.append(f"**Round {round_num}** (exit code: {exit_code}, confirmed: {confirmed})")
                if stdout:
                    lines.append("")
                    lines.append("```")
                    # Limit output for the report
                    lines.append(stdout[:1500])
                    lines.append("```")
                lines.append("")
        else:
            execution_output = docker_verification.get("execution_output", "").strip()
            if execution_output:
                lines.extend([
                    "### Execution Log",
                    "",
                    "```",
                    execution_output[:1500],
                    "```",
                    "",
                ])

        # PoC generation info
        poc_gen = docker_verification.get("poc_generation", {})
        if poc_gen and poc_gen.get("status") == "ok":
            steps = poc_gen.get("attack_steps", [])
            if steps:
                lines.append("### PoC Attack Steps")
                lines.append("")
                for step in steps:
                    lines.append(f"- {step}")
                lines.append("")

        # Evidence files
        evidence = docker_verification.get("evidence_summary", {})
        if evidence:
            files = evidence.get("files", [])
            if files:
                lines.append("### Evidence Files")
                lines.append("")
                for f in files:
                    lines.append(f"- `{f}`")
                lines.append("")
        elif docker_verification.get("poc_script_path"):
            lines.extend([
                "### Evidence Files",
                "",
                f"- `{docker_verification['poc_script_path']}`",
                "",
            ])

        # Screenshot placeholder
        lines.extend([
            "### Screenshots",
            "",
            "> **Note for reviewer**: Screenshots of the Docker execution output should be attached below.",
            "> Run the Docker reproduction steps above and capture the terminal output.",
            "",
            "<!-- SCREENSHOT_PLACEHOLDER: Paste Docker execution terminal output screenshots here -->",
            "",
        ])

        return "\n".join(lines)

    # ---- Full Research Report ----

    def generate_full_report(
        self,
        exploitability_results: Dict[str, Any],
        cve_id: Optional[str] = None,
        only_exploitable: bool = False,
    ) -> str:
        """Generate a comprehensive security research report.

        This report includes all findings, analysis details, and reproduction
        instructions suitable for review and submission.
        """
        results = exploitability_results.get("results", [])
        summary = exploitability_results.get("summary", {})
        metadata = exploitability_results.get("metadata", {})
        verifications = self._extract_finding_verifications(exploitability_results)
        filtered_results = [
            r for r in results
            if r.get("verdict", "").upper() == "EXPLOITABLE"
        ] if only_exploitable else results

        summary_counts = {
            "exploitable": sum(1 for r in filtered_results if r.get("verdict", "").upper() == "EXPLOITABLE"),
            "conditionally_exploitable": sum(
                1 for r in filtered_results if r.get("verdict", "").upper() == "CONDITIONALLY_EXPLOITABLE"
            ),
            "library_risk": sum(1 for r in filtered_results if r.get("verdict", "").upper() == "LIBRARY_RISK"),
            "not_exploitable": sum(1 for r in filtered_results if r.get("verdict", "").upper() == "NOT_EXPLOITABLE"),
        }
        if not filtered_results and not only_exploitable:
            summary_counts = {
                "exploitable": summary.get("exploitable", 0),
                "conditionally_exploitable": summary.get("conditionally_exploitable", 0),
                "library_risk": summary.get("library_risk", 0),
                "not_exploitable": summary.get("not_exploitable", 0),
            }

        lines = [
            f"# Security Research Report: {self.repo_name}",
            "",
            f"**Date**: {datetime.now().strftime('%Y-%m-%d')}",
            f"**Repository**: [{self.repo_name}]({self.repo_url})",
            f"**Commit**: `{self.commit_hash[:12]}`",
            f"**CVE**: {cve_id or 'N/A'}",
            "",
            "---",
            "",
            "## Executive Summary",
            "",
            f"This report presents the security analysis of **{self.repo_name}** at commit "
            f"`{self.commit_hash[:12]}`. The analysis identified the following:",
            "",
            f"| Verdict | Count |",
            f"|---------|-------|",
            f"| Exploitable | {summary_counts.get('exploitable', 0)} |",
            f"| Conditionally Exploitable | {summary_counts.get('conditionally_exploitable', 0)} |",
            f"| Library Risk | {summary_counts.get('library_risk', 0)} |",
            f"| Not Exploitable | {summary_counts.get('not_exploitable', 0)} |",
            "",
        ]
        if only_exploitable:
            lines.extend([
                "> Report mode: only findings with verdict `EXPLOITABLE` are included in detailed sections.",
                "",
            ])

        # Docker verification summary
        if verifications:
            docker_summary = self._summarize_docker_verifications(verifications)
            lines.extend([
                "### Docker Verification Results",
                "",
                f"| Result | Count |",
                f"|--------|-------|",
                f"| Verified Exploitable | {docker_summary.get('verified_exploitable', 0)} |",
                f"| Partial Verification | {docker_summary.get('partial_verification', 0)} |",
                f"| Verification Failed | {docker_summary.get('verification_failed', 0)} |",
                f"| Generation Failed | {docker_summary.get('generation_failed', 0)} |",
                "",
            ])

        lines.extend([
            "---",
            "",
            "## Environment Setup for Reproduction",
            "",
            "### Prerequisites",
            "",
            "- Docker (version 20.10+)",
            "- Git",
            f"- Access to the repository: {self.repo_url}",
            "",
            "### Setup Steps",
            "",
            "```bash",
            f"# 1. Clone the repository",
            f"git clone {self.repo_url}.git",
            f"cd {self.repo_name}",
            "",
            f"# 2. Checkout the vulnerable commit",
            f"git checkout {self.commit_hash}",
            "",
            f"# 3. Build Docker image",
            f"docker build -t vuln-{self.repo_name.lower()} .",
            "```",
            "",
            "---",
            "",
            "## Detailed Findings",
            "",
        ])

        # Group findings by verdict
        exploitable = [r for r in filtered_results if r.get("verdict", "").upper() == "EXPLOITABLE"]
        conditional = [] if only_exploitable else [
            r for r in filtered_results if r.get("verdict", "").upper() == "CONDITIONALLY_EXPLOITABLE"
        ]
        library_risk = [] if only_exploitable else [
            r for r in filtered_results if r.get("verdict", "").upper() == "LIBRARY_RISK"
        ]

        if exploitable:
            lines.append("### Exploitable Vulnerabilities")
            lines.append("")
            for i, r in enumerate(exploitable, 1):
                finding_id = r.get("finding_id", f"vuln_{i:03d}")
                docker_v = verifications.get(finding_id)
                lines.append(self._render_finding_section(i, r, docker_v))

        if conditional:
            lines.append("### Conditionally Exploitable Vulnerabilities")
            lines.append("")
            for i, r in enumerate(conditional, 1):
                finding_id = r.get("finding_id", f"vuln_{i:03d}")
                docker_v = verifications.get(finding_id)
                lines.append(self._render_finding_section(i, r, docker_v))

        if library_risk:
            lines.append("### Library Risk Findings")
            lines.append("")
            for i, r in enumerate(library_risk, 1):
                lines.append(self._render_finding_section(i, r))

        # Appendix
        lines.extend([
            "---",
            "",
            "## Appendix",
            "",
            "### Analysis Metadata",
            "",
            f"- **Analysis started**: {metadata.get('started_at', 'N/A')}",
            f"- **Analysis completed**: {metadata.get('completed_at', 'N/A')}",
            f"- **Total findings analyzed**: {metadata.get('total_vulnerabilities', 0)}",
            f"- **Tool**: LLM-VulVariant (automated vulnerability variant detection)",
            "",
            "### Methodology",
            "",
            "1. **Vulnerability Variant Scanning**: Using LLM-based agentic scanning to identify",
            "   code patterns similar to known vulnerabilities (source → flow → sink analysis).",
            "2. **Exploitability Analysis**: Static analysis using Claude Code to verify",
            "   attack paths, sources, sinks, and sanitizers.",
            "3. **Docker-based PoC Verification**: Automated proof-of-concept generation",
            "   and execution in isolated Docker containers.",
            "",
            "### Screenshot Checklist",
            "",
            "For final submission, attach screenshots of:",
            "",
            "- [ ] Docker build output showing successful image creation",
            "- [ ] PoC execution output showing `VULNERABILITY_CONFIRMED`",
            "- [ ] Relevant code snippets in the repository",
            "- [ ] Evidence files produced by the PoC (if any)",
            "",
            "---",
            "",
            f"*Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} by LLM-VulVariant*",
        ])

        return "\n".join(lines)

    def _render_finding_section(
        self,
        index: int,
        result: Dict[str, Any],
        docker_verification: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Render detailed section for a single finding."""
        vuln = result.get("original_finding", {})
        file_path = vuln.get("file_path", "unknown")
        vuln_type = vuln.get("vulnerability_type", "unknown")
        description = vuln.get("description", "")
        evidence = vuln.get("evidence", "")
        attack_scenario = vuln.get("attack_scenario", "")
        confidence = vuln.get("confidence", "unknown")
        verdict = result.get("verdict", "UNKNOWN")

        source_analysis = result.get("source_analysis", {})
        attack_path = source_analysis.get("attack_path", []) if source_analysis else []

        lines = [
            f"#### Finding {index}: {vuln_type.replace('_', ' ').title()} in `{file_path}`",
            "",
            f"**Verdict**: {verdict} | **Confidence**: {confidence}",
            "",
            f"**Description**: {description}",
            "",
        ]

        if evidence:
            lines.extend([
                "**Evidence**:",
                "```",
                evidence[:1000],
                "```",
                "",
            ])

        if attack_path:
            lines.append("**Attack Path**:")
            for step in attack_path:
                lines.append(f"1. `{step}`")
            lines.append("")

        if attack_scenario:
            lines.extend([
                "**Attack Scenario**:",
                f"> {attack_scenario[:500]}",
                "",
            ])

        # Docker verification results
        if docker_verification:
            dv_verdict = self._docker_verification_verdict(docker_verification) or "N/A"
            lines.append(f"**Docker Verification**: {dv_verdict}")
            lines.append("")

            if dv_verdict == "VERIFIED_EXPLOITABLE":
                lines.append("✅ **Exploitation confirmed via automated Docker PoC execution.**")
                lines.append("")

                # Show execution output
                rounds = docker_verification.get("execution_rounds", [])
                for r in rounds:
                    if r.get("exploit_confirmed"):
                        stdout = r.get("stdout_excerpt", "").strip()
                        if stdout:
                            lines.extend([
                                "**PoC Output**:",
                                "```",
                                stdout[:1500],
                                "```",
                                "",
                            ])
                        break
                else:
                    execution_output = docker_verification.get("execution_output", "").strip()
                    if execution_output:
                        lines.extend([
                            "**PoC Output**:",
                            "```",
                            execution_output[:1500],
                            "```",
                            "",
                        ])

        lines.append("---")
        lines.append("")
        return "\n".join(lines)

    # ---- Helpers ----

    def _extract_finding_verifications(
        self, exploitability_results: Dict[str, Any]
    ) -> Dict[str, Dict[str, Any]]:
        """Extract docker verification records keyed by finding_id."""
        verifications: Dict[str, Dict[str, Any]] = {}
        for result in exploitability_results.get("results", []):
            finding_id = result.get("finding_id")
            docker_v = result.get("docker_verification")
            if finding_id and isinstance(docker_v, dict):
                verifications[finding_id] = docker_v
        return verifications

    @staticmethod
    def _docker_verification_verdict(
        docker_verification: Optional[Dict[str, Any]]
    ) -> Optional[str]:
        """Normalize docker verification verdict for old/new result schemas."""
        if not isinstance(docker_verification, dict):
            return None

        explicit_verdict = str(docker_verification.get("verification_verdict", "")).strip().upper()
        if explicit_verdict:
            return explicit_verdict
        if docker_verification.get("exploit_confirmed"):
            return "VERIFIED_EXPLOITABLE"
        if docker_verification.get("run_success"):
            return "VERIFICATION_FAILED"
        if docker_verification.get("build_success"):
            return "PARTIAL_VERIFICATION"
        return "GENERATION_FAILED"

    def _summarize_docker_verifications(
        self, verifications: Dict[str, Dict[str, Any]]
    ) -> Dict[str, int]:
        """Summarize docker verification outcomes across findings."""
        summary = {
            "verified_exploitable": 0,
            "partial_verification": 0,
            "verification_failed": 0,
            "generation_failed": 0,
        }

        for docker_v in verifications.values():
            verdict = self._docker_verification_verdict(docker_v)
            if verdict == "VERIFIED_EXPLOITABLE":
                summary["verified_exploitable"] += 1
            elif verdict == "PARTIAL_VERIFICATION":
                summary["partial_verification"] += 1
            elif verdict in {"VERIFICATION_FAILED", "NOT_VERIFIED"}:
                summary["verification_failed"] += 1
            else:
                summary["generation_failed"] += 1
        return summary

    def _determine_severity(
        self, vuln_type: str, verdict: str, exploitability: Dict[str, Any]
    ) -> str:
        """Determine severity level based on vulnerability type and verdict."""
        high_severity_types = {
            "deserialization", "command_injection", "code_injection",
            "code_execution", "sql_injection",
        }
        medium_severity_types = {
            "path_traversal", "ssrf", "xxe",
        }

        if verdict == "EXPLOITABLE":
            if vuln_type.lower() in high_severity_types:
                return "Critical"
            elif vuln_type.lower() in medium_severity_types:
                return "High"
            else:
                return "High"
        elif verdict == "CONDITIONALLY_EXPLOITABLE":
            if vuln_type.lower() in high_severity_types:
                return "High"
            else:
                return "Medium"
        else:
            return "Medium"

    def _generate_cvss_vector(
        self, vuln_type: str, exploitability: Dict[str, Any]
    ) -> str:
        """Generate a CVSS 3.1 vector string.

        This is an approximation based on vulnerability type.
        """
        # Base vectors by type
        vectors = {
            "deserialization": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
            "command_injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "code_injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "code_execution": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "path_traversal": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
            "ssrf": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N",
            "sql_injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        }

        # Check if source requires user interaction
        source_analysis = exploitability.get("source_analysis", {})
        sources = source_analysis.get("sources_found", []) if source_analysis else []
        has_direct = any(s.get("controllability") == "direct" for s in sources)

        base = vectors.get(vuln_type.lower(), "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H")

        # Adjust for indirect sources
        if not has_direct and sources:
            base = base.replace("UI:N", "UI:R")

        return base

    def _impact_description(self, vuln_type: str) -> str:
        """Get impact description for a vulnerability type."""
        impacts = {
            "deserialization": "Remote Code Execution (RCE) via malicious deserialization payload",
            "command_injection": "Remote Code Execution (RCE) via OS command injection",
            "code_injection": "Remote Code Execution (RCE) via code injection",
            "code_execution": "Remote Code Execution (RCE)",
            "path_traversal": "Arbitrary file read/write via path traversal",
            "ssrf": "Server-Side Request Forgery allowing internal network access",
            "sql_injection": "SQL Injection allowing data exfiltration or modification",
            "xxe": "XML External Entity (XXE) allowing file disclosure or SSRF",
        }
        return impacts.get(vuln_type.lower(), "Security impact dependent on context")

    def _manual_reproduction_steps(
        self, vuln_type: str, file_path: str, attack_scenario: str, evidence: str
    ) -> str:
        """Generate manual reproduction steps."""
        steps = [
            f"1. Open the vulnerable file: `{file_path}`",
            f"2. Locate the vulnerable code pattern described in the evidence above.",
        ]

        if vuln_type.lower() == "deserialization":
            steps.extend([
                "3. Create a malicious serialized payload appropriate for the project language.",
                f"   For {self.language} projects, craft a payload that triggers the vulnerable deserialization path.",
                "4. Feed the malicious file through the vulnerable code path.",
                "5. Observe arbitrary code execution.",
            ])
        elif vuln_type.lower() in ("command_injection", "code_injection"):
            steps.extend([
                "3. Craft input that includes shell metacharacters or code:",
                '   ```\n   malicious_input = "; id #"\n   ```',
                "4. Provide this input through the identified source (CLI/API/config).",
                "5. Observe command execution in the output.",
            ])
        elif vuln_type.lower() == "path_traversal":
            steps.extend([
                "3. Craft a path traversal payload:",
                '   ```\n   malicious_path = "../../../etc/passwd"\n   ```',
                "4. Provide this path through the identified source.",
                "5. Observe access to files outside the expected directory.",
            ])
        else:
            steps.extend([
                f"3. Follow the attack scenario: {attack_scenario[:200]}",
                "4. Verify the vulnerability is triggered.",
            ])

        return "\n".join(steps)
