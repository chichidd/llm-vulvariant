"""Agent scan memory for tracking progress and enabling resume."""

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class ScanMemory:
    """Lightweight scan memory supporting resume and progress tracking."""
    
    # Scan metadata
    target_repo: str = ""
    target_commit: str = ""
    cve_id: str = ""
    started_at: str = ""
    
    # File status: {file_path: "pending"|"completed"|"skipped"}
    file_status: Dict[str, str] = field(default_factory=dict)
    
    # File completion reasons: {file_path: reason}
    file_completion_reasons: Dict[str, str] = field(default_factory=dict)
    
    # Module priorities: {module_name: priority (1=highest)}
    module_priorities: Dict[str, int] = field(default_factory=dict)
    
    # File to module mapping: {file_path: module_name}
    file_to_module: Dict[str, str] = field(default_factory=dict)
    
    # Findings and issues
    findings: List[Dict[str, Any]] = field(default_factory=list)
    issues: List[str] = field(default_factory=list)
    
    # Iteration logs: [{iteration, actions, timestamp}]
    iterations: List[Dict[str, Any]] = field(default_factory=list)
    
    # Summary (LLM generated)
    summary: str = ""

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
    
    def initialize(
        self,
        target_repo: str,
        target_commit: str,
        cve_id: str,
        module_priorities: Dict[str, int],
        file_to_module: Dict[str, str],
    ) -> bool:
        """Initialize memory for a new scan or resume existing.
        
        Returns:
            True if resuming from existing memory, False if starting fresh.
        """
        if self.load():
            logger.info(f"Resuming scan from {self.memory_file}")
            return True
        
        self.memory = ScanMemory(
            target_repo=target_repo,
            target_commit=target_commit[:12],
            cve_id=cve_id,
            started_at=datetime.now().isoformat(),
            module_priorities=module_priorities,
            file_to_module=file_to_module,
            file_status={f: "pending" for f in file_to_module},
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
        self.memory_file.write_text(
            json.dumps(self.memory.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8"
        )
    
    def mark_file(self, file_path: str, status: str):
        """Update file status."""
        if file_path in self.memory.file_status:
            self.memory.file_status[file_path] = status
            self.save()
    
    def mark_files(self, file_paths: List[str], status: str):
        """Batch update file status."""
        for f in file_paths:
            if f in self.memory.file_status:
                self.memory.file_status[f] = status
        self.save()
    
    def add_finding(self, finding: Dict[str, Any]) -> bool:
        """Record a vulnerability finding.
        
        Returns:
            True if finding was added, False if it was a duplicate.
        """
        # Check for duplicate (same file + same vulnerability type)
        for existing in self.memory.findings:
            if (existing.get("file_path") == finding.get("file_path", "") and 
                existing.get("function_name") == finding.get("function_name") and
                existing.get("vulnerability_type") == finding.get("vulnerability_type") and 
                existing.get("line_number") == finding.get("line_number")):
                return False  # Duplicate
        
        self.memory.findings.append(finding)
        self.save()
        return True
    
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
    
    def add_issue(self, issue: str):
        """Record an issue encountered during scan."""
        self.memory.issues.append(issue)
        self.save()
    
    def log_iteration(self, iteration: int, actions: List[str]):
        """Log an iteration's actions."""
        self.memory.iterations.append({
            "iteration": iteration,
            "actions": actions,
            "timestamp": datetime.now().isoformat(),
        })
        self.save()
    
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
        completed = sum(1 for s in self.memory.file_status.values() if s == "completed")
        pending = sum(1 for s in self.memory.file_status.values() if s == "pending")
        
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
            "completed": completed,
            "pending": pending,
            "findings": len(self.memory.findings),
            "priority_1": priority_stats[1],
            "priority_2": priority_stats[2],
        }
    
    def is_critical_complete(self) -> bool:
        """Check if all priority-1 (directly affected) files are scanned."""
        for f, status in self.memory.file_status.items():
            module = self.memory.file_to_module.get(f, "")
            priority = self.memory.module_priorities.get(module, 3)
            if priority == 1 and status == "pending":
                return False
        return True
    
    def generate_summary(self) -> str:
        """Generate summary using LLM."""
        if not self.llm_client:
            return ""
        
        progress = self.get_progress()
        prompt = f"""Summarize this vulnerability scan in 3-5 sentences:

Target: {self.memory.target_repo}@{self.memory.target_commit}
CVE: {self.memory.cve_id}
Files scanned: {progress['completed']}/{progress['total_files']}
Vulnerabilities found: {progress['findings']}
Priority-1 modules: {progress['priority_1']['completed']}/{progress['priority_1']['total']} complete
Issues encountered: {len(self.memory.issues)}

Findings: {json.dumps(self.memory.findings[-5:], indent=2) if self.memory.findings else 'None'}
Issues: {self.memory.issues[-5:] if self.memory.issues else 'None'}

Provide a concise technical summary."""

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
        
        lines = [
            "# Vulnerability Scan Memory",
            "",
            "## Scan Info",
            f"- **Target**: {self.memory.target_repo}@{self.memory.target_commit}",
            f"- **CVE**: {self.memory.cve_id}",
            f"- **Started**: {self.memory.started_at}",
            "",
            "## Progress",
            f"- Total files: {progress['total_files']}",
            f"- Completed: {progress['completed']}",
            f"- Pending: {progress['pending']}",
            f"- Findings: {progress['findings']}",
            "",
            "### Priority Breakdown",
            f"- Priority 1 (affected): {progress['priority_1']['completed']}/{progress['priority_1']['total']}",
            f"- Priority 2 (related): {progress['priority_2']['completed']}/{progress['priority_2']['total']}",
            "",
        ]
        
        # Critical files status
        if not self.is_critical_complete():
            lines.extend([
                "### ⚠️ Incomplete Critical Files",
                "",
            ])
            for f, status in self.memory.file_status.items():
                module = self.memory.file_to_module.get(f, "")
                priority = self.memory.module_priorities.get(module, 3)
                if priority == 1 and status == "pending":
                    lines.append(f"- [ ] `{f}`")
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
