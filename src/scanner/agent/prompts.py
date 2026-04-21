"""Prompt builders for the agentic vulnerability finder."""

from __future__ import annotations

import json
from typing import Any, Dict, List

from .utils import _to_dict


def build_system_prompt(
    vulnerability_profile: Any,
    toolkit,
    shared_observation_count: int = 0,
) -> str:
    vuln_dict = _to_dict(vulnerability_profile)
    raw_evidence = vuln_dict.get("evidence", [])
    evidence_samples = raw_evidence[:3] if isinstance(raw_evidence, list) else []
    vuln_summary = {
        "cve_id": vuln_dict.get("cve_id"),
        "vulnerability_type": vuln_dict.get("sink_features", {}).get("type", "unknown")
        if vuln_dict.get("sink_features")
        else "unknown",
        "description": vuln_dict.get("vuln_description"),
        "cause": vuln_dict.get("vuln_cause"),
        "payload": vuln_dict.get("payload"),
        "source_features": vuln_dict.get("source_features"),
        "sink_features": vuln_dict.get("sink_features"),
        "flow_features": vuln_dict.get("flow_features"),
        "exploit_scenarios": vuln_dict.get("exploit_scenarios"),
        "exploit_conditions": vuln_dict.get("exploit_conditions"),
        "query_terms": vuln_dict.get("query_terms", []),
        "dangerous_apis": vuln_dict.get("dangerous_apis", []),
        "source_indicators": vuln_dict.get("source_indicators", []),
        "sink_indicators": vuln_dict.get("sink_indicators", []),
        "variant_hypotheses": vuln_dict.get("variant_hypotheses", []),
        "negative_constraints": vuln_dict.get("negative_constraints", []),
        "likely_false_positive_patterns": vuln_dict.get("likely_false_positive_patterns", []),
        "scan_start_points": vuln_dict.get("scan_start_points", []),
        "open_questions": vuln_dict.get("open_questions", []),
        "assumptions": vuln_dict.get("assumptions", []),
        "status": vuln_dict.get("status", "unknown"),
        "confidence": vuln_dict.get("confidence", "unknown"),
        "evidence_summary": vuln_dict.get("evidence_summary", ""),
        "evidence_samples": evidence_samples,
        "evidence_count": len(raw_evidence) if isinstance(raw_evidence, list) else 0,
        "uncertainty": vuln_dict.get("uncertainty", "low"),
    }

    tools_desc = "\n".join(
        [
            f"- {t.get('function', {}).get('name', t.get('name', 'unknown'))}: {t.get('function', {}).get('description', t.get('description', ''))}"
            for t in toolkit.get_available_tools()
        ]
    )
    tool_names = {
        t.get("function", {}).get("name", t.get("name", "unknown"))
        for t in toolkit.get_available_tools()
        if isinstance(t, dict)
    }
    shared_memory_hint = ""
    if "read_shared_public_memory" in tool_names:
        shared_memory_hint = (
            "\n    - Use read_shared_public_memory when you want reusable observations from previous "
            "scans of the same target repo"
        )
        if shared_observation_count > 0:
            shared_memory_hint += (
                f"\n    - There are already {shared_observation_count} reusable shared observations "
                "available for this target repo and commit in the current batch run; read them early "
                "before repeating broad searches"
                "\n    - Prefer a focused query derived from the current vulnerability pattern "
                "(SOURCE/SINK/FLOW, dangerous APIs, module names, or sink keywords)"
                "\n    - Do not default to an empty shared-memory query unless you explicitly want "
                "a broad overview"
            )

    return f"""You are a security researcher specializing in source-code vulnerability hunting.
Your task is to find vulnerabilities in other parts of the codebase that are "similar" to the known vulnerability.

## Known vulnerability analysis
{json.dumps(vuln_summary, indent=2, ensure_ascii=False)}

## What is a "similar vulnerability"?
A similar vulnerability means: the vulnerability type is the same, but the implementation form or location differs. For example:
- Known: os.system(user_input) -> Similar: subprocess.run(cmd, shell=True), os.popen()
- Known: pickle.load(file) -> Similar: yaml.unsafe_load(), marshal.load(), shelve.open()
- Known: SQL injection via string concatenation -> Similar: any SQL query built via f-strings/format concatenation
- Known: path traversal via open(user_path) -> Similar: shutil.copy(user_src, dst), os.rename()

Key point: 
1. What matters is the vulnerability "pattern", not a specific API name.
2. Pay attention to directly affected modules and embedding-similar modules in the target software.
3. Do not report a different sink class just because the impact is also RCE; command_injection, code_injection/code_execution, deserialization, template_injection, etc. remain distinct vulnerability types.

## Available tools
{tools_desc}

## Analysis Strategy
1. Identify the vulnerability pattern from query_terms, dangerous_apis, source_indicators, sink_indicators, and negative_constraints:
    - SOURCE: Where does untrusted data enter?
    - SINK: What dangerous operation is performed?
    - FLOW: How does data flow from the source to the sink?
    - Use scan_start_points as concrete anchors for first-pass inspection before inventing broader searches.
    - Treat negative_constraints as disqualifiers that should reject false matches early.
    - Treat likely_false_positive_patterns as early warning signs for dead ends.

2. If shared observations are available, read them with a focused query before broad reads:
    - Start from focused query terms derived from the current vulnerability pattern.
    - Reuse strong shared-memory hits before repeating repo-wide searches.
{shared_memory_hint}

3. Search PRIORITY-1 scope first:
    - Exhaust directly affected or embedding-similar modules before widening.

4. For each candidate module, use the following tools depending on your needs:
    - Use list_files_in_folder to quickly understand the module
    - Use search_in_file/search_in_folder to locate potential sinks
    - Use search_in_folder to identify sources (config parsing, user input, file reads, etc.)
    - Use read_file or get_function_code to inspect suspicious code in depth
    - Use analyze_data_flow to trace data flow from source to sink

5. Think about alternative implementations:
    - Different APIs for the same functionality
    - Different data formats (JSON, YAML, XML, pickle)
    - Different execution methods (subprocess, os, multiprocessing)
    - Use variant_hypotheses to prioritize plausible variants before repo-wide exploration

6. Widen to RELATED or repo-wide searches only when the current evidence is insufficient:
    - Expand scope only after focused PRIORITY-1 checks and shared-memory reads leave unresolved gaps.

7. Record rejected hypotheses, evidence gaps, and next best queries:
    - Keep track of shared-memory hits worth reusing.
    - Note why candidate patterns were rejected so they are not retried blindly.
    - Capture the best next focused queries before broadening scope.

## Security claim verification contract
Before calling report_vulnerability, apply this security claim verification contract and explain:
- claim: the vulnerability class and expected attacker-controlled effect
- attacker-controlled source: where the input or action comes from in normal software usage
- trust boundary: what lower-privileged or external boundary is crossed
- sink semantics: why the reached operation matches the claimed vulnerability class
- protection analysis: validation, sandboxing, escaping, safe defaults, capability limits, or provenance checks and why they fail or hold
- security impact: what the attacker gains or changes
- counterevidence: facts that would make the candidate a non-vulnerability or a different class

If any required part is missing, do not report the finding; call mark_file_completed with the rejection reason or continue gathering evidence.
Derive false-positive considerations from the inspected code and the known vulnerability profile rather than from a fixed checklist.

## Evidence-first reporting rule
- Do not report a finding without evidence snippets from files/functions.
- If no strong evidence is found in the selected scope, call `mark_file_completed` with a short reason instead of guessing.

## Tool calling
You have a set of tools (functions) available. When you need code information or need to report a vulnerability, the system will invoke the corresponding functions.

Important notes:
- When you find a vulnerability, you must use the report_vulnerability tool and provide complete evidence
- When you finish analyzing a file, use mark_file_completed for that file even if you did not find a vulnerability
- When you are confident no more vulnerabilities remain, clearly state "analysis complete" and summarize your findings; no special formatting is required
- Use tools to analyze code deeply; do not rely on speculation alone
"""


def build_initial_user_message(
    software_profile: Any,
    module_priorities: Dict[str, int] = None,
    critical_stop_max_priority: int = 2,
    shared_observation_count: int = 0,
) -> str:
    software_dict = _to_dict(software_profile)
    module_priorities = module_priorities or {}
    normalized_max_priority = 1 if critical_stop_max_priority == 1 else 2
    modules = software_dict.get("modules")
    if not isinstance(modules, list):
        modules = getattr(software_profile, "modules", [])
        if not isinstance(modules, list):
            modules = []
    basic_info = software_dict.get("basic_info", {})
    if not isinstance(basic_info, dict):
        basic_info = {}
    project_name = str(
        basic_info.get("name")
        or getattr(software_profile, "name", "")
        or ""
    )
    
    # Build prioritized module list
    prioritized_modules = []
    
    for raw_module in modules:
        if isinstance(raw_module, dict):
            module = raw_module
        else:
            module = {
                "name": str(getattr(raw_module, "name", "") or ""),
                "files": list(getattr(raw_module, "files", []) or []),
                "description": str(getattr(raw_module, "description", "") or ""),
                "key_functions": list(getattr(raw_module, "key_functions", []) or []),
                "external_dependencies": list(
                    getattr(raw_module, "external_dependencies", []) or []
                ),
            }
        name = str(module.get("name", "") or "")
        priority = module_priorities.get(name, 3)
        prioritized_modules.append((priority, module))
    
    # Sort by priority (1=priority-1, 2=related, 3=other)
    prioritized_modules.sort(key=lambda x: x[0])
    
    # Build module info with priority labels
    key_modules = []
    for priority, module in prioritized_modules[:50]:
        priority_label = {1: "🔴 PRIORITY-1", 2: "🟡 RELATED", 3: "⚪ OTHER"}.get(priority, "")
        key_modules.append({
            "name": module.get("name"),
            "priority": priority_label,
            "files": module.get("files", [])[:5],
            "description": module.get("description", "")[:150],
            "key_functions": module.get("key_functions", [])[:5],
            "external_dependencies": module.get("external_dependencies", [])[:5],
        })
    
    project_info = {
        "project_name": project_name,
        "modules": key_modules,
    }
    
    # Count priority stats
    p1_count = sum(1 for priority in module_priorities.values() if priority == 1)
    p2_count = sum(1 for priority in module_priorities.values() if priority == 2)
    no_priority_one_modules = p1_count == 0
    if no_priority_one_modules and p2_count > 0:
        related_scope_line = (
            f"- 🟡 RELATED ({p2_count} modules): Highest-priority concrete scan targets for this run "
            "because no PRIORITY-1 modules were identified"
        )
        analysis_scope_line = (
            "No PRIORITY-1 modules were identified for this run. Use 🟡 RELATED modules as the "
            "highest-priority concrete scan targets before broad repo-wide searches."
        )
        widening_scope_line = (
            "- Use 🟡 RELATED modules as the highest-priority concrete scan targets before widening "
            "to repo-wide searches"
        )
    elif no_priority_one_modules:
        related_scope_line = "- 🟡 RELATED (0 modules): None currently identified"
        if shared_observation_count > 0:
            analysis_scope_line = (
                "No PRIORITY-1 or RELATED modules were identified for this run. Start from shared memory, "
                "scan_start_points, and focused repo-wide searches."
            )
            widening_scope_line = (
                "- No scoped PRIORITY-1 or RELATED modules are currently identified; rely on shared memory, "
                "scan_start_points, and focused repo-wide searches"
            )
        else:
            analysis_scope_line = (
                "No PRIORITY-1 or RELATED modules were identified for this run. Start from scan_start_points "
                "and focused repo-wide searches."
            )
            widening_scope_line = (
                "- No scoped PRIORITY-1 or RELATED modules are currently identified; rely on scan_start_points "
                "and focused repo-wide searches"
            )
    else:
        related_scope_line = (
            "- 🟡 RELATED "
            f"({p2_count} modules): Follow-up scope only after all PRIORITY-1 files are complete"
            if normalized_max_priority == 1
            else f"- 🟡 RELATED ({p2_count} modules): Calls or is called by priority-1 modules - scan next"
        )
        analysis_scope_line = (
            "This run's critical scope is 🔴 PRIORITY-1 modules only. "
            "Do not spend analysis turns on 🟡 RELATED modules while any 🔴 file is still pending."
            if normalized_max_priority == 1
            else "Do not skip any PRIORITY-1 or RELATED modules."
        )
        widening_scope_line = "- Widen to 🟡 RELATED modules only when 🔴 PRIORITY-1 evidence is insufficient"

    shared_memory_section = ""
    if shared_observation_count > 0:
        shared_memory_section = (
            f"- Shared public memory already has {shared_observation_count} reusable observations for this "
            "target repo and commit. Call read_shared_public_memory before broad searches when you start a new module or pattern.\n"
            "- Use focused query terms derived from the current vulnerability pattern instead of an empty query whenever possible.\n"
        )
    shared_memory_priority_line = ""
    if shared_observation_count > 0 and no_priority_one_modules:
        if p2_count > 0:
            shared_memory_priority_line = (
                "No PRIORITY-1 modules are currently identified. Start by calling read_shared_public_memory "
                "with focused query terms derived from the current vulnerability pattern, then use 🟡 RELATED "
                "modules as the highest-priority concrete scan scope before any repo-wide widening.\n"
            )
        else:
            shared_memory_priority_line = (
                "No PRIORITY-1 modules are currently identified. Start by calling read_shared_public_memory "
                "with focused query terms derived from the current vulnerability pattern before broad "
                "repo-wide searches.\n"
            )
    no_priority_one_with_related_modules = no_priority_one_modules and p2_count > 0
    task_start_line = (
        "1. **Start by reading shared public memory**: No PRIORITY-1 modules are currently identified, "
        "so begin with focused shared-memory queries and then use 🟡 RELATED modules as the highest-priority "
        "concrete scan scope"
        if shared_memory_priority_line and no_priority_one_with_related_modules
        else (
            "1. **Start by reading shared public memory**: No PRIORITY-1 modules are currently identified, "
            "so begin with focused shared-memory queries and then widen carefully"
            if shared_memory_priority_line
        else (
            "1. **Start with 🟡 RELATED modules**: No PRIORITY-1 modules are currently identified, so use "
            "the RELATED scope as the highest-priority concrete starting point and focus those checks with "
            "scan_start_points plus the structured vulnerability guidance"
            if no_priority_one_with_related_modules
            else (
                "1. **No PRIORITY-1 modules are currently identified**: Start with focused repo-wide searches "
                "anchored on the vulnerability pattern"
                if no_priority_one_modules
                else "1. **Start with PRIORITY-1 modules**: These are directly affected or embedding-similar to the known vulnerable module"
            )
        )
        )
    )
    module_scan_line = (
        "- No PRIORITY-1 modules are currently identified; use shared memory to focus the 🟡 RELATED module checks, "
        "then widen to repo-wide searches only if those concrete targets are exhausted without enough evidence"
        if no_priority_one_with_related_modules and shared_observation_count > 0
        else (
            "- No PRIORITY-1 modules are currently identified; use 🟡 RELATED modules as the highest-priority "
            "concrete scan scope before repo-wide widening"
            if no_priority_one_with_related_modules
            else (
                "- No PRIORITY-1 modules are currently identified; use shared memory, scan_start_points, and focused repo-wide "
                "searches to establish the best candidate modules"
                if no_priority_one_modules and shared_observation_count > 0
                else (
                    "- No PRIORITY-1 modules are currently identified; use scan_start_points and focused repo-wide "
                    "searches to establish the best candidate modules"
                    if no_priority_one_modules
        else "- For each PRIORITY-1 module, scan ALL files for the vulnerability pattern"
                )
            )
        )
    )
    start_instruction = (
        "Begin analysis now. Start by reading shared public memory with a focused query, then use the 🟡 "
        "RELATED modules as the highest-priority concrete scope before any repo-wide widening."
        if shared_memory_priority_line and no_priority_one_with_related_modules
        else (
            "Begin analysis now. Start by reading shared public memory with a focused query, then widen "
            "to repo-wide searches."
            if shared_memory_priority_line
        else (
            "Begin analysis now. Start with the 🟡 RELATED modules as the highest-priority concrete scope."
            if no_priority_one_with_related_modules
            else (
                "Begin analysis now. No PRIORITY-1 modules are currently identified, so start with focused "
                "repo-wide searches anchored on the vulnerability pattern."
                if no_priority_one_modules
                else "Begin analysis now. Start with the 🔴 PRIORITY-1 modules."
            )
        )
        )
    )

    return f"""Based on the project architecture and the known vulnerability pattern, search for similar vulnerabilities in the codebase.

## Module Priority Guide
- 🔴 PRIORITY-1 ({p1_count} modules): Directly affected or embedding-similar to the known vulnerable module - **MUST SCAN FIRST**
{related_scope_line}
- ⚪ OTHER: Lower priority

## Project Architecture
{json.dumps(project_info, indent=2, ensure_ascii=False)}

## Your Task
{task_start_line}
2. Understand the vulnerability pattern (SOURCE → FLOW → SINK)
3. Use tools to deeply analyze code in priority order
4. Report each finding with the report_vulnerability tool
5. Mark each fully analyzed file with mark_file_completed, including files with no findings

## Analysis Strategy
{shared_memory_priority_line}{module_scan_line}
{shared_memory_section}- Look for alternative APIs that perform similar dangerous operations
- Trace data flow from user input/config to dangerous sinks
{widening_scope_line}
- Record rejected hypotheses, evidence gaps, shared-memory hits, and next best queries as you go
- {analysis_scope_line}
- Keep scan progress accurate by calling mark_file_completed as soon as a file is fully analyzed

{start_instruction}"""


def build_intermediate_user_message(
    scanned_files: List[str] = None,
    findings: List[Dict[str, str]] = None,
    progress_info: str = "",
    critical_stop_max_priority: int = 2,
    shared_observation_count: int = 0,
    has_priority_one: bool = True,
    has_related: bool = True,
    compact: bool = False,
) -> str:
    """Build intermediate prompt with context about what's already been scanned."""
    normalized_max_priority = 1 if critical_stop_max_priority == 1 else 2
    if not has_priority_one and has_related:
        if shared_observation_count > 0:
            msg = """Continue your vulnerability analysis:
1. No PRIORITY-1 modules are currently identified; use focused shared-memory queries first, then scan ALL files in 🟡 RELATED modules before any repo-wide widening
2. Mark each fully analyzed file with mark_file_completed, even when it has no finding
3. Widen to repo-wide searches only when RELATED-module evidence is insufficient
4. Record rejected hypotheses, evidence gaps, shared-memory hits, and next best queries
5. Do NOT repeat previous analysis - see scanned files and findings below."""
        else:
            msg = """Continue your vulnerability analysis:
1. No PRIORITY-1 modules are currently identified; scan ALL files in 🟡 RELATED modules before any repo-wide widening
2. Mark each fully analyzed file with mark_file_completed, even when it has no finding
3. Widen to repo-wide searches only when RELATED-module evidence is insufficient
4. Record rejected hypotheses, evidence gaps, shared-memory hits, and next best queries
5. Do NOT repeat previous analysis - see scanned files and findings below."""
    elif not has_priority_one:
        if shared_observation_count > 0:
            msg = """Continue your vulnerability analysis:
1. No PRIORITY-1 or RELATED modules are currently identified; continue from focused shared-memory queries, scan_start_points, and focused repo-wide searches
2. Mark each fully analyzed file with mark_file_completed, even when it has no finding
3. Widen only when the current evidence is insufficient
4. Record rejected hypotheses, evidence gaps, shared-memory hits, and next best queries
5. Do NOT repeat previous analysis - see scanned files and findings below."""
        else:
            msg = """Continue your vulnerability analysis:
1. No PRIORITY-1 or RELATED modules are currently identified; continue from scan_start_points and focused repo-wide searches
2. Mark each fully analyzed file with mark_file_completed, even when it has no finding
3. Widen only when the current evidence is insufficient
4. Record rejected hypotheses, evidence gaps, shared-memory hits, and next best queries
5. Do NOT repeat previous analysis - see scanned files and findings below."""
    elif normalized_max_priority == 1:
        msg = """Continue your vulnerability analysis:
1. Have you scanned ALL files in PRIORITY-1 (🔴) modules?
2. Do not spend turns on RELATED (🟡) modules while any PRIORITY-1 file remains pending
3. Mark each fully analyzed file with mark_file_completed, even when it has no finding
4. Widen scope only when the current evidence is insufficient
5. Record rejected hypotheses, evidence gaps, shared-memory hits, and next best queries
6. Do NOT repeat previous analysis - see scanned files and findings below."""
    else:
        msg = """Continue your vulnerability analysis:
1. Have you scanned ALL files in PRIORITY-1 (🔴) modules?
2. Have you checked RELATED (🟡) modules?
3. Mark each fully analyzed file with mark_file_completed, even when it has no finding
4. Widen scope only when the current evidence is insufficient
5. Record rejected hypotheses, evidence gaps, shared-memory hits, and next best queries
6. Do NOT repeat previous analysis - see scanned files and findings below."""
    
    if progress_info:
        msg += f"\n\n**Progress**: {progress_info}"

    if shared_observation_count > 0:
        msg += (
            "\n\n**Shared Public Memory**: "
            f"{shared_observation_count} reusable observations are already available from previous "
            "scans of this target repo and commit. Call `read_shared_public_memory` before repeating "
            "broad searches for a new module or pattern. Prefer focused query terms derived from the "
            "current vulnerability pattern instead of an empty query unless you need a broad overview."
        )

    if compact:
        if findings:
            msg += (
                "\n\n**Reported Vulnerability Memory**: "
                f"{len(findings)} previously reported vulnerabilities tracked in memory. "
                "Do not re-report duplicates; rely on memory summaries and `check_file_status`."
            )
        if scanned_files:
            msg += (
                "\n\n**Scanned File Memory**: "
                f"{len(scanned_files)} previously scanned files tracked in memory. "
                "Use `check_file_status` for specific files instead of replaying the full inventory."
            )
        return msg

    if findings:
        msg += "\n\n**Already Reported Vulnerabilities** (DO NOT REPORT AGAIN):"
        for f in findings:
            msg += f"\n- {f['file']}: {f['type']} ({f['confidence']})"

    if scanned_files:
        # Show a sample of scanned files to save context
        sample = scanned_files[:20]
        msg += f"\n\n**Already Scanned Files** ({len(scanned_files)} total):"
        for f in sample:
            msg += f"\n- {f}"
        if len(scanned_files) > 20:
            msg += f"\n- ... and {len(scanned_files) - 20} more files"
    
    return msg
