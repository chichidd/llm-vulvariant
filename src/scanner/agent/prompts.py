"""Prompt builders for the agentic vulnerability finder."""

from __future__ import annotations

import json
from typing import Any, Dict, List

from .schedule_window import schedule_contract_metadata, validate_schedule_page
from .utils import _to_dict


def build_system_prompt(
    vulnerability_profile: Any,
    toolkit,
    shared_observation_count: int = 0,
    verifier_enabled: bool = True,
    candidate_priority_enabled: bool = True,
    candidate_file_order: List[str] = None,
    candidate_schedule_provenance: Dict[str, Any] = None,
    memory_guidance_enabled: bool = True,
    reference_semantics_enabled: bool = True,
) -> str:
    if not memory_guidance_enabled:
        shared_observation_count = 0
    candidate_file_order = [str(path) for path in (candidate_file_order or [])]
    if not candidate_priority_enabled and not candidate_file_order:
        raise ValueError(
            "candidate-priority ablation requires a frozen global file schedule"
        )

    def _finalize_system_prompt(prompt: str) -> str:
        projector = getattr(toolkit, "sanitize_invariant_model_value", None)
        if not callable(projector):
            if candidate_priority_enabled:
                return prompt
            raise ValueError("Invariant system-prompt sanitizer is unavailable")
        projected = projector(prompt)
        if not isinstance(projected, str):
            raise ValueError("System-prompt sanitizer returned invalid data")
        return projected

    frozen_schedule_section = ""
    if not candidate_priority_enabled and candidate_file_order:
        schedule_metadata = schedule_contract_metadata(
            candidate_file_order,
            candidate_schedule_provenance,
        )
        frozen_schedule_section = (
            "## Frozen global schedule contract\n"
            + json.dumps(schedule_metadata, indent=2, ensure_ascii=False)
            + "\nThe host first-presents contiguous windows in frozen order and prevents page "
            "skipping or reactivation. Current structured repository-path fields, enumeration, "
            "and tool eligibility are limited to pending files in the active page and globally "
            "ranked. Historical transcript may retain old-page text, but that does not reactivate "
            "or recount it. Within-window visitation remains model-controlled and recorded.\n"
        )


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
        "scan_start_points": (
            vuln_dict.get("scan_start_points", [])
            if candidate_priority_enabled
            else []
        ),
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
    if not reference_semantics_enabled:
        model_card = {
            "card_id": str(vuln_dict.get("card_id", "") or ""),
            "weaknesses": list(vuln_dict.get("weaknesses", []) or []),
        }
        memory_line = (
            "- Reuse run-scoped shared observations when they are available through the memory tool."
            if memory_guidance_enabled and "read_shared_public_memory" in tool_names
            else ""
        )
        priority_line = (
            "- Follow the host-precomputed module priority presentation."
            if candidate_priority_enabled
            else "- Use only pending files in the active host window; structured repository-path fields follow frozen global rank."
        )
        verifier_line = (
            "- Before reporting, establish attacker influence, boundary crossing, unsafe operation, missing protection, concrete impact, and counterevidence."
            if verifier_enabled
            else "- Claim-verifier ablation is active; the structured claim contract is disabled."
        )
        completion_line = (
            "- Use mark_file_completed for fully inspected files."
            if memory_guidance_enabled or not candidate_priority_enabled
            else ""
        )
        return _finalize_system_prompt(f"""You are a security researcher inspecting a target repository for code weaknesses.

## Frozen minimal reference card
{json.dumps(model_card, indent=2, ensure_ascii=False)}

The card is intentionally limited to an opaque identifier and CWE categories. Do not infer or request hidden CVE, repository, affected-module, API, flow, evidence, or exploit details.

{frozen_schedule_section}

## Available tools
{tools_desc}

## Analysis contract
- Inspect target code for concrete instances of the listed CWE categories.
{priority_line}
{memory_line}
{verifier_line}
- Report only findings supported by inspected code, using report_vulnerability.
{completion_line}
- When no further supported findings remain, state "analysis complete".
""")


    shared_memory_hint = ""
    shared_query_scope = (
        "module names" if candidate_priority_enabled else "scheduled path names"
    )
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
                f"(SOURCE/SINK/FLOW, dangerous APIs, {shared_query_scope}, or sink keywords)"
                "\n    - Do not default to an empty shared-memory query unless you explicitly want "
                "a broad overview"
            )

    if memory_guidance_enabled:
        observation_strategy = (
            "2. If shared observations are available, read them with a focused query before broad reads:\n"
            "    - Start from focused query terms derived from the current vulnerability pattern.\n"
            "    - Reuse strong shared-memory hits before repeating repo-wide searches.\n"
            f"{shared_memory_hint}"
        )
        widening_instruction = (
            "    - Expand scope only after focused PRIORITY-1 checks and shared-memory reads leave unresolved gaps."
        )
        hypothesis_instruction = (
            "7. Record rejected hypotheses, evidence gaps, and next best queries:\n"
            "    - Keep track of shared-memory hits worth reusing.\n"
            "    - Note why candidate patterns were rejected so they are not retried blindly.\n"
            "    - Capture the best next focused queries before broadening scope."
        )
        completion_tracking_note = (
            "- When you finish analyzing a file, use mark_file_completed for that file even if you did not find a vulnerability"
        )
    else:
        observation_strategy = (
            "2. Inspect focused code locations before broad reads:\n"
            "    - Start from query terms and code anchors derived from the current vulnerability pattern.\n"
            "    - Reuse evidence from the current analysis before repeating repo-wide searches."
        )
        widening_instruction = (
            "    - Expand scope only after focused PRIORITY-1 checks leave unresolved gaps."
        )
        hypothesis_instruction = (
            "7. Record rejected hypotheses, evidence gaps, and next best queries in the current analysis:\n"
            "    - Note why candidate patterns were rejected so they are not retried blindly.\n"
            "    - Capture the best next focused queries before broadening scope."
        )
        completion_tracking_note = ""

    rejection_instruction = (
        "If no strong evidence is found in the selected scope, call `mark_file_completed` "
        "with a short reason instead of guessing."
        if memory_guidance_enabled
        else "If no strong evidence is found in the selected scope, do not report a finding."
    )

    priority_instruction = (
        "Pay attention to directly affected and embedding-similar modules in the target software."
        if candidate_priority_enabled
        else "Candidate-priority ablation is active: use only the current frozen schedule window without module ordering."
    )
    candidate_priority_strategy = (
        "3. Search PRIORITY-1 scope first:\n    - Exhaust directly affected or embedding-similar modules before widening."
        if candidate_priority_enabled
        else "3. Candidate-priority ablation:\n    - Use only pending files in the active contiguous schedule window; the host rank-orders structured repository-path fields and records actual touches."
    )
    if candidate_priority_enabled:
        start_point_instruction = (
            "Use scan_start_points as concrete anchors for first-pass inspection "
            "before inventing broader searches."
        )
        candidate_scope_label = "candidate module"
        scope_listing_instruction = (
            "Use list_files_in_folder to quickly understand the module"
        )
        widening_heading = (
            "Widen to RELATED or repo-wide searches only when the current evidence "
            "is insufficient"
        )
    else:
        start_point_instruction = (
            "Do not use module, profile, or start-point hints to reorder the frozen "
            "global file schedule."
        )
        candidate_scope_label = "scheduled file"
        scope_listing_instruction = (
            "Use list_files_in_folder only as a schedule-ordered file view"
        )
        widening_heading = (
            "Continue through the frozen schedule without priority-based widening"
        )
        widening_instruction = (
            "    - Do not skip, regroup, or add lexical fallback paths."
        )

    verification_contract = (
        """## Security claim verification contract
Before calling report_vulnerability, apply this security claim verification contract and explain:
- claim: the vulnerability class and expected attacker-controlled effect
- attacker-controlled source: where the input or action comes from in normal software usage
- trust boundary: what lower-privileged or external boundary is crossed
- sink semantics: why the reached operation matches the claimed vulnerability class
- protection analysis: validation, sandboxing, escaping, safe defaults, capability limits, or provenance checks and why they fail or hold
- security impact: what the attacker gains or changes
- counterevidence: facts that would make the candidate a non-vulnerability or a different class

If any required part is missing, do not report the finding; call mark_file_completed with the rejection reason or continue gathering evidence.
Derive false-positive considerations from the inspected code and the known vulnerability profile rather than from a fixed checklist."""
        if verifier_enabled
        else "## Claim-verifier ablation\nThe structured security-claim verification contract and same-type verifier gate are disabled for this run."
    )

    return _finalize_system_prompt(f"""You are a security researcher specializing in source-code vulnerability hunting.
Your task is to find vulnerabilities in other parts of the codebase that are "similar" to the known vulnerability.

## Known vulnerability analysis
{json.dumps(vuln_summary, indent=2, ensure_ascii=False)}

{frozen_schedule_section}

## What is a "similar vulnerability"?
A similar vulnerability means: the vulnerability type is the same, but the implementation form or location differs. For example:
- Known: os.system(user_input) -> Similar: subprocess.run(cmd, shell=True), os.popen()
- Known: pickle.load(file) -> Similar: yaml.unsafe_load(), marshal.load(), shelve.open()
- Known: SQL injection via string concatenation -> Similar: any SQL query built via f-strings/format concatenation
- Known: path traversal via open(user_path) -> Similar: shutil.copy(user_src, dst), os.rename()

Key point: 
1. What matters is the vulnerability "pattern", not a specific API name.
2. {priority_instruction}
3. Do not report a different sink class just because the impact is also RCE; command_injection, code_injection/code_execution, deserialization, template_injection, etc. remain distinct vulnerability types.

## Available tools
{tools_desc}

## Analysis Strategy
1. Identify the vulnerability pattern from query_terms, dangerous_apis, source_indicators, sink_indicators, and negative_constraints:
    - SOURCE: Where does untrusted data enter?
    - SINK: What dangerous operation is performed?
    - FLOW: How does data flow from the source to the sink?
    - {start_point_instruction}
    - Treat negative_constraints as disqualifiers that should reject false matches early.
    - Treat likely_false_positive_patterns as early warning signs for dead ends.

{observation_strategy}

{candidate_priority_strategy}

4. For each {candidate_scope_label}, use the following tools depending on your needs:
    - {scope_listing_instruction}
    - Use search_in_file/search_in_folder to locate potential sinks
    - Use search_in_folder to identify sources (config parsing, user input, file reads, etc.)
    - Use read_file or get_function_code to inspect suspicious code in depth
    - Use analyze_data_flow to trace data flow from source to sink

5. Think about alternative implementations:
    - Different APIs for the same functionality
    - Different data formats (JSON, YAML, XML, pickle)
    - Different execution methods (subprocess, os, multiprocessing)
    - Use variant_hypotheses to prioritize plausible variants before repo-wide exploration

6. {widening_heading}:
{widening_instruction}

{hypothesis_instruction}

{verification_contract}

## Evidence-first reporting rule
- Do not report a finding without evidence snippets from files/functions.
- {rejection_instruction}

## Tool calling
You have a set of tools (functions) available. When you need code information or need to report a vulnerability, the system will invoke the corresponding functions.

Important notes:
- When you find a vulnerability, you must use the report_vulnerability tool and provide complete evidence
{completion_tracking_note}
- When you are confident no more vulnerabilities remain, clearly state "analysis complete" and summarize your findings; no special formatting is required
- Use tools to analyze code deeply; do not rely on speculation alone
""")


def build_initial_user_message(
    software_profile: Any,
    module_priorities: Dict[str, int] = None,
    critical_stop_max_priority: int = 2,
    shared_observation_count: int = 0,
    candidate_priority_enabled: bool = True,
    candidate_file_order: List[str] = None,
    candidate_schedule_provenance: Dict[str, Any] = None,
    candidate_schedule_page: Dict[str, Any] = None,
    memory_guidance_enabled: bool = True,
    reference_semantics_enabled: bool = True,
) -> str:
    if not memory_guidance_enabled:
        shared_observation_count = 0

    software_dict = _to_dict(software_profile)
    module_priorities = module_priorities or {}
    candidate_file_order = [str(path) for path in (candidate_file_order or [])]
    if not candidate_priority_enabled and not candidate_file_order:
        raise ValueError(
            "candidate-priority ablation requires a frozen global file schedule"
        )
    candidate_file_rank = (
        {}
        if candidate_priority_enabled
        else {path: index for index, path in enumerate(candidate_file_order)}
    )

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
    
    if not candidate_priority_enabled:
        schedule_contract_metadata(
            candidate_file_order,
            candidate_schedule_provenance,
        )
        active_schedule_page = validate_schedule_page(
            candidate_file_order,
            candidate_schedule_page,
        )
        project_info = {
            "project_name": project_name,
            "active_frozen_schedule_window": active_schedule_page,
        }
    else:
        prioritized_modules = []
        for raw_module in modules:
            if isinstance(raw_module, dict):
                module = dict(raw_module)
            else:
                module = {
                    "name": str(getattr(raw_module, "name", "") or ""),
                    "files": list(getattr(raw_module, "files", []) or []),
                    "description": str(
                        getattr(raw_module, "description", "") or ""
                    ),
                    "key_functions": list(
                        getattr(raw_module, "key_functions", []) or []
                    ),
                    "external_dependencies": list(
                        getattr(raw_module, "external_dependencies", []) or []
                    ),
                }
            module_files = [str(path) for path in module.get("files", []) or []]
            if candidate_file_rank:
                module_files.sort(
                    key=lambda path: (
                        candidate_file_rank.get(path, len(candidate_file_rank)),
                        path,
                    )
                )
            module["files"] = module_files
            name = str(module.get("name", "") or "")
            priority = module_priorities.get(name, 3)
            prioritized_modules.append((priority, module))

        if candidate_file_rank:
            prioritized_modules.sort(
                key=lambda item: (
                    min(
                        (
                            candidate_file_rank.get(
                                path,
                                len(candidate_file_rank),
                            )
                            for path in item[1].get("files", [])
                        ),
                        default=len(candidate_file_rank),
                    ),
                    str(item[1].get("name", "")),
                )
            )
        else:
            prioritized_modules.sort(key=lambda item: item[0])

        key_modules = []
        for priority, module in prioritized_modules[:50]:
            key_modules.append(
                {
                    "name": module.get("name"),
                    "priority": {
                        1: "🔴 PRIORITY-1",
                        2: "🟡 RELATED",
                        3: "⚪ OTHER",
                    }.get(priority, ""),
                    "files": module.get("files", [])[:5],
                    "description": module.get("description", "")[:150],
                    "key_functions": module.get("key_functions", [])[:5],
                    "external_dependencies": module.get(
                        "external_dependencies", []
                    )[:5],
                }
            )
        project_info = {
            "project_name": project_name,
            "modules": key_modules,
        }

    coverage_task_line = (
        "4. Mark each fully analyzed file with mark_file_completed"
        if memory_guidance_enabled or not candidate_priority_enabled
        else ""
    )
    numbered_coverage_task_line = (
        "5. Mark each fully analyzed file with mark_file_completed, including files with no findings"
        if memory_guidance_enabled or not candidate_priority_enabled
        else ""
    )
    hypothesis_record_line = (
        "- Record rejected hypotheses, evidence gaps, shared-memory hits, and next best queries as you go"
        if memory_guidance_enabled
        else "- Record rejected hypotheses, evidence gaps, and next best queries in the current analysis"
    )
    progress_tracking_line = (
        "- Keep scan progress accurate by calling mark_file_completed as soon as a file is fully analyzed"
        if memory_guidance_enabled
        else ""
    )

    if not reference_semantics_enabled:
        priority_task = (
            "Inspect the host-precomputed module order."
            if candidate_priority_enabled
            else "Inspect only files in the current host-injected frozen schedule window."
        )
        memory_task = (
            "Reuse run-scoped shared observations and mark fully inspected files complete."
            if memory_guidance_enabled
            else (
                "Mark fully inspected window files complete for private host coverage accounting."
                if not candidate_priority_enabled
                else "Keep conclusions within the current analysis."
            )
        )
        return f"""Use the target architecture and frozen CWE-only card to inspect this repository.

## Project Architecture
{json.dumps(project_info, indent=2, ensure_ascii=False)}

## Your Task
1. {priority_task}
2. Identify concrete code behavior corresponding to one of the listed CWE categories.
3. Report supported findings with report_vulnerability.
4. {memory_task}

Do not infer hidden reference details. Begin analysis now."""


    if not candidate_priority_enabled:
        shared_line = (
            "Read focused shared-public-memory observations before broad searches.\n"
            if shared_observation_count > 0
            else ""
        )
        return f"""Based on the project architecture and known vulnerability pattern, search for similar vulnerabilities.

## Candidate-priority ablation
Use only pending files in the current host-injected contiguous window. Pages are first-presented in frozen order; current structured repository-path enumeration and tool eligibility exclude completed, prior, and future pages. Historical transcript may retain already-presented page text, but it cannot reactivate or recount those paths. Within-window visitation is model-controlled and recorded; do not claim deterministic traversal.

## Project Architecture
{json.dumps(project_info, indent=2, ensure_ascii=False)}

## Your Task
1. Inspect only files in the current frozen schedule window
2. Trace SOURCE → FLOW → SINK with concrete evidence
3. Report findings with report_vulnerability
{coverage_task_line}
{shared_line}
Begin analysis now."""

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
{numbered_coverage_task_line}

## Analysis Strategy
{shared_memory_priority_line}{module_scan_line}
{shared_memory_section}- Look for alternative APIs that perform similar dangerous operations
- Trace data flow from user input/config to dangerous sinks
{widening_scope_line}
{hypothesis_record_line}
- {analysis_scope_line}
{progress_tracking_line}

{start_instruction}"""


def build_intermediate_user_message(
    scanned_files: List[str] = None,
    pending_files: List[str] = None,
    findings: List[Dict[str, str]] = None,
    progress_info: str = "",
    critical_stop_max_priority: int = 2,
    shared_observation_count: int = 0,
    candidate_priority_enabled: bool = True,
    candidate_file_order: List[str] = None,
    candidate_schedule_provenance: Dict[str, Any] = None,
    candidate_schedule_page: Dict[str, Any] = None,
    memory_guidance_enabled: bool = True,
    reference_semantics_enabled: bool = True,
    has_priority_one: bool = True,
    has_related: bool = True,
    compact: bool = False,
) -> str:
    """Build intermediate prompt with context about what has already been scanned."""
    candidate_file_order = [str(path) for path in (candidate_file_order or [])]
    if not candidate_priority_enabled and not candidate_file_order:
        raise ValueError(
            "candidate-priority ablation requires a frozen global file schedule"
        )
    scheduled_state_section = ""
    if not candidate_priority_enabled:
        schedule_contract_metadata(
            candidate_file_order,
            candidate_schedule_provenance,
        )
        active_schedule_page = validate_schedule_page(
            candidate_file_order,
            candidate_schedule_page,
        )
        scheduled_state_section = (
            "\n\n## Active Frozen Schedule Window\n"
            + json.dumps(active_schedule_page, indent=2, ensure_ascii=False)
        )
    if not reference_semantics_enabled:
        scope_line = (
            "Continue through the host-precomputed module presentation."
            if candidate_priority_enabled
            else "Continue only within the current host-injected frozen schedule window."
        )
        msg = (
            "Continue the CWE-card analysis:\n"
            f"1. {scope_line}\n"
            "2. Inspect concrete target code for the listed CWE categories.\n"
            "3. Report only supported findings with report_vulnerability.\n"
            "4. Do not infer hidden reference details."
        )
        if memory_guidance_enabled:
            if progress_info:
                msg += f"\n\nProgress: {progress_info}"
            if shared_observation_count > 0:
                msg += (
                    f"\n\nRun-scoped shared observations available: {shared_observation_count}."
                )
            if not candidate_priority_enabled:
                msg += scheduled_state_section
            elif scanned_files:
                visible_scanned_files = (
                    scanned_files
                    if not candidate_priority_enabled
                    else scanned_files[:20]
                )
                msg += f"\n\nPreviously inspected files: {visible_scanned_files}"
            if findings:
                msg += f"\n\nPreviously reported finding count: {len(findings)}"
        if not candidate_priority_enabled and scheduled_state_section not in msg:
            msg += scheduled_state_section
        return msg

    if not memory_guidance_enabled:
        if not candidate_priority_enabled:
            scope_instruction = (
                "Use only the current host-injected frozen schedule window; the host blocks other pages."
            )
        elif not has_priority_one and has_related:
            scope_instruction = (
                "Inspect all files in RELATED modules before widening to focused repo-wide searches."
            )
        elif not has_priority_one:
            scope_instruction = (
                "Use scan_start_points and focused repo-wide searches because no scoped modules are identified."
            )
        elif critical_stop_max_priority == 1:
            scope_instruction = (
                "Inspect PRIORITY-1 modules and do not widen to RELATED modules while that scope remains."
            )
        else:
            scope_instruction = "Inspect PRIORITY-1 modules, then check RELATED modules as evidence requires."
        msg = (
            "Analyze the current vulnerability-search scope:\n"
            f"1. {scope_instruction}\n"
            "2. Trace concrete SOURCE -> FLOW -> SINK evidence.\n"
            "3. Report each supported finding with report_vulnerability.\n"
            "4. Record rejected hypotheses, evidence gaps, and next best queries in the current response."
        )
        if not candidate_priority_enabled:
            msg += (
                "\n5. Mark each fully inspected window file with mark_file_completed "
                "for private host coverage accounting."
            )
            msg += scheduled_state_section
        return msg

    normalized_max_priority = 1 if critical_stop_max_priority == 1 else 2



    if not candidate_priority_enabled:
        msg = """Continue vulnerability analysis through the current frozen schedule window:
1. Use only pending files in this contiguous host-injected window; structured repository-path fields remain globally rank-ordered
2. Mark each fully analyzed file with mark_file_completed
3. Trace concrete SOURCE → FLOW → SINK evidence
4. Within-window visitation is model-controlled and recorded; do not claim deterministic traversal."""
    elif not has_priority_one and has_related:
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
            f"broad searches for a new {'module' if candidate_priority_enabled else 'scheduled file'} or pattern. Prefer focused query terms derived from the "
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
        if not candidate_priority_enabled:
            msg += scheduled_state_section
        return msg

    if not candidate_priority_enabled:
        msg += scheduled_state_section
    else:
        if findings:
            msg += "\n\n**Already Reported Vulnerabilities** (DO NOT REPORT AGAIN):"
            for finding in findings:
                msg += (
                    f"\n- {finding['file']}: {finding['type']} "
                    f"({finding['confidence']})"
                )

        if scanned_files:
            sample = scanned_files[:20]
            msg += f"\n\n**Already Scanned Files** ({len(scanned_files)} total):"
            for file_path in sample:
                msg += f"\n- {file_path}"
            if len(scanned_files) > 20:
                msg += f"\n- ... and {len(scanned_files) - 20} more files"
    
    return msg
