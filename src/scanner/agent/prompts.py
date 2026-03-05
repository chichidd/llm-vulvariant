"""Prompt builders for the agentic vulnerability finder."""

import json
from typing import Any, Dict, List

from utils.logger import get_logger
from .utils import _to_dict

logger = get_logger(__name__)

def build_system_prompt(vulnerability_profile: Any, toolkit) -> str:
    vuln_dict = _to_dict(vulnerability_profile)
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
    }

    tools_desc = "\n".join(
        [
            f"- {t.get('function', {}).get('name', t.get('name', 'unknown'))}: {t.get('function', {}).get('description', t.get('description', ''))}"
            for t in toolkit.get_available_tools()
        ]
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
2. Pay attention to the affected modules and common/similar modules in the target software.

## Available tools
{tools_desc}

## Analysis Strategy
1. Deeply understand the vulnerability pattern:
    - SOURCE: Where does untrusted data enter?
    - SINK: What dangerous operation is performed?
    - FLOW: How does data flow from the source to the sink?

2. For each candidate module, you can use the following tools depending on your needs:
    - Use list_files_in_folder to quickly understand the module
    - Use search_in_file/search_in_folder to locate potential sinks
    - Use search_in_folder to identify sources (config parsing, user input, file reads, etc.)
    - Use read_file or get_function_code to inspect suspicious code in depth
    - Use analyze_data_flow to trace data flow from source to sink

3. Think about alternative implementations:
    - Different APIs for the same functionality
    - Different data formats (JSON, YAML, XML, pickle)
    - Different execution methods (subprocess, os, multiprocessing)

## Tool calling
You have a set of tools (functions) available. When you need code information or need to report a vulnerability, the system will invoke the corresponding functions.

Important notes:
- When you find a vulnerability, you must use the report_vulnerability tool and provide complete evidence
- When you are confident no more vulnerabilities remain, clearly state "analysis complete" and summarize your findings; no special formatting is required
- Use tools to analyze code deeply; do not rely on speculation alone
"""


def build_initial_user_message(
    software_profile: Any,
    module_priorities: Dict[str, int] = None,
) -> str:
    software_dict = _to_dict(software_profile)
    module_priorities = module_priorities or {}
    
    # Build prioritized module list
    modules = software_dict.get("modules", [])
    prioritized_modules = []
    
    for module in modules:
        name = module.get("name", "")
        priority = module_priorities.get(name, 3)
        prioritized_modules.append((priority, module))
    
    # Sort by priority (1=affected, 2=related, 3=other)
    prioritized_modules.sort(key=lambda x: x[0])
    
    # Build module info with priority labels
    key_modules = []
    for priority, module in prioritized_modules[:50]:
        priority_label = {1: "🔴 AFFECTED", 2: "🟡 RELATED", 3: "⚪ OTHER"}.get(priority, "")
        key_modules.append({
            "name": module.get("name"),
            "priority": priority_label,
            "files": module.get("files", [])[:5],
            "description": module.get("description", "")[:150],
            "key_functions": module.get("key_functions", [])[:5],
            "external_dependencies": module.get("external_dependencies", [])[:5],
        })
    
    project_info = {
        "project_name": software_dict.get("basic_info", {}).get("name", ""),
        "modules": key_modules,
    }
    
    # Count priority stats
    p1_count = sum(1 for p, _ in prioritized_modules if p == 1)
    p2_count = sum(1 for p, _ in prioritized_modules if p == 2)

    return f"""Based on the project architecture and the known vulnerability pattern, search for similar vulnerabilities in the codebase.

## Module Priority Guide
- 🔴 AFFECTED ({p1_count} modules): Same category as the known vulnerability - **MUST SCAN FIRST**
- 🟡 RELATED ({p2_count} modules): Calls or is called by affected modules - scan next
- ⚪ OTHER: Lower priority

## Project Architecture
{json.dumps(project_info, indent=2, ensure_ascii=False)}

## Your Task
1. **Start with AFFECTED modules**: These share the same functionality category as the known vulnerability
2. Understand the vulnerability pattern (SOURCE → FLOW → SINK)
3. Use tools to deeply analyze code in priority order
4. Report each finding with the report_vulnerability tool

## Analysis Strategy
- For each AFFECTED module, scan ALL files for the vulnerability pattern
- Look for alternative APIs that perform similar dangerous operations
- Trace data flow from user input/config to dangerous sinks
- Do not skip any AFFECTED or RELATED modules

Begin analysis now. Start with the 🔴 AFFECTED modules."""


def build_intermediate_user_message(
    scanned_files: List[str] = None,
    findings: List[Dict[str, str]] = None,
    progress_info: str = "",
) -> str:
    """Build intermediate prompt with context about what's already been scanned."""
    msg = """Continue your vulnerability analysis:
1. Have you scanned ALL files in AFFECTED (🔴) modules?
2. Have you checked RELATED (🟡) modules?
3. Do NOT repeat previous analysis - see scanned files and findings below."""
    
    if progress_info:
        msg += f"\n\n**Progress**: {progress_info}"
    
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
