"""Prompt builders for the agentic vulnerability finder."""

import json
from typing import Any, Dict

from utils.logger import get_logger

logger = get_logger(__name__)


def _to_dict(obj: Any) -> Dict[str, Any]:
    if hasattr(obj, "to_dict"):
        return obj.to_dict()
    if isinstance(obj, dict):
        return obj
    return {}


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

Key point: what matters is the vulnerability "pattern", not a specific API name.

## Available tools
{tools_desc}

## Analysis strategy
1. Deeply understand the vulnerability pattern:
    - SOURCE: Where does untrusted data enter?
    - SINK: What dangerous operation is performed?
    - FLOW: How does data flow from the source to the sink?

2. For each candidate module:
    - Use list_files_in_folder to quickly understand the module
    - Use find_dangerous_patterns to locate potential sinks
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
- When analysis is finished, clearly state your conclusion; no special formatting is required
- Use tools to analyze code deeply; do not rely on speculation alone
"""


def build_initial_user_message(software_profile: Any) -> str:
    software_dict = _to_dict(software_profile)
    project_info = {
        "project_name": software_dict.get("project_name"),
        "architecture": software_dict.get("architecture", {}),
        "module_hierarchy": software_dict.get("module_hierarchy", {}),
        "key_modules": [],
    }
    modules = software_dict.get("modules", [])
    for module in modules[:50]:
        project_info["key_modules"].append(
            {
                "name": module.get("name"),
                "path": module.get("path"),
                "description": module.get("description", "")[:200],
                "key_functions": [f.get("name") for f in module.get("functions", [])[:10]],
                "external_dependencies": module.get("external_dependencies", [])[:10],
            }
        )

    return f"""Based on the project architecture information and the known vulnerability pattern, independently search for modules in the codebase that may contain similar vulnerabilities.

## Project architecture information
{json.dumps(project_info, indent=2, ensure_ascii=False)}

## Your task
1. Understand the known vulnerability pattern: carefully analyze its SOURCE/SINK/FLOW characteristics
2. Identify similar functional modules: based on the project architecture, find modules that may implement similar functionality
3. Deeply analyze code: use tools to inspect these modules and look for similar vulnerability patterns
4. Report findings: use the report_vulnerability tool for each potential vulnerability you find

## Suggested analysis strategy
- From the architecture info, identify modules functionally similar to the known vulnerable component
- Look for code that handles similar data types or performs similar operations
- Watch for equivalent implementations using different APIs (e.g., subprocess vs os.system)
- Focus on data flow: paths from user input/config to dangerous operations

Begin your analysis now. First use tools to explore the project structure, then systematically hunt for potential vulnerabilities."""


def build_intermediate_user_message() -> str:
    return """Please continue your analysis and use the available tools to deeply investigate potential vulnerabilities in the code. Notes:
        1. Do not miss any possible clues.
        2. Do not repeat previously explored analysis paths.
        3. Be thorough in searching for similar vulnerabilities and scan all potentially relevant modules.
        4. If you believe analysis is complete, clearly say so and summarize your work."""
