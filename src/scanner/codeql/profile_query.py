"""Helpers to build CodeQL generation prompts from vulnerability profiles."""

from typing import Optional, Tuple

from llm import BaseLLMClient

from .query_generator import CodeQLQueryGenerator


def _build_intent_from_vuln_profile(vulnerability_profile: dict) -> str:
    sink_type = vulnerability_profile.get("sink_features", {}).get(
        "type", "code_execution"
    )
    sink_function = vulnerability_profile.get("sink_features", {}).get(
        "function", ""
    )
    source_type = vulnerability_profile.get("source_features", {}).get(
        "data_type", "user_input"
    )
    vuln_desc = vulnerability_profile.get("vuln_description", "")

    return f"""Find vulnerabilities matching this profile:
- Vulnerability Type: {sink_type}
- Sink Function: {sink_function}
- Source Type: {source_type}
- Description: {vuln_desc[:200]}

Generate a CodeQL query to detect calls to the sink function '{sink_function}' that could lead to {sink_type} vulnerabilities."""


def _build_context_from_vuln_profile(vulnerability_profile: dict) -> str:
    sink_function = vulnerability_profile.get("sink_features", {}).get(
        "function", ""
    )
    sink_type = vulnerability_profile.get("sink_features", {}).get("type", "code_execution")

    return f"""Use these validated CodeQL templates:

**Template A - Find specific function calls**:
```ql
from Call call, Name func
where
  call.getFunc() = func and
  func.getId() = "function_name"
select call, "Found dangerous function call"
```

**Template B - Find method calls**:
```ql
from Call call, Attribute attr, Name base
where
  call.getFunc() = attr and
  attr.getObject() = base and
  base.getId() = "module_name" and
  attr.getName() = "method_name"
select call, "Found dangerous method call"
```

**Template C - Find multiple dangerous functions**:
```ql
from Call call, Name func
where
  call.getFunc() = func and
  func.getId() in ["eval", "exec", "compile"]
select call, "Found dangerous call: " + func.getId()
```

For this vulnerability (Sink: {sink_function}, Type: {sink_type}), choose the most appropriate template.

IMPORTANT:
- Use 'Call' not 'CallNode'
- Use 'call.getFunc()' not 'call.getFunction()'
- For Attribute, use 'attr.getObject()' and 'attr.getName()'
- Import only 'import python' (no submodules)
- Must include metadata with '@kind problem'"""


def generate_codeql_query_from_vuln_profile(
    vulnerability_profile: dict, llm_client: BaseLLMClient, max_retries: int = 10
) -> Tuple[bool, str, str]:
    generator = CodeQLQueryGenerator(
        llm_client=llm_client, language="python", verbose=True
    )
    intent = _build_intent_from_vuln_profile(vulnerability_profile)
    context = _build_context_from_vuln_profile(vulnerability_profile)
    result = generator.generate_query(
        intent=intent, context=context, max_retries=max_retries, auto_fix=True
    )

    if result.success:
        return True, result.query, ""

    return (
        False,
        result.query,
        f"Failed after {result.attempts} attempts. Errors: {'; '.join(result.errors)}",
    )
