#!/usr/bin/env python3
"""CodeQL query generation helpers powered by LLM."""

import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from llm import BaseLLMClient, LLMConfig, create_llm_client
from utils.logger import get_logger
from utils.llm_utils import parse_llm_json

logger = get_logger(__name__)

CODEQL_TEMPLATES = {
    "python": """/**
 * @name {name}
 * @description {description}
 * @kind problem
 * @problem.severity {severity}
 * @id python/{id}
 */

import python

{query_body}
""",
    "javascript": """/**
 * @name {name}
 * @description {description}
 * @kind problem
 * @problem.severity {severity}
 * @id js/{id}
 */

import javascript

{query_body}
""",
    "java": """/**
 * @name {name}
 * @description {description}
 * @kind problem
 * @problem.severity {severity}
 * @id java/{id}
 */

import java

{query_body}
""",
}


@dataclass
class QueryGenerationResult:
    success: bool
    query: str
    attempts: int
    errors: List[str]
    validation_issues: List[str]


class CodeQLQueryValidator:
    """Minimal validation for generated CodeQL queries."""

    VALIDATION_RULES = {
        "python": {
            "required_imports": ["import python"],
            "forbidden_imports": ["import semmle.python.dataflow", "import codeql.python"],
            "required_elements": ["select"],
            "metadata_required": True,
        },
        "javascript": {
            "required_imports": ["import javascript"],
            "forbidden_imports": ["import semmle.javascript"],
            "required_elements": ["select"],
            "metadata_required": True,
        },
        "java": {
            "required_imports": ["import java"],
            "forbidden_imports": ["import semmle.code.java"],
            "required_elements": ["select"],
            "metadata_required": True,
        },
    }

    def __init__(self, language: str = "python"):
        self.language = language
        self.rules = self.VALIDATION_RULES.get(language, self.VALIDATION_RULES["python"])

    def validate(self, query: str) -> Tuple[bool, List[str]]:
        issues: List[str] = []
        lines = query.strip().split("\n")
        query_lower = query.lower()

        for required_import in self.rules["required_imports"]:
            if required_import not in query_lower:
                issues.append(f"Missing required import: {required_import}")

        for forbidden_import in self.rules["forbidden_imports"]:
            if forbidden_import in query_lower:
                issues.append(f"Using forbidden import: {forbidden_import}")

        for required_elem in self.rules["required_elements"]:
            if required_elem not in query_lower:
                issues.append(f"Missing required element: {required_elem}")

        if self.rules["metadata_required"]:
            has_metadata = any("@name" in line for line in lines)
            if not has_metadata:
                issues.append("Missing metadata comment block (/** ... */)")

        return len(issues) == 0, issues

    def fix_common_issues(self, query: str) -> Tuple[str, List[str]]:
        fixes_applied: List[str] = []
        lines = query.strip().split("\n")

        has_required_import = any(
            import_stmt in line.lower()
            for line in lines
            for import_stmt in self.rules["required_imports"]
        )

        if not has_required_import:
            insert_idx = 0
            in_metadata = False
            for i, line in enumerate(lines):
                stripped = line.strip()
                if stripped.startswith("/**"):
                    in_metadata = True
                elif stripped.endswith("*/") and in_metadata:
                    in_metadata = False
                    insert_idx = i + 1
                    break
                elif not in_metadata and stripped and not stripped.startswith("//"):
                    insert_idx = i
                    break

            for import_stmt in self.rules["required_imports"]:
                lines.insert(insert_idx, import_stmt)
                fixes_applied.append(f"Added missing import: {import_stmt}")
                insert_idx += 1

        fixed_lines = []
        for line in lines:
            for forbidden_import in self.rules["forbidden_imports"]:
                if forbidden_import in line:
                    for correct_import in self.rules["required_imports"]:
                        line = line.replace(forbidden_import, correct_import)
                        fixes_applied.append(
                            f"Replaced '{forbidden_import}' with '{correct_import}'"
                        )
                        break
            fixed_lines.append(line)
        lines = fixed_lines

        if self.rules["metadata_required"]:
            has_metadata = any("@name" in line for line in lines)
            if not has_metadata:
                metadata = [
                    "/**",
                    " * @name Find potential issues",
                    " * @description Finds potential security or quality issues",
                    " * @kind problem",
                    " * @problem.severity warning",
                    f" * @id {self.language}/generated-query",
                    " */",
                    "",
                ]
                lines = metadata + lines
                fixes_applied.append("Added missing metadata block")

        return "\n".join(lines), fixes_applied


class CodeQLQueryGenerator:
    """Generate CodeQL queries using an LLM with validation and retries."""

    def __init__(
        self,
        llm_client: Optional[BaseLLMClient] = None,
        language: str = "python",
        verbose: bool = True,
    ):
        self.llm_client = llm_client or create_llm_client(LLMConfig(provider="deepseek"))
        self.language = language
        self.validator = CodeQLQueryValidator(language)
        self.verbose = verbose

    def _log(self, message: str, level: str = "info") -> None:
        if not self.verbose:
            return
        if level == "info":
            logger.info(message)
        elif level == "warning":
            logger.warning(message)
        else:
            logger.error(message)

    def _build_generation_prompt(
        self,
        intent: str,
        context: Optional[str] = None,
        previous_attempts: Optional[List[Dict]] = None,
    ) -> str:
        template = CODEQL_TEMPLATES.get(self.language, CODEQL_TEMPLATES["python"])

        if self.language == "python":
            example_intent = "Find all calls to os.system()"
            example_query = """/**
 * @name Find os.system calls
 * @description Finds all calls to os.system() which can be dangerous
 * @kind problem
 * @problem.severity warning
 * @id python/os-system-call
 */

import python

from Call call
where
  call.getFunc().(Attribute).getObject().(Name).getId() = "os" and
  call.getFunc().(Attribute).getAttr() = "system"
select call, "Potentially dangerous call to os.system()"
"""
        elif self.language == "javascript":
            example_intent = "Find all calls to eval()"
            example_query = """/**
 * @name Find eval calls
 * @description Finds all calls to eval() which can be dangerous
 * @kind problem
 * @problem.severity error
 * @id js/eval-call
 */

import javascript

from CallExpr call
where call.getCalleeName() = "eval"
select call, "Potentially dangerous call to eval()"
"""
        else:
            example_intent = "Find security issues"
            example_query = "See language-specific documentation"

        prompt = f"""Generate a CodeQL query for {self.language.upper()} based on this requirement:

**Requirement:** {intent}

**Template Structure:**
```
{template}
```

**Example Query:**
Requirement: {example_intent}

```ql
{example_query}
```

**CRITICAL RULES:**
1. ONLY use "import {self.language}" - NO other imports like "import semmle.*" or "import codeql.*"
2. MUST include the metadata comment block (/** @name ... */)
3. Use appropriate {self.language.upper()} AST classes and predicates
4. Include a clear 'select' statement
5. Return ONLY the complete query code
6. Use proper CodeQL syntax and patterns
7. No explanations, no markdown formatting in the actual query code
"""

        if context:
            prompt += f"\n**Additional Context:**\n{context}\n"

        if previous_attempts:
            prompt += "\n**Previous Attempts and Errors:**\n"
            for i, attempt in enumerate(previous_attempts, 1):
                prompt += f"\nAttempt {i}:\n"
                if attempt.get("validation_errors"):
                    prompt += "Validation Errors:\n"
                    for error in attempt["validation_errors"]:
                        prompt += f"  - {error}\n"
                if attempt.get("execution_error"):
                    prompt += f"Execution Error: {attempt['execution_error']}\n"
                if attempt.get("query"):
                    prompt += f"Generated Query (failed):\n```ql\n{attempt['query']}\n```\n"
            prompt += "\n**Please fix the above errors and generate a correct query.**\n"

        prompt += """
You need to generate the query in json:
        ```json
        {"query": "<CodeQL query code here>"}
        ```
        Generate the CodeQL query now:"""
        return prompt

    def generate_query(
        self,
        intent: str,
        context: Optional[str] = None,
        max_retries: int = 10,
        auto_fix: bool = True,
    ) -> QueryGenerationResult:
        self._log(f"Generating CodeQL query for: {intent}")

        previous_attempts: List[Dict] = []
        all_errors: List[str] = []

        for attempt in range(max_retries):
            self._log(f"Generation attempt {attempt + 1}/{max_retries}")
            try:
                prompt = self._build_generation_prompt(
                    intent=intent,
                    context=context,
                    previous_attempts=previous_attempts if attempt > 0 else None,
                )
                response = self.llm_client.chat([{"role": "user", "content": prompt}])
                query = parse_llm_json(response)["query"]

                if auto_fix:
                    query, fixes = self.validator.fix_common_issues(query)
                    if fixes:
                        self._log(f"Applied fixes: {', '.join(fixes)}", "info")

                is_valid, validation_errors = self.validator.validate(query)
                if is_valid:
                    self._log(
                        f"Query generated successfully after {attempt + 1} attempts"
                    )
                    return QueryGenerationResult(
                        success=True,
                        query=query,
                        attempts=attempt + 1,
                        errors=all_errors,
                        validation_issues=[],
                    )

                self._log(f"Validation failed: {validation_errors}", "warning")
                all_errors.extend(validation_errors)
                previous_attempts.append(
                    {"query": query, "validation_errors": validation_errors}
                )
            except Exception as exc:  # pylint: disable=broad-except
                error_msg = f"Generation error: {exc}"
                self._log(error_msg, "error")
                all_errors.append(error_msg)
                previous_attempts.append(
                    {"query": None, "execution_error": str(exc)}
                )

        self._log(
            f"Failed to generate valid query after {max_retries} attempts", "error"
        )
        last_query = previous_attempts[-1].get("query", "") if previous_attempts else ""
        return QueryGenerationResult(
            success=False,
            query=last_query,
            attempts=max_retries,
            errors=all_errors,
            validation_issues=previous_attempts[-1].get("validation_errors", [])
            if previous_attempts
            else [],
        )


def generate_codeql_query(
    intent: str,
    language: str = "python",
    llm_config: Optional[LLMConfig] = None,
    context: Optional[str] = None,
    max_retries: int = 10,
    verbose: bool = True,
) -> Tuple[bool, str, List[str]]:
    llm_config = llm_config or LLMConfig(provider="deepseek")
    llm_client = create_llm_client(llm_config)
    generator = CodeQLQueryGenerator(
        llm_client=llm_client, language=language, verbose=verbose
    )
    result = generator.generate_query(
        intent=intent, context=context, max_retries=max_retries
    )
    return result.success, result.query, result.errors
