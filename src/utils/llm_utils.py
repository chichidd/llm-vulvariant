import re
import json
from typing import Any, Dict, Optional, Callable, List, Tuple, Type, Union
from .logger import get_logger

logger = get_logger(__name__)


JsonTypeConstraint = Union[Type[Any], Tuple[Type[Any], ...]]

def _get_line_number_formatter(line_number_format: str, max_line_number: int) -> Callable[[int, str], str]:
    """
    Get a line-number formatting function (internal helper).

    Args:
        line_number_format: Line number format type.
            - "standard": "1: code" (simple and clear)
            - "markdown": "`1` code" (Markdown style)
            - "pipe": "1 | code" (pipe separator)
            - "bracket": "[1] code" (brackets)
        max_line_number: Max line number, used to compute padding width.

    Returns:
        A formatter function that accepts (line_number, line_text) and returns a formatted string.
    """
    if line_number_format == "standard":
        width = len(str(max_line_number))
        return lambda num, line: f"{num:>{width}}: {line}"
    elif line_number_format == "markdown":
        return lambda num, line: f"`{num}` {line}"
    elif line_number_format == "pipe":
        return lambda num, line: f"{num} | {line}"
    elif line_number_format == "bracket":
        return lambda num, line: f"[{num}] {line}"
    else:  
        return lambda num, line: f"{num}: {line}"


def extract_message_content(response: Any) -> str:
    """Extract textual content from an LLM response.

    Args:
        response: LLM response, which may be:
            - str: returned directly
            - ChatCompletionMessage: OpenAI/DeepSeek response object
            - dict: dict-form response

    Returns:
        Extracted text content.
    """
    # If it's already a string, return directly.
    if isinstance(response, str):
        return response
    
    # If it's a dict, try extracting the content field.
    if isinstance(response, dict):
        return response.get('content', str(response))
    
    # Handle ChatCompletionMessage-like objects.
    if hasattr(response, 'content'):
        return response.content or ''
    
    # Fallback: coerce to string.
    return str(response)


def _extract_json_candidates(response_str: str) -> List[str]:
    """Extract likely JSON snippets from model output."""
    candidates: List[str] = []
    seen = set()

    def _add_candidate(text: str) -> None:
        normalized = text.strip()
        if not normalized or normalized in seen:
            return
        seen.add(normalized)
        candidates.append(normalized)

    # 1) Prefer fenced JSON blocks.
    for match in re.finditer(r'```(?:json)?\s*([\s\S]*?)\s*```', response_str):
        _add_candidate(match.group(1))

    # 2) Try the entire response directly.
    _add_candidate(response_str)

    # 3) Try raw-decoding JSON objects from any "{" / "[" start.
    decoder = json.JSONDecoder()
    for idx, char in enumerate(response_str):
        if char not in "{[":
            continue
        try:
            obj, end = decoder.raw_decode(response_str[idx:])
            if isinstance(obj, dict):
                _add_candidate(response_str[idx:idx + end])
        except json.JSONDecodeError:
            continue

    return candidates


def _validate_json_dict(
    parsed: Dict[str, Any],
    required_keys: Optional[List[str]] = None,
    expected_types: Optional[Dict[str, JsonTypeConstraint]] = None,
) -> Tuple[bool, str]:
    """Validate required keys and type expectations."""
    required_keys = required_keys or []
    expected_types = expected_types or {}

    missing = [k for k in required_keys if k not in parsed]
    if missing:
        return False, f"Missing required keys: {missing}"

    for key, expected in expected_types.items():
        if key not in parsed:
            continue
        if not isinstance(parsed[key], expected):
            expected_name = (
                "/".join(t.__name__ for t in expected)
                if isinstance(expected, tuple)
                else expected.__name__
            )
            actual_name = type(parsed[key]).__name__
            return False, f"Field '{key}' type mismatch: expected {expected_name}, got {actual_name}"

    return True, ""


def _repair_json_with_llm(
    raw_text: str,
    llm_client: Any,
    required_keys: Optional[List[str]] = None,
    expected_types: Optional[Dict[str, JsonTypeConstraint]] = None,
    task_hint: str = "",
) -> str:
    """Ask the model to repair malformed JSON output."""
    required_keys = required_keys or []
    expected_types = expected_types or {}

    type_hints: List[str] = []
    for field, expected in expected_types.items():
        type_name = (
            "/".join(t.__name__ for t in expected)
            if isinstance(expected, tuple)
            else expected.__name__
        )
        type_hints.append(f'- "{field}": {type_name}')
    type_hint_text = "\n".join(type_hints) if type_hints else "- None"

    hint = task_hint or "the previous task"
    prompt = f"""Fix the following model output into a valid JSON object for {hint}.

Rules:
1. Output ONLY one JSON object. No markdown fences and no extra text.
2. Keep original meaning as much as possible.
3. Ensure required keys exist: {required_keys if required_keys else 'None'}.
4. Enforce field types:
{type_hint_text}

Raw output:
```text
{raw_text[:20000]}
```"""

    response = llm_client.chat(
        messages=[
            {"role": "system", "content": "You are a strict JSON repair assistant."},
            {"role": "user", "content": prompt},
        ],
        temperature=0.0,
    )
    return extract_message_content(response)


def parse_llm_json(
    response: Any,
    required_keys: Optional[List[str]] = None,
    expected_types: Optional[Dict[str, JsonTypeConstraint]] = None,
    llm_client: Any = None,
    max_repair_attempts: int = 0,
    task_hint: str = "",
) -> Optional[Dict[str, Any]]:
    """Parse JSON returned by an LLM.

    Args:
        response: LLM response, which can be a string or a ChatCompletionMessage-like object.
        required_keys: Optional required keys for schema-like validation.
        expected_types: Optional field type constraints, e.g. {"field": str, "items": list}.
        llm_client: Optional LLM client used for repair retries.
        max_repair_attempts: Number of repair retries when parsing/validation fails.
        task_hint: Optional task description to improve repair quality.

    Returns:
        Parsed JSON dict, or None if parsing fails.
    """
    response_str = extract_message_content(response)
    required_keys = required_keys or []
    expected_types = expected_types or {}

    latest_text = response_str
    attempts = 0
    max_attempts = max(0, max_repair_attempts)

    while True:
        last_error = "JSON parsing failed"
        for candidate in _extract_json_candidates(latest_text):
            try:
                parsed = json.loads(candidate)
            except json.JSONDecodeError as exc:
                last_error = f"JSON decode error: {exc}"
                continue

            if not isinstance(parsed, dict):
                last_error = f"Top-level JSON is {type(parsed).__name__}, expected object"
                continue

            is_valid, error_msg = _validate_json_dict(
                parsed,
                required_keys=required_keys,
                expected_types=expected_types,
            )
            if is_valid:
                return parsed
            last_error = error_msg

        if not llm_client or attempts >= max_attempts:
            if (required_keys or expected_types) and last_error:
                logger.debug(f"parse_llm_json validation failed: {last_error}")
            return None

        attempts += 1
        try:
            latest_text = _repair_json_with_llm(
                raw_text=latest_text,
                llm_client=llm_client,
                required_keys=required_keys,
                expected_types=expected_types,
                task_hint=task_hint,
            )
        except Exception as exc:  # pylint: disable=broad-except
            logger.warning(f"JSON repair attempt {attempts} failed: {exc}")
            return None
    



def extract_function_snippet_based_on_name_with_ast(
    file_content: str, 
    function_name: str,
    with_line_numbers: bool = False,
    line_number_format: str = "standard"
) -> str:
    """
    Extract a code snippet for a given function/class name using AST.

    Args:
        file_content: File content as a string.
        function_name: Function/class name to extract.
        with_line_numbers: Whether to include line numbers (default: False; keeps backward compatibility).
        line_number_format: Line number format. Options:
            - "standard": "1: code" (default, simple and clear)
            - "padded": "001: code" (aligned line numbers)
            - "markdown": "`1` code" (Markdown style)
            - "pipe": "1 | code" (pipe separator)
            - "bracket": "[1] code" (brackets)

    Returns:
        Extracted function/class snippet; returns an empty string if not found.
        
    Example:
        >>> snippet = extract_function_snippet_based_on_name_with_ast(
        ...     file_content, "my_function", with_line_numbers=True
        ... )
        >>> print(snippet)
        42: def my_function():
        43:     return "hello"
    """
    import ast
    try:
        # Parse the file content
        tree = ast.parse(file_content)
        
        # Find the function or class with the given name
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if node.name == function_name:
                    # Extract the source code for this node
                    lines = file_content.split('\n')
                    if hasattr(node, 'lineno') and hasattr(node, 'end_lineno'):
                        # Get the function/class definition
                        start_line = node.lineno - 1  # 0-indexed
                        end_line = node.end_lineno if node.end_lineno else start_line + 1
                        
                        # If line numbers are not needed, return the raw snippet.
                        if not with_line_numbers:
                            snippet = '\n'.join(lines[start_line:end_line])
                            return snippet
                        
                        # Add line numbers.
                        snippet_lines = lines[start_line:end_line]
                        actual_start_line = start_line + 1  # Convert to 1-indexed.
                        
                        # Get line number formatter.
                        format_func = _get_line_number_formatter(line_number_format, end_line)
                        
                        # Build a snippet with line numbers.
                        result_lines = []
                        for i, line in enumerate(snippet_lines):
                            line_number = actual_start_line + i
                            formatted_line = format_func(line_number, line)
                            result_lines.append(formatted_line)
                        
                        return '\n'.join(result_lines)
        return ""
    except Exception as e:
        logger.debug("DEBUG", "ast", function_name, e)
        return ""
