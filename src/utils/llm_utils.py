from __future__ import annotations

import ast
import json
import re
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple, Type, Union

from .logger import get_logger

logger = get_logger(__name__)


JsonTypeConstraint = Union[Type[Any], Tuple[Type[Any], ...]]


@dataclass(frozen=True)
class JsonObjectMatch:
    """Structured JSON object match extracted from model output."""

    start: int
    end: int
    payload: Dict[str, Any]
    raw_text: str


JsonMatchFilter = Callable[[JsonObjectMatch, Optional[JsonObjectMatch], str], bool]

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


def extract_json_object_matches(
    response_str: str,
    validator: Optional[Callable[[Dict[str, Any]], bool]] = None,
) -> List[JsonObjectMatch]:
    """Extract all JSON objects raw-decodable from a response string."""
    matches: List[JsonObjectMatch] = []
    decoder = json.JSONDecoder()

    for idx, char in enumerate(response_str):
        if char != "{":
            continue
        try:
            parsed, end = decoder.raw_decode(response_str[idx:])
        except json.JSONDecodeError:
            continue
        if not isinstance(parsed, dict):
            continue
        if validator is not None and not validator(parsed):
            continue
        matches.append(
            JsonObjectMatch(
                start=idx,
                end=idx + end,
                payload=parsed,
                raw_text=response_str[idx:idx + end],
            )
        )

    return matches


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

    # 3) Try raw-decoding JSON objects from any "{" start.
    for match in extract_json_object_matches(response_str):
        _add_candidate(match.raw_text)

    return candidates


def extract_json_from_text(
    response_text: str,
    required_keys: Optional[List[str]] = None,
    validator: Optional[Callable[[Dict[str, Any]], bool]] = None,
    prefer_last: bool = False,
    match_filter: Optional[JsonMatchFilter] = None,
) -> Optional[Dict[str, Any]]:
    """Extract the first JSON object from a model response.

    Args:
        response_text: Raw response text from an LLM.
        required_keys: Optional keys that must be present in the returned object.
        validator: Optional predicate that must accept the parsed object.
        prefer_last: Whether to return the last matching JSON object instead of the first.
        match_filter: Optional predicate that can reject object matches using
            match location and surrounding response text.

    Returns:
        Parsed JSON object if available; otherwise, ``None``.
    """
    required_keys = required_keys or []
    matches = extract_json_object_matches(response_text)
    indexed_matches = list(enumerate(matches))
    if prefer_last:
        indexed_matches = list(reversed(indexed_matches))

    for index, match in indexed_matches:
        parsed = match.payload
        if not all(key in parsed for key in required_keys):
            continue
        if validator is not None and not validator(parsed):
            continue
        previous_match = matches[index - 1] if index > 0 else None
        if match_filter is not None and not match_filter(match, previous_match, response_text):
            continue
        return parsed
    return None


def _looks_like_example_candidate(response_text: str, match: JsonObjectMatch) -> bool:
    """Heuristic for skipping example/schema style JSON snippets."""
    window_size = 120
    prefix = response_text[max(0, match.start - window_size) : match.start].lower()
    suffix = response_text[match.end : match.end + window_size].lower()
    if not _looks_like_example_context(prefix):
        return False
    # If the payload contains pipe-separated placeholder values, it is very likely
    # an enum/example snippet (e.g. "...|..."), which should be skipped.
    payload_text = response_text[match.start : match.end]
    if not _looks_like_template_enumeration(payload_text):
        return False
    # If the model explicitly indicates this is the final output, keep it.
    if _looks_like_final_output_marker(suffix):
        return False
    return True


def _format_snippet(
    file_content: str,
    start_line: int,
    end_line: int,
    with_line_numbers: bool,
    line_number_format: str,
) -> str:
    """Format a snippet slice with optional line numbers."""
    lines = file_content.split("\n")
    snippet_lines = lines[start_line:end_line]
    if not with_line_numbers:
        return "\n".join(snippet_lines)

    actual_start_line = start_line + 1
    format_func = _get_line_number_formatter(line_number_format, end_line)
    result_lines = []
    for index, line in enumerate(snippet_lines):
        line_number = actual_start_line + index
        result_lines.append(format_func(line_number, line))
    return "\n".join(result_lines)


def _strip_leading_declaration_attributes(prefix: str) -> str:
    """Drop leading annotations/attributes before declaration checks."""
    remaining = prefix.lstrip()
    while remaining:
        if remaining.startswith("@"):
            match = re.match(r"@[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*(?:\([^)]*\))?\s*", remaining)
            if not match:
                break
            remaining = remaining[match.end():].lstrip()
            continue
        if remaining.startswith("[["):
            end_idx = remaining.find("]]")
            if end_idx == -1:
                break
            remaining = remaining[end_idx + 2:].lstrip()
            continue
        if remaining.startswith("["):
            match = re.match(r"\[[^\]]*\]\s*", remaining)
            if not match:
                break
            remaining = remaining[match.end():].lstrip()
            continue
        break
    return remaining


def _contains_top_level_char(text: str, target: str) -> bool:
    """Return whether text contains a char outside generic/template brackets."""
    angle_depth = 0
    for char in text:
        if char == "<":
            angle_depth += 1
            continue
        if char == ">" and angle_depth > 0:
            angle_depth -= 1
            continue
        if char == target and angle_depth == 0:
            return True
    return False


def _looks_like_declaration_prefix(prefix: str) -> bool:
    """Return whether text before a function name looks like a declaration."""
    remaining = _strip_leading_declaration_attributes(prefix)
    stripped = remaining.strip()
    if not stripped:
        return True
    if stripped.startswith("#"):
        return False
    if re.search(
        r"\b(if|for|while|switch|case|return|throw|catch|new|await|yield|sizeof|delete)\b",
        stripped,
    ):
        return False
    if any(token in stripped for token in ("=>", "=", "->")):
        return False
    if _contains_top_level_char(remaining, ","):
        return False
    if stripped.endswith("."):
        return False
    if stripped.endswith(("(", "[", "{")):
        return False
    if re.search(r"(?<!:):(?!:)\s*$", stripped):
        return False
    return True


def _looks_like_statement_declaration_prefix(prefix: str) -> bool:
    """Return whether a prefix is strong enough for expression-bodied declarations."""
    remaining = _strip_leading_declaration_attributes(prefix).strip()
    if not remaining:
        return False
    if re.search(
        r"\b(fun|public|private|protected|internal|static|virtual|override|sealed|async|partial|"
        r"final|abstract|suspend|inline|operator|extern|readonly|unsafe|def)\b",
        remaining,
    ):
        return True

    tokens = [token for token in remaining.split() if token]
    if len(tokens) >= 2:
        return True
    if len(tokens) != 1:
        return False

    token = tokens[0]
    if token.endswith(("::", ".")):
        return False
    if token in {"int", "string", "bool", "double", "float", "long", "short", "byte", "char", "decimal", "void"}:
        return True
    return token[0].isupper() or any(char in token for char in ".:<[]>?")


def _find_signature_opener(
    lines: List[str],
    start_line: int,
    start_column: int,
    max_scan_lines: int,
) -> Optional[Tuple[int, int, str]]:
    """Return the opener that starts the parameter or generic list."""
    for line_idx in range(start_line, min(len(lines), start_line + max_scan_lines)):
        line = lines[line_idx]
        column = start_column if line_idx == start_line else 0
        while column < len(line):
            char = line[column]
            if char.isspace():
                column += 1
                continue
            if char in "(<":
                return line_idx, column + 1, char
            return None
    return None


def _classify_signature_shape(
    lines: List[str],
    start_line: int,
    start_column: int,
    opener: str,
    max_scan_lines: int,
) -> Optional[Tuple[str, int, int]]:
    """Classify the matched signature as a block or expression-bodied declaration."""
    paren_depth = 1 if opener == "(" else 0
    angle_depth = 1 if opener == "<" else 0

    for line_idx in range(start_line, min(len(lines), start_line + max_scan_lines)):
        line = lines[line_idx]
        column = start_column if line_idx == start_line else 0
        while column < len(line):
            char = line[column]
            if char == "(":
                paren_depth += 1
            elif char == ")" and paren_depth > 0:
                paren_depth -= 1
            elif char == "<":
                angle_depth += 1
            elif char == ">" and angle_depth > 0:
                angle_depth -= 1
            elif char == "{" and paren_depth == 0 and angle_depth == 0:
                return "block", line_idx, column
            elif line.startswith("=>", column) and paren_depth == 0 and angle_depth == 0:
                return "statement", line_idx, column + 2
            elif char == "=" and paren_depth == 0 and angle_depth == 0:
                return "statement", line_idx, column + 1
            elif char == ";" and paren_depth == 0 and angle_depth == 0:
                return "statement", line_idx, column + 1
            column += 1
    return None


def _find_statement_declaration_end(
    lines: List[str],
    start_line: int,
    statement_line: int,
    statement_column: int,
    max_scan_lines: int,
) -> int:
    """Return the exclusive end line for an expression-bodied declaration."""
    scan_limit = min(len(lines), start_line + max_scan_lines)
    declaration_indent = len(lines[start_line]) - len(lines[start_line].lstrip())
    branch_keywords = ("else", "catch", "finally")
    continuation_prefixes = (
        ".",
        "?.",
        "?:",
        "&&",
        "||",
        "??",
        "+",
        "-",
        "*",
        "/",
        "%",
        "|",
        "&",
        "^",
        ",",
    )
    continuation_suffixes = (
        "=>",
        "=",
        ".",
        "?.",
        "?:",
        "&&",
        "||",
        "??",
        "+",
        "-",
        "*",
        "/",
        "%",
        "|",
        "&",
        "^",
        ",",
        "(",
        "[",
        "{",
    )

    paren_depth = 0
    bracket_depth = 0
    brace_depth = 0
    saw_body = False

    for line_idx in range(statement_line, scan_limit):
        line = lines[line_idx]
        line_indent = len(line) - len(line.lstrip())
        segment = line[statement_column:] if line_idx == statement_line else line
        stripped = segment.strip()

        column = statement_column if line_idx == statement_line else 0
        while column < len(line):
            if line.startswith("//", column):
                break
            char = line[column]
            if char == "(":
                paren_depth += 1
            elif char == ")" and paren_depth > 0:
                paren_depth -= 1
            elif char == "[":
                bracket_depth += 1
            elif char == "]" and bracket_depth > 0:
                bracket_depth -= 1
            elif char == "{":
                brace_depth += 1
            elif char == "}" and brace_depth > 0:
                brace_depth -= 1
            elif char == ";" and paren_depth == 0 and bracket_depth == 0 and brace_depth == 0:
                return line_idx + 1
            column += 1

        if stripped:
            saw_body = True
        if not stripped:
            if saw_body and line_idx > statement_line:
                return line_idx
            continue
        if paren_depth > 0 or bracket_depth > 0 or brace_depth > 0:
            continue
        if any(stripped.endswith(token) for token in continuation_suffixes):
            continue

        next_nonempty_idx: Optional[int] = None
        for next_idx in range(line_idx + 1, scan_limit):
            if lines[next_idx].strip():
                next_nonempty_idx = next_idx
                break
        if next_nonempty_idx is None:
            return line_idx + 1

        next_line = lines[next_nonempty_idx]
        next_indent = len(next_line) - len(next_line.lstrip())
        next_stripped = next_line.strip()
        if next_stripped.startswith(branch_keywords):
            continue
        # Keep indented or operator-prefixed continuation lines attached to the declaration.
        if next_indent > line_indent:
            continue
        if next_indent > declaration_indent and next_stripped.startswith(continuation_prefixes):
            continue
        if next_stripped.startswith(continuation_prefixes):
            continue
        return line_idx + 1

    return scan_limit


def _extract_with_regex_fallback(
    file_content: str,
    function_name: str,
    with_line_numbers: bool,
    line_number_format: str,
) -> str:
    """Extract a declaration block via regex-style matching for non-Python files."""
    lines = file_content.split("\n")
    name_pattern = re.compile(rf"(?<![\w$]){re.escape(function_name)}(?![\w$])")
    max_scan_lines = 200

    start_line: Optional[int] = None
    signature_shape: Optional[str] = None
    signature_end_line: Optional[int] = None
    signature_end_column: Optional[int] = None
    for line_idx, line in enumerate(lines):
        for match in name_pattern.finditer(line):
            prefix = line[:match.start()]
            stripped_prefix = _strip_leading_declaration_attributes(prefix).strip()
            if re.match(r"^(?:public|private|protected)\s+def\b", stripped_prefix) or re.match(
                r"^def\b",
                stripped_prefix,
            ):
                continue
            if not _looks_like_declaration_prefix(prefix):
                continue
            signature_opener = _find_signature_opener(
                lines,
                line_idx,
                match.end(),
                max_scan_lines,
            )
            if signature_opener is None:
                continue
            signature_info = _classify_signature_shape(
                lines,
                signature_opener[0],
                signature_opener[1],
                signature_opener[2],
                max_scan_lines,
            )
            if signature_info is None:
                continue
            if signature_info[0] == "statement" and not _looks_like_statement_declaration_prefix(prefix):
                continue
            start_line = line_idx
            signature_shape, signature_end_line, signature_end_column = signature_info
            break
        if start_line is not None:
            break

    if start_line is None:
        return _extract_ruby_method_fallback(
            file_content=file_content,
            function_name=function_name,
            with_line_numbers=with_line_numbers,
            line_number_format=line_number_format,
        )

    if signature_shape == "statement":
        return _format_snippet(
            file_content=file_content,
            start_line=start_line,
            end_line=_find_statement_declaration_end(
                lines=lines,
                start_line=start_line,
                statement_line=signature_end_line if signature_end_line is not None else start_line,
                statement_column=signature_end_column if signature_end_column is not None else 0,
                max_scan_lines=max_scan_lines,
            ),
            with_line_numbers=with_line_numbers,
            line_number_format=line_number_format,
        )

    end_line = start_line
    depth = 0
    started = False
    for line_idx in range(start_line, min(len(lines), start_line + max_scan_lines)):
        line = lines[line_idx]
        if "{" in line:
            started = True
        depth += line.count("{") - line.count("}")
        end_line = line_idx + 1
        if started and depth <= 0:
            break

    return _format_snippet(
        file_content=file_content,
        start_line=start_line,
        end_line=end_line,
        with_line_numbers=with_line_numbers,
        line_number_format=line_number_format,
    )


def _count_ruby_block_openers(line: str) -> int:
    """Count Ruby block openers that require a matching ``end``."""
    stripped = re.sub(r"#.*", "", line).strip()
    if not stripped:
        return 0
    if re.match(r"^(?:public|private|protected)\s+def\b", stripped):
        return 1
    if re.match(r"^(?:def|class|module|if|unless|case|begin|for|while|until)\b", stripped):
        return 1
    if re.search(r"\bdo\b(?:\s*\|[^|]*\|)?\s*$", stripped):
        return 1
    return 0


def _extract_ruby_method_fallback(
    file_content: str,
    function_name: str,
    with_line_numbers: bool,
    line_number_format: str,
) -> str:
    """Extract a Ruby ``def ... end`` block when brace-based matching does not apply."""
    lines = file_content.split("\n")
    max_scan_lines = 200
    method_pattern = re.compile(
        rf"^\s*(?:(?:public|private|protected)\s+)?def\s+"
        rf"(?:(?:self|[A-Za-z_]\w*(?:::[A-Za-z_]\w*)*)\.)?"
        rf"{re.escape(function_name)}(?=\s|\(|$)"
    )

    start_line: Optional[int] = None
    matched_line: Optional[str] = None
    matched_method_end: Optional[int] = None
    for line_idx, line in enumerate(lines):
        match = method_pattern.search(line)
        if match:
            start_line = line_idx
            matched_line = line
            matched_method_end = match.end()
            break

    if start_line is None:
        return ""

    if (
        matched_line is not None
        and matched_method_end is not None
        and _is_ruby_endless_method_declaration(matched_line, matched_method_end)
    ):
        return _format_snippet(
            file_content=file_content,
            start_line=start_line,
            end_line=start_line + 1,
            with_line_numbers=with_line_numbers,
            line_number_format=line_number_format,
        )

    if (
        matched_line is not None
        and matched_method_end is not None
        and _is_ruby_single_line_method_definition(matched_line, matched_method_end)
    ):
        return _format_snippet(
            file_content=file_content,
            start_line=start_line,
            end_line=start_line + 1,
            with_line_numbers=with_line_numbers,
            line_number_format=line_number_format,
        )

    depth = 0
    end_line: Optional[int] = None
    for line_idx in range(start_line, min(len(lines), start_line + max_scan_lines)):
        line = lines[line_idx]
        depth += _count_ruby_block_openers(line)
        if re.match(r"^\s*end\b", re.sub(r"#.*", "", line)):
            depth -= 1
            if depth == 0:
                end_line = line_idx + 1
                break

    if end_line is None:
        return ""

    return _format_snippet(
        file_content=file_content,
        start_line=start_line,
        end_line=end_line,
        with_line_numbers=with_line_numbers,
        line_number_format=line_number_format,
    )


def _is_ruby_endless_method_declaration(line: str, method_name_end: int) -> bool:
    """Return whether one Ruby ``def`` line uses endless-method syntax."""
    sanitized = re.sub(r"#.*", "", line)
    paren_depth = 0

    for idx in range(method_name_end, len(sanitized)):
        char = sanitized[idx]
        if char == "(":
            paren_depth += 1
            continue
        if char == ")" and paren_depth > 0:
            paren_depth -= 1
            continue
        if char != "=" or paren_depth != 0:
            continue

        previous_char = sanitized[idx - 1] if idx > 0 else ""
        next_char = sanitized[idx + 1] if idx + 1 < len(sanitized) else ""
        if previous_char in ("=", "!", "<", ">") or next_char in ("=", ">"):
            continue
        return True

    return False


def _is_ruby_single_line_method_definition(line: str, method_name_end: int) -> bool:
    """Return whether one Ruby ``def`` line closes with ``; ... ; end``."""
    sanitized = re.sub(r"#.*", "", line)
    return re.search(r";\s*end\b", sanitized[method_name_end:]) is not None


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
    default_match_filter = lambda match, previous_match, text: not _looks_like_example_candidate(text, match)

    while True:
        last_error = "JSON parsing failed"
        parsed = extract_json_from_text(
            response_text=latest_text,
            required_keys=required_keys,
            prefer_last=False,
            match_filter=default_match_filter,
            validator=lambda payload: _validate_json_dict(
                payload,
                required_keys=required_keys,
                expected_types=expected_types,
            )[0],
        )
        if parsed is not None:
            return parsed

        # Keep last error message when schema validation fails.
        if _extract_json_candidates(latest_text):
            last_error = "Schema validation failed for all candidate JSON objects"
        else:
            last_error = "No valid JSON objects found"

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
    line_number_format: str = "standard",
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
    try:
        tree = ast.parse(file_content)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if node.name != function_name:
                    continue
                if hasattr(node, "lineno") and hasattr(node, "end_lineno"):
                    start_line = node.lineno - 1
                    end_line = node.end_lineno if node.end_lineno else start_line + 1
                    return _format_snippet(
                        file_content=file_content,
                        start_line=start_line,
                        end_line=end_line,
                        with_line_numbers=with_line_numbers,
                        line_number_format=line_number_format,
                    )
        return _extract_with_regex_fallback(
            file_content=file_content,
            function_name=function_name,
            with_line_numbers=with_line_numbers,
            line_number_format=line_number_format,
        )
    except Exception as exc:
        logger.debug("AST function extraction failed for %s: %s", function_name, exc)
        return _extract_with_regex_fallback(
            file_content=file_content,
            function_name=function_name,
            with_line_numbers=with_line_numbers,
            line_number_format=line_number_format,
        )

def _looks_like_example_context(context: str) -> bool:
    """Return True when nearby context likely contains schema/example markers."""
    context_markers = (
        "example",
        "schema",
        "format",
        "valid values",
        "valid example",
        "should be",
        "one of",
        "possible values",
        "allowed values",
    )
    lower_context = context.lower()
    return any(marker in lower_context for marker in context_markers)


def _is_simple_token(value: str) -> bool:
    """Return True when token is compact and enum-like."""
    token = value.strip()
    return bool(re.fullmatch(r"[A-Za-z0-9_\\-]+", token))


def _looks_like_template_enumeration(payload_text: str) -> bool:
    """Return True when payload is likely a schema/example placeholder list."""
    if re.search(
        r'\"[^\"]*\"\\s*:\\s*\"[^\"]*\\b[A-Za-z0-9_\\-]+\\s*\\|\\s*[A-Za-z0-9_\\-]+(?:\\s*\\|\\s*[A-Za-z0-9_\\-]+)+[^\"\\n]*\"',
        payload_text,
    ):
        return True

    if re.search(r"<[^<>]+\\|[^<>]+>", payload_text):
        return True

    if re.search(r'\"[^\"\\n]*\\bone of\\b[^\"\\n]*\"', payload_text, re.IGNORECASE):
        return True

    enum_block_match = re.search(
        r'"(?:enum|oneof|one_of|possible_values|allowed_values)"\\s*:\\s*\\[(.*?)\\]',
        payload_text,
        flags=re.IGNORECASE | re.DOTALL,
    )
    if enum_block_match:
        values = re.findall(r'"([^"\\\\]*(?:\\\\.[^"\\\\]*)*)"', enum_block_match.group(1))
        if len(values) >= 2 and all(_is_simple_token(value) for value in values):
            return True

    return False


def _looks_like_final_output_marker(context: str) -> bool:
    """Return True when nearby text marks an actual final output block."""
    keep_markers = ("final", "answer", "result", "output")
    lower_context = context.lower()
    return any(marker in lower_context for marker in keep_markers)
