import re
import json
from typing import Any, Dict, Optional, Callable
from .logger import get_logger

logger = get_logger(__name__)

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


def parse_llm_json(response: Any) -> Optional[Dict[str, Any]]:
    """Parse JSON returned by an LLM.

    Args:
        response: LLM response, which can be a string or a ChatCompletionMessage-like object.

    Returns:
        Parsed JSON dict, or None if parsing fails.
    """
    import json
    
    # First extract a content string.
    response_str = extract_message_content(response)
    
    # Try extracting JSON from a fenced code block.
    json_match = re.search(r'```(?:json)?\s*([\s\S]*?)\s*```', response_str)
    if json_match:
        json_str = json_match.group(1)
    else:
        json_str = response_str
    
    try:
        return json.loads(json_str)
    except json.JSONDecodeError:
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


def read_code_file_with_line_numbers(
    file_path,
    start_line: int = 1,
    end_line: Optional[int] = None,
    line_number_format: str = "standard",
    include_empty_lines: bool = True,
    encoding: str = "utf-8"
) -> str:
    """
    Read a code file and add line numbers, formatted for LLM queries.

    Args:
        file_path: File path (str or Path).
        start_line: Start line number (1-indexed; default: 1).
        end_line: End line number (1-indexed; None means read to EOF).
        line_number_format: Line number format. Options:
            - "standard": "1: code" (default, simple and clear)
            - "padded": "001: code" (aligned line numbers; good for large files)
            - "markdown": "`1` code" (Markdown style)
            - "pipe": "1 | code" (pipe separator)
            - "bracket": "[1] code" (brackets)
        include_empty_lines: Whether to include empty lines (default: True).
        encoding: File encoding (default: utf-8).

    Returns:
        Code string with line numbers.
        
    Example:
        >>> content = read_code_file_with_line_numbers("example.py", start_line=10, end_line=20)
        >>> print(content)
        10: def example():
        11:     return "hello"
        
    Notes:
        - The "standard" format is best for LLM queries because it is simple and easy to reference.
        - For files over 1000 lines, consider using "padded" to keep alignment.
        - LLMs can easily reference specific lines, e.g., "at line 15...".
    """
    from pathlib import Path
    
    file_path = Path(file_path)
    
    # Read file contents.
    try:
        with open(file_path, 'r', encoding=encoding, errors='ignore') as f:
            lines = f.readlines()
    except Exception as e:
        return f"Error reading file: {e}"
    
    # Determine line range.
    total_lines = len(lines)
    start_idx = max(0, start_line - 1)  # Convert to 0-indexed.
    end_idx = min(total_lines, end_line) if end_line else total_lines
    
    if start_idx >= total_lines:
        return f"Error: start_line {start_line} exceeds file length {total_lines}"
    
    # Get line number formatter.
    format_func = _get_line_number_formatter(line_number_format, end_idx)
    
    # Build content with line numbers.
    result_lines = []
    for i in range(start_idx, end_idx):
        line = lines[i].rstrip('\n\r')  # Strip line endings; keep other whitespace.
        
        # Optionally skip empty lines.
        if not include_empty_lines and not line.strip():
            continue
        
        line_number = i + 1  # Convert back to 1-indexed.
        formatted_line = format_func(line_number, line)
        result_lines.append(formatted_line)
    
    return '\n'.join(result_lines)


def read_code_file_with_context(
    file_path,
    target_line: int,
    context_lines: int = 5,
    line_number_format: str = "standard",
    encoding: str = "utf-8"
) -> str:
    """
    Read a target line and surrounding context from a code file, with line numbers.

    This is especially useful when showing the surrounding context of a specific code location to an LLM.

    Args:
        file_path: File path (str or Path).
        target_line: Target line number (1-indexed).
        context_lines: Number of lines to show before/after the target (default: 5).
        line_number_format: Line number format (same as read_code_file_with_line_numbers).
        encoding: File encoding.

    Returns:
        Code string with line numbers, including the target line and its context.
        
    Example:
        >>> content = read_code_file_with_context("example.py", target_line=42, context_lines=3)
        >>> # Shows lines 39-45; line 42 is the target.
    """
    start_line = max(1, target_line - context_lines)
    end_line = target_line + context_lines
    
    return read_code_file_with_line_numbers(
        file_path=file_path,
        start_line=start_line,
        end_line=end_line,
        line_number_format=line_number_format,
        encoding=encoding
    )


def read_multiple_code_sections(
    file_path,
    sections: list,
    line_number_format: str = "standard",
    separator: str = "\n...\n",
    encoding: str = "utf-8"
) -> str:
    """
    Read multiple non-contiguous sections of a code file and join them with a separator.

    Useful for showing an LLM several key parts of a file without including the entire content.

    Args:
        file_path: File path (str or Path).
        sections: List of ranges, each a (start_line, end_line) tuple.
                 Example: [(1, 10), (50, 60), (100, 110)]
        line_number_format: Line number format.
        separator: Separator between sections (default: "...").
        encoding: File encoding.

    Returns:
        Code string with line numbers, containing all requested sections joined by the separator.
        
    Example:
        >>> content = read_multiple_code_sections(
        ...     "example.py",
        ...     sections=[(1, 5), (20, 25), (50, 55)]
        ... )
        >>> # Shows lines 1-5, then "...", then 20-25, then "...", then 50-55.
    """
    from pathlib import Path
    
    file_path = Path(file_path)
    result_parts = []
    
    for start_line, end_line in sections:
        section_content = read_code_file_with_line_numbers(
            file_path=file_path,
            start_line=start_line,
            end_line=end_line,
            line_number_format=line_number_format,
            encoding=encoding
        )
        
        if section_content and not section_content.startswith("Error"):
            result_parts.append(section_content)
    
    return separator.join(result_parts)

