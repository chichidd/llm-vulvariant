import re
import json
from typing import Any, Dict, Optional, Callable

def _get_line_number_formatter(line_number_format: str, max_line_number: int) -> Callable[[int, str], str]:
    """
    获取行号格式化函数（内部辅助函数）
    
    Args:
        line_number_format: 行号格式类型
            - "standard": "1: code" (简洁清晰)
            - "markdown": "`1` code" (Markdown风格)
            - "pipe": "1 | code" (管道分隔符)
            - "bracket": "[1] code" (方括号)
        max_line_number: 最大行号，用于计算填充宽度
    
    Returns:
        格式化函数，接受 (行号, 行内容) 返回格式化后的字符串
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


def parse_llm_json(response: str) -> Optional[Dict[str, Any]]:
    """解析LLM返回的JSON"""
    import json
    
    # 尝试从响应中提取JSON
    json_match = re.search(r'```(?:json)?\s*([\s\S]*?)\s*```', response)
    if json_match:
        json_str = json_match.group(1)
    else:
        json_str = response
    
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
    使用AST提取指定函数的代码片段
    
    Args:
        file_content: 文件内容字符串
        function_name: 要提取的函数/类名称
        with_line_numbers: 是否包含行号 (默认False，保持向后兼容)
        line_number_format: 行号格式，可选:
            - "standard": "1: code" (默认，简洁清晰)
            - "padded": "001: code" (对齐的行号)
            - "markdown": "`1` code" (Markdown风格)
            - "pipe": "1 | code" (管道分隔符)
            - "bracket": "[1] code" (方括号)
    
    Returns:
        提取的函数/类代码片段，如果找不到则返回空字符串
        
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
                        
                        # 如果不需要行号，返回原始代码片段
                        if not with_line_numbers:
                            snippet = '\n'.join(lines[start_line:end_line])
                            return snippet
                        
                        # 添加行号
                        snippet_lines = lines[start_line:end_line]
                        actual_start_line = start_line + 1  # 转换为1-indexed
                        
                        # 获取行号格式化函数
                        format_func = _get_line_number_formatter(line_number_format, end_line)
                        
                        # 构建带行号的片段
                        result_lines = []
                        for i, line in enumerate(snippet_lines):
                            line_number = actual_start_line + i
                            formatted_line = format_func(line_number, line)
                            result_lines.append(formatted_line)
                        
                        return '\n'.join(result_lines)
        return ""
    except Exception as e:
        print("DEBUG", "ast", function_name, e)
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
    读取代码文件并添加行号，格式化为适合LLM查询的形式
    
    Args:
        file_path: 文件路径 (str 或 Path对象)
        start_line: 起始行号 (1-indexed, 默认为1)
        end_line: 结束行号 (1-indexed, None表示读取到文件末尾)
        line_number_format: 行号格式，可选:
            - "standard": "1: code" (默认，简洁清晰)
            - "padded": "001: code" (对齐的行号，适合大文件)
            - "markdown": "`1` code" (Markdown风格)
            - "pipe": "1 | code" (管道分隔符)
            - "bracket": "[1] code" (方括号)
        include_empty_lines: 是否包含空行 (默认True)
        encoding: 文件编码 (默认utf-8)
    
    Returns:
        带行号的代码字符串
        
    Example:
        >>> content = read_code_file_with_line_numbers("example.py", start_line=10, end_line=20)
        >>> print(content)
        10: def example():
        11:     return "hello"
        
    Notes:
        - 行号格式 "standard" 最适合LLM查询，因为格式简单，LLM容易识别和引用
        - 对于超过1000行的文件，建议使用 "padded" 格式以保持对齐
        - LLM可以轻松引用特定行，例如："在第15行..."
    """
    from pathlib import Path
    
    file_path = Path(file_path)
    
    # 读取文件内容
    try:
        with open(file_path, 'r', encoding=encoding, errors='ignore') as f:
            lines = f.readlines()
    except Exception as e:
        return f"Error reading file: {e}"
    
    # 确定行范围
    total_lines = len(lines)
    start_idx = max(0, start_line - 1)  # 转换为0-indexed
    end_idx = min(total_lines, end_line) if end_line else total_lines
    
    if start_idx >= total_lines:
        return f"Error: start_line {start_line} exceeds file length {total_lines}"
    
    # 获取行号格式化函数
    format_func = _get_line_number_formatter(line_number_format, end_idx)
    
    # 构建带行号的内容
    result_lines = []
    for i in range(start_idx, end_idx):
        line = lines[i].rstrip('\n\r')  # 移除行尾换行符，保留其他空白
        
        # 根据选项决定是否包含空行
        if not include_empty_lines and not line.strip():
            continue
        
        line_number = i + 1  # 转换回1-indexed
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
    读取代码文件中指定行及其上下文，添加行号
    
    这对于向LLM展示特定代码位置的上下文特别有用。
    
    Args:
        file_path: 文件路径 (str 或 Path对象)
        target_line: 目标行号 (1-indexed)
        context_lines: 目标行前后显示的行数 (默认5行)
        line_number_format: 行号格式 (同 read_code_file_with_line_numbers)
        encoding: 文件编码
    
    Returns:
        带行号的代码字符串，包含目标行及其上下文
        
    Example:
        >>> content = read_code_file_with_context("example.py", target_line=42, context_lines=3)
        >>> # 显示第39-45行，第42行是目标行
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
    读取代码文件的多个不连续部分，用分隔符连接
    
    适合向LLM展示代码的多个关键部分而不显示全部内容。
    
    Args:
        file_path: 文件路径 (str 或 Path对象)
        sections: 区间列表，每个区间为 (start_line, end_line) 元组
                 例如: [(1, 10), (50, 60), (100, 110)]
        line_number_format: 行号格式
        separator: 区间之间的分隔符 (默认为 "...")
        encoding: 文件编码
    
    Returns:
        带行号的代码字符串，包含所有指定区间，用分隔符连接
        
    Example:
        >>> content = read_multiple_code_sections(
        ...     "example.py",
        ...     sections=[(1, 5), (20, 25), (50, 55)]
        ... )
        >>> # 显示第1-5行，然后 "..."，然后20-25行，然后 "..."，然后50-55行
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

