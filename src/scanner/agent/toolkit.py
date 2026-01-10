"""Tools exposed to the agentic vulnerability finder."""

import ast
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from utils.tree_utils import build_path_tree, format_file_size, render_tree


@dataclass
class ToolResult:
    success: bool
    content: str
    error: Optional[str] = None


class AgenticToolkit:
    def __init__(self, repo_path: Path):
        self.repo_path = repo_path
        self._file_cache: Dict[str, str] = {}

    @staticmethod
    def _format_size(size_bytes: int) -> str:
        return format_file_size(size_bytes)

    @staticmethod
    def _build_path_tree(paths_with_values: List[Any]) -> Dict:
        return build_path_tree(paths_with_values)

    @staticmethod
    def _render_tree(node: Dict, prefix: str = "", value_formatter=None) -> List[str]:
        return render_tree(node, prefix, value_formatter)

    def get_available_tools(self) -> List[Dict[str, Any]]:
        return [
            {
                "type": "function",
                "function": {
                    "name": "read_file",
                    "description": "读取仓库中指定文件的内容，用于检查源代码中潜在漏洞。",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "file_path": {
                                "type": "string",
                                "description": "相对于仓库根目录的文件路径",
                            },
                            "start_line": {
                                "type": "integer",
                                "description": "可选起始行号（从 1 开始）。不提供则从文件开头读取。",
                            },
                            "end_line": {
                                "type": "integer",
                                "description": "可选结束行号（从 1 开始）。不提供则读取到文件末尾。",
                            },
                        },
                        "required": ["file_path"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "search_in_file",
                    "description": "在指定文件中搜索模式（正则或纯文本），并返回带行号的匹配行。",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "file_path": {"type": "string", "description": "文件的相对路径"},
                            "pattern": {"type": "string", "description": "搜索模式（支持正则）"},
                            "context_lines": {
                                "type": "integer",
                                "description": "每处匹配前后返回的上下文行数（默认：2）",
                            },
                        },
                        "required": ["file_path", "pattern"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "search_in_folder",
                    "description": "在某个文件夹下的所有 Python 文件中搜索模式，返回文件路径与匹配行。",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "folder_path": {"type": "string", "description": "文件夹的相对路径"},
                            "pattern": {"type": "string", "description": "搜索模式（支持正则）"},
                            "max_results": {
                                "type": "integer",
                                "description": "最多返回的结果数量（默认：50）",
                            },
                        },
                        "required": ["folder_path", "pattern"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "list_files_in_folder",
                    "description": "列出文件夹内所有 Python 文件及其大小。",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "folder_path": {"type": "string", "description": "文件夹的相对路径"},
                            "recursive": {
                                "type": "boolean",
                                "description": "是否递归搜索（默认：True）",
                            },
                        },
                        "required": ["folder_path"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "get_function_code",
                    "description": "从文件中提取指定函数或类的源代码。",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "file_path": {"type": "string", "description": "文件的相对路径"},
                            "function_name": {"type": "string", "description": "要提取的函数或类名"},
                        },
                        "required": ["file_path", "function_name"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "get_imports",
                    "description": "获取 Python 文件中的所有 import 语句，展示导入了哪些模块与函数。",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "file_path": {"type": "string", "description": "文件的相对路径"}
                        },
                        "required": ["file_path"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "find_dangerous_patterns",
                    "description": "在文件或文件夹中搜索潜在危险模式，例如 subprocess 调用、eval、exec、pickle 等。",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "path": {"type": "string", "description": "要分析的文件或文件夹相对路径"},
                            "patterns": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "可选：指定要搜索的具体模式列表。不提供则使用默认危险模式集合。",
                            },
                        },
                        "required": ["path"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "analyze_data_flow",
                    "description": "深度分析函数的代码结构，提供详细信息：参数、变量使用、函数调用、属性访问、字符串操作、赋值、返回值等。",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "file_path": {"type": "string", "description": "文件的相对路径"},
                            "function_name": {"type": "string", "description": "要分析的函数名"},
                        },
                        "required": ["file_path", "function_name"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "report_vulnerability",
                    "description": "上报你发现的潜在漏洞。",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "file_path": {"type": "string", "description": "漏洞所在的文件路径"},
                            "function_name": {"type": "string", "description": "包含漏洞的函数或方法名"},
                            "line_number": {"type": "integer", "description": "漏洞的大致行号"},
                            "vulnerability_type": {"type": "string", "description": "漏洞类型"},
                            "description": {"type": "string", "description": "漏洞的详细描述"},
                            "evidence": {"type": "string", "description": "证明漏洞存在的代码片段或证据"},
                            "similarity_to_known": {"type": "string", "description": "说明相似性的原因"},
                            "confidence": {"type": "string", "description": "置信度：high / medium / low"},
                            "attack_scenario": {"type": "string", "description": "利用场景"},
                        },
                        "required": [
                            "file_path",
                            "vulnerability_type",
                            "description",
                            "evidence",
                            "similarity_to_known",
                            "confidence",
                        ],
                    },
                },
            },
        ]

    def execute_tool(self, tool_name: str, parameters: Dict[str, Any]) -> ToolResult:
        try:
            if tool_name == "read_file":
                return self._read_file(**parameters)
            if tool_name == "search_in_file":
                return self._search_in_file(**parameters)
            if tool_name == "search_in_folder":
                return self._search_in_folder(**parameters)
            if tool_name == "list_files_in_folder":
                return self._list_files_in_folder(**parameters)
            if tool_name == "get_function_code":
                return self._get_function_code(**parameters)
            if tool_name == "get_imports":
                return self._get_imports(**parameters)
            if tool_name == "find_dangerous_patterns":
                return self._find_dangerous_patterns(**parameters)
            if tool_name == "analyze_data_flow":
                return self._analyze_data_flow(**parameters)
            if tool_name == "report_vulnerability":
                return self._report_vulnerability(**parameters)
            return ToolResult(success=False, content="", error=f"Unknown tool: {tool_name}")
        except Exception as exc:  # pylint: disable=broad-except
            return ToolResult(success=False, content="", error=str(exc))

    def _read_file(self, file_path: str, start_line: int = None, end_line: int = None) -> ToolResult:
        full_path = self.repo_path / file_path
        if not full_path.exists():
            return ToolResult(success=False, content="", error=f"File not found: {file_path}")
        try:
            content = full_path.read_text(encoding="utf-8", errors="ignore")
            lines = content.split("\n")
            if start_line is not None or end_line is not None:
                start_idx = (start_line - 1) if start_line else 0
                end_idx = end_line if end_line else len(lines)
                lines = lines[start_idx:end_idx]
                numbered_lines = [f"{start_idx + i + 1}: {line}" for i, line in enumerate(lines)]
                content = "\n".join(numbered_lines)
            else:
                numbered_lines = [f"{i + 1}: {line}" for i, line in enumerate(lines)]
                content = "\n".join(numbered_lines)
            if len(content) > 15000:
                content = content[:15000] + "\n... [truncated, use start_line/end_line to read specific sections]"
            return ToolResult(success=True, content=content)
        except Exception as exc:  # pylint: disable=broad-except
            return ToolResult(success=False, content="", error=str(exc))

    def _search_in_file(self, file_path: str, pattern: str, context_lines: int = 2) -> ToolResult:
        full_path = self.repo_path / file_path
        if not full_path.exists():
            return ToolResult(success=False, content="", error=f"File not found: {file_path}")
        try:
            content = full_path.read_text(encoding="utf-8", errors="ignore")
            lines = content.split("\n")
            regex = re.compile(pattern, re.IGNORECASE)
            matches = []
            for i, line in enumerate(lines):
                if regex.search(line):
                    start = max(0, i - context_lines)
                    end = min(len(lines), i + context_lines + 1)
                    context = []
                    for j in range(start, end):
                        prefix = ">>> " if j == i else "    "
                        context.append(f"{prefix}{j + 1}: {lines[j]}")
                    matches.append("\n".join(context))
            if not matches:
                return ToolResult(success=True, content=f"No matches found for pattern: {pattern}")
            result = f"Found {len(matches)} matches:\n\n" + "\n\n---\n\n".join(matches[:20])
            if len(matches) > 20:
                result += f"\n\n... and {len(matches) - 20} more matches"
            return ToolResult(success=True, content=result)
        except Exception as exc:  # pylint: disable=broad-except
            return ToolResult(success=False, content="", error=str(exc))

    def _search_in_folder(self, folder_path: str, pattern: str, max_results: int = 50) -> ToolResult:
        full_path = self.repo_path / folder_path
        if not full_path.exists():
            return ToolResult(success=False, content="", error=f"Folder not found: {folder_path}")
        try:
            regex = re.compile(pattern, re.IGNORECASE)
            file_results: Dict[str, List[Any]] = {}
            total_matches = 0
            for py_file in full_path.rglob("*.py"):
                if total_matches >= max_results:
                    break
                try:
                    content = py_file.read_text(encoding="utf-8", errors="ignore")
                    lines = content.split("\n")
                    for i, line in enumerate(lines):
                        if regex.search(line):
                            rel_path = str(py_file.relative_to(self.repo_path))
                            file_results.setdefault(rel_path, []).append((i + 1, line.strip()))
                            total_matches += 1
                            if total_matches >= max_results:
                                break
                except Exception:  # pylint: disable=broad-except
                    continue
            if not file_results:
                return ToolResult(success=True, content=f"No matches found for pattern: {pattern}")
            result_lines = [f"Found {total_matches} matches in {len(file_results)} files:\n"]
            for file_path in sorted(file_results.keys()):
                result_lines.append(f"\n{file_path}:")
                for line_num, line_content in file_results[file_path][:10]:
                    result_lines.append(f"  L{line_num}: {line_content}")
                if len(file_results[file_path]) > 10:
                    result_lines.append(
                        f"  ... and {len(file_results[file_path]) - 10} more matches in this file"
                    )
            return ToolResult(success=True, content="\n".join(result_lines))
        except Exception as exc:  # pylint: disable=broad-except
            return ToolResult(success=False, content="", error=str(exc))

    def _list_files_in_folder(self, folder_path: str, recursive: bool = True) -> ToolResult:
        full_path = self.repo_path / folder_path
        if not full_path.exists():
            return ToolResult(success=False, content="", error=f"Folder not found: {folder_path}")
        try:
            glob_pattern = "**/*.py" if recursive else "*.py"
            file_info: List[Any] = []
            total_size = 0
            for py_file in full_path.glob(glob_pattern):
                rel_path = str(py_file.relative_to(self.repo_path))
                size = py_file.stat().st_size
                total_size += size
                file_info.append((rel_path, size))
            if not file_info:
                return ToolResult(success=True, content="No Python files found")
            tree = self._build_path_tree(file_info)
            tree_lines = self._render_tree(tree, value_formatter=self._format_size)
            result = f"Found {len(file_info)} Python files (total: {self._format_size(total_size)}):\n\n" + "\n".join(tree_lines)
            return ToolResult(success=True, content=result)
        except Exception as exc:  # pylint: disable=broad-except
            return ToolResult(success=False, content="", error=str(exc))

    def _get_function_code(self, file_path: str, function_name: str) -> ToolResult:
        full_path = self.repo_path / file_path
        if not full_path.exists():
            return ToolResult(success=False, content="", error=f"File not found: {file_path}")
        try:
            content = full_path.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(content)
            lines = content.split("\n")
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    if node.name == function_name:
                        start_line = node.lineno - 1
                        end_line = node.end_lineno if hasattr(node, "end_lineno") else start_line + 50
                        func_lines = lines[start_line:end_line]
                        numbered = [f"{start_line + i + 1}: {line}" for i, line in enumerate(func_lines)]
                        return ToolResult(success=True, content="\n".join(numbered))
            return ToolResult(success=False, content="", error=f"Function/class not found: {function_name}")
        except Exception as exc:  # pylint: disable=broad-except
            return ToolResult(success=False, content="", error=str(exc))

    def _get_imports(self, file_path: str) -> ToolResult:
        full_path = self.repo_path / file_path
        if not full_path.exists():
            return ToolResult(success=False, content="", error=f"File not found: {file_path}")
        try:
            content = full_path.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(content)
            imports: List[str] = []
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.append(
                            f"import {alias.name}" + (f" as {alias.asname}" if alias.asname else "")
                        )
                elif isinstance(node, ast.ImportFrom):
                    module = node.module or ""
                    names = ", ".join(
                        alias.name + (f" as {alias.asname}" if alias.asname else "") for alias in node.names
                    )
                    imports.append(f"from {module} import {names}")
            if not imports:
                return ToolResult(success=True, content="No imports found")
            return ToolResult(success=True, content="\n".join(imports))
        except Exception as exc:  # pylint: disable=broad-except
            return ToolResult(success=False, content="", error=str(exc))

    def _find_dangerous_patterns(self, path: str, patterns: List[str] = None) -> ToolResult:
        default_patterns = [
            r"subprocess\.(run|call|Popen|check_output|check_call)",
            r"os\.(system|popen|spawn|exec)",
            r"eval\s*\(",
            r"exec\s*\(",
            r"pickle\.(load|loads)",
            r"yaml\.(load|unsafe_load)",
            r"__import__\s*\(",
            r"compile\s*\(",
            r"marshal\.(load|loads)",
            r"shelve\.",
            r"shell\s*=\s*True",
            r"codecs\.(decode|encode)",
            r"ctypes\.",
            r"cffi\.",
            r"multiprocessing\.(Pool|Process)",
        ]
        search_patterns = patterns or default_patterns
        full_path = self.repo_path / path
        if not full_path.exists():
            return ToolResult(success=False, content="", error=f"Path not found: {path}")
        try:
            results: List[Dict[str, Any]] = []
            files = [full_path] if full_path.is_file() else list(full_path.rglob("*.py"))
            for py_file in files:
                try:
                    content = py_file.read_text(encoding="utf-8", errors="ignore")
                    lines = content.split("\n")
                    rel_path = str(py_file.relative_to(self.repo_path))
                    for pattern in search_patterns:
                        regex = re.compile(pattern, re.IGNORECASE)
                        for i, line in enumerate(lines):
                            if regex.search(line):
                                results.append(
                                    {
                                        "file": rel_path,
                                        "line": i + 1,
                                        "pattern": pattern,
                                        "code": line.strip(),
                                    }
                                )
                except Exception:  # pylint: disable=broad-except
                    continue
            if not results:
                return ToolResult(success=True, content="No dangerous patterns found")
            file_groups: Dict[str, List[Dict[str, Any]]] = {}
            for item in results:
                file_groups.setdefault(item["file"], []).append(item)
            result_lines = [f"Found {len(results)} potentially dangerous patterns in {len(file_groups)} files:\n"]
            for file_path in sorted(file_groups.keys())[:30]:
                file_matches = file_groups[file_path]
                result_lines.append(f"\n{file_path}:")
                for entry in file_matches[:5]:
                    result_lines.append(f"  L{entry['line']}: {entry['code'][:80]}")
                    result_lines.append(f"    → Pattern: {entry['pattern']}")
                if len(file_matches) > 5:
                    result_lines.append(
                        f"  ... and {len(file_matches) - 5} more patterns in this file"
                    )
            if len(file_groups) > 30:
                result_lines.append(
                    f"\n... and {len(file_groups) - 30} more files with dangerous patterns"
                )
            return ToolResult(success=True, content="\n".join(result_lines))
        except Exception as exc:  # pylint: disable=broad-except
            return ToolResult(success=False, content="", error=str(exc))

    def _analyze_data_flow(self, file_path: str, function_name: str) -> ToolResult:
        full_path = self.repo_path / file_path
        if not full_path.exists():
            return ToolResult(success=False, content="", error=f"File not found: {file_path}")
        try:
            content = full_path.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(content)
            lines = content.split("\n")
            target_func = None
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == function_name:
                    target_func = node
                    break
            if not target_func:
                return ToolResult(success=False, content="", error=f"Function not found: {function_name}")
            analysis: Dict[str, Any] = {
                "function_name": function_name,
                "parameters": [arg.arg for arg in target_func.args.args],
                "variables_used": [],
                "function_calls": [],
                "attribute_accesses": [],
                "string_operations": [],
                "assignments": [],
                "returns": [],
                "code_with_line_numbers": [],
            }
            start_line = target_func.lineno - 1
            end_line = target_func.end_lineno if hasattr(target_func, "end_lineno") else start_line + 50
            func_lines = lines[start_line:end_line]
            analysis["code_with_line_numbers"] = [
                f"{start_line + i + 1}: {line}" for i, line in enumerate(func_lines)
            ]
            for node in ast.walk(target_func):
                if isinstance(node, ast.Name):
                    analysis["variables_used"].append(
                        {"name": node.id, "context": type(node.ctx).__name__, "line": node.lineno}
                    )
                if isinstance(node, ast.Call):
                    call_info: Dict[str, Any] = {"line": node.lineno}
                    if isinstance(node.func, ast.Attribute):
                        call_info["type"] = "method_call"
                        call_info["object"] = ast.unparse(node.func.value)
                        call_info["method"] = node.func.attr
                        call_info["full_call"] = f"{call_info['object']}.{call_info['method']}"
                    elif isinstance(node.func, ast.Name):
                        call_info["type"] = "function_call"
                        call_info["function"] = node.func.id
                        call_info["full_call"] = node.func.id
                    else:
                        call_info["type"] = "complex_call"
                        call_info["full_call"] = ast.unparse(node.func)
                    call_info["args"] = [ast.unparse(arg) for arg in node.args]
                    call_info["kwargs"] = {kw.arg: ast.unparse(kw.value) for kw in node.keywords}
                    analysis["function_calls"].append(call_info)
                if isinstance(node, ast.Attribute):
                    analysis["attribute_accesses"].append(
                        {
                            "object": ast.unparse(node.value),
                            "attribute": node.attr,
                            "full": ast.unparse(node),
                            "line": node.lineno,
                        }
                    )
                if isinstance(node, ast.JoinedStr):
                    analysis["string_operations"].append(
                        {"type": "f-string", "expression": ast.unparse(node), "line": node.lineno}
                    )
                elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                    analysis["string_operations"].append(
                        {
                            "type": "binary_op_add",
                            "expression": ast.unparse(node),
                            "line": node.lineno,
                        }
                    )
                elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                    if node.func.attr in ["format", "join"]:
                        analysis["string_operations"].append(
                            {
                                "type": node.func.attr,
                                "expression": ast.unparse(node),
                                "line": node.lineno,
                            }
                        )
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        analysis["assignments"].append(
                            {
                                "target": ast.unparse(target),
                                "value": ast.unparse(node.value),
                                "line": node.lineno,
                            }
                        )
                if isinstance(node, ast.Return) and node.value:
                    analysis["returns"].append(
                        {"value": ast.unparse(node.value), "line": node.lineno}
                    )
            seen_vars = set()
            unique_vars = []
            for var in analysis["variables_used"]:
                var_key = (var["name"], var["line"])
                if var_key not in seen_vars:
                    seen_vars.add(var_key)
                    unique_vars.append(var)
            analysis["variables_used"] = unique_vars[:50]
            analysis["function_calls"] = analysis["function_calls"][:50]
            analysis["attribute_accesses"] = analysis["attribute_accesses"][:50]
            return ToolResult(success=True, content=json.dumps(analysis, indent=2, ensure_ascii=False))
        except Exception as exc:  # pylint: disable=broad-except
            return ToolResult(success=False, content="", error=str(exc))

    def _report_vulnerability(self, **kwargs) -> ToolResult:
        return ToolResult(success=True, content=json.dumps(kwargs, indent=2, ensure_ascii=False))
