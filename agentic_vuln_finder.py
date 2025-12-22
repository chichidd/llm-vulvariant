"""
Agentic Vulnerability Finder - Version 2 (Autonomous Exploration)

This script uses an agentic approach with LLM to find similar vulnerabilities
in the codebase based on known vulnerability patterns. 

Key Feature: LLM autonomously explores the project architecture to identify
similar vulnerability patterns, rather than relying on pre-analyzed similar modules.

This version uses the project's customized LLM client with:
- Support for multiple LLM providers (DeepSeek, OpenAI, HKU, etc.)
- Automatic retry mechanism with configurable parameters
- Consistent interface across different providers

Usage:
    # 扫描漏洞 profile 所在的同一个 commit
    python agentic_vuln_finder.py --repo NeMo --vuln-commit 2919fedf260120766d8c714749d5e18494dcf67b --cve CVE-2025-23361 --provider deepseek
    
    # 使用已知漏洞的 profile，扫描其他 commit
    python agentic_vuln_finder.py --repo NeMo --vuln-commit 2919fedf260120766d8c714749d5e18494dcf67b --target-commit 6489229cb --cve CVE-2025-23361 --provider hku

Supported providers:
    - deepseek: DeepSeek API
    - hku: HKU internal API
    - openai: OpenAI API
    - anthropic: Anthropic Claude API

Features:
    - Autonomous module exploration based on project architecture
    - Cross-version vulnerability scanning (scan different commits)
    - Enhanced data flow analysis tools
    - Comprehensive vulnerability reporting with attack scenarios
"""

import json
import os
import re
import ast
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field
import argparse
import time

# Project imports
from core.config import LLMConfig, PROJECT_ROOT, REPO_BASE_PATH
from core.llm_client import create_llm_client, BaseLLMClient
from core.vuln_profile import VulnerabilityProfile
from core.software_profile import SoftwareProfile


# ==================== Tool Definitions ====================

@dataclass
class ToolResult:
    """Result of a tool execution"""
    success: bool
    content: str
    error: Optional[str] = None


class AgenticToolkit:
    """
    Toolkit for agentic vulnerability analysis.
    Provides file reading, code search, and dependency analysis capabilities.
    """
    
    def __init__(self, repo_path: Path, software_profile: SoftwareProfile):
        self.repo_path = repo_path
        self.software_profile = software_profile
        self._file_cache: Dict[str, str] = {}
    
    def get_available_tools(self) -> List[Dict[str, Any]]:
        """Return the list of available tools in OpenAI format"""
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
                                "description": "相对于仓库根目录的文件路径"
                            },
                            "start_line": {
                                "type": "integer",
                                "description": "可选起始行号（从 1 开始）。不提供则从文件开头读取。"
                            },
                            "end_line": {
                                "type": "integer",
                                "description": "可选结束行号（从 1 开始）。不提供则读取到文件末尾。"
                            }
                        },
                        "required": ["file_path"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "search_in_file",
                    "description": "在指定文件中搜索模式（正则或纯文本），并返回带行号的匹配行。",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "file_path": {
                                "type": "string",
                                "description": "文件的相对路径"
                            },
                            "pattern": {
                                "type": "string",
                                "description": "搜索模式（支持正则）"
                            },
                            "context_lines": {
                                "type": "integer",
                                "description": "每处匹配前后返回的上下文行数（默认：2）"
                            }
                        },
                        "required": ["file_path", "pattern"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "search_in_folder",
                    "description": "在某个文件夹下的所有 Python 文件中搜索模式，返回文件路径与匹配行。",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "folder_path": {
                                "type": "string",
                                "description": "文件夹的相对路径"
                            },
                            "pattern": {
                                "type": "string",
                                "description": "搜索模式（支持正则）"
                            },
                            "max_results": {
                                "type": "integer",
                                "description": "最多返回的结果数量（默认：50）"
                            }
                        },
                        "required": ["folder_path", "pattern"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "list_files_in_folder",
                    "description": "列出文件夹内所有 Python 文件及其大小。",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "folder_path": {
                                "type": "string",
                                "description": "文件夹的相对路径"
                            },
                            "recursive": {
                                "type": "boolean",
                                "description": "是否递归搜索（默认：True）"
                            }
                        },
                        "required": ["folder_path"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "get_function_code",
                    "description": "从文件中提取指定函数或类的源代码。",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "file_path": {
                                "type": "string",
                                "description": "文件的相对路径"
                            },
                            "function_name": {
                                "type": "string",
                                "description": "要提取的函数或类名"
                            }
                        },
                        "required": ["file_path", "function_name"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "get_imports",
                    "description": "获取 Python 文件中的所有 import 语句，展示导入了哪些模块与函数。",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "file_path": {
                                "type": "string",
                                "description": "文件的相对路径"
                            }
                        },
                        "required": ["file_path"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "find_dangerous_patterns",
                    "description": "在文件或文件夹中搜索潜在危险模式，例如 subprocess 调用、eval、exec、pickle 等。",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "path": {
                                "type": "string",
                                "description": "要分析的文件或文件夹相对路径"
                            },
                            "patterns": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "可选：指定要搜索的具体模式列表。不提供则使用默认危险模式集合。"
                            }
                        },
                        "required": ["path"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "analyze_data_flow",
                    "description": "分析函数中潜在的数据流路径，识别来源（输入）与汇点（危险操作）。",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "file_path": {
                                "type": "string",
                                "description": "文件的相对路径"
                            },
                            "function_name": {
                                "type": "string",
                                "description": "要分析的函数名"
                            }
                        },
                        "required": ["file_path", "function_name"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "report_vulnerability",
                    "description": "上报你发现的潜在漏洞。当你已收集到足够证据并确认存在问题时使用。",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "file_path": {
                                "type": "string",
                                "description": "漏洞所在的文件路径"
                            },
                            "function_name": {
                                "type": "string",
                                "description": "包含漏洞的函数或方法名"
                            },
                            "line_number": {
                                "type": "integer",
                                "description": "漏洞的大致行号"
                            },
                            "vulnerability_type": {
                                "type": "string",
                                "description": "漏洞类型（例如：command_injection、deserialization、path_traversal）"
                            },
                            "description": {
                                "type": "string",
                                "description": "漏洞的详细描述"
                            },
                            "evidence": {
                                "type": "string",
                                "description": "证明漏洞存在的代码片段或证据"
                            },
                            "similarity_to_known": {
                                "type": "string",
                                "description": "说明它与已知漏洞相似的原因"
                            },
                            "confidence": {
                                "type": "string",
                                "description": "置信度：high / medium / low"
                            },
                            "attack_scenario": {
                                "type": "string",
                                "description": "一个利用该漏洞的合理攻击场景"
                            }
                        },
                        "required": ["file_path", "vulnerability_type", "description", "evidence", "similarity_to_known", "confidence"]
                    }
                }
            }
        ]

    
    def execute_tool(self, tool_name: str, parameters: Dict[str, Any]) -> ToolResult:
        """Execute a tool and return the result"""
        try:
            if tool_name == "read_file":
                return self._read_file(**parameters)
            elif tool_name == "search_in_file":
                return self._search_in_file(**parameters)
            elif tool_name == "search_in_folder":
                return self._search_in_folder(**parameters)
            elif tool_name == "list_files_in_folder":
                return self._list_files_in_folder(**parameters)
            elif tool_name == "get_function_code":
                return self._get_function_code(**parameters)
            elif tool_name == "get_imports":
                return self._get_imports(**parameters)
            elif tool_name == "find_dangerous_patterns":
                return self._find_dangerous_patterns(**parameters)
            elif tool_name == "analyze_data_flow":
                return self._analyze_data_flow(**parameters)
            elif tool_name == "report_vulnerability":
                return self._report_vulnerability(**parameters)
            else:
                return ToolResult(success=False, content="", error=f"Unknown tool: {tool_name}")
        except Exception as e:
            return ToolResult(success=False, content="", error=str(e))
    
    def _read_file(self, file_path: str, start_line: int = None, end_line: int = None) -> ToolResult:
        """Read file content"""
        full_path = self.repo_path / file_path
        if not full_path.exists():
            return ToolResult(success=False, content="", error=f"File not found: {file_path}")
        
        try:
            content = full_path.read_text(encoding='utf-8', errors='ignore')
            lines = content.split('\n')
            
            if start_line is not None or end_line is not None:
                start_idx = (start_line - 1) if start_line else 0
                end_idx = end_line if end_line else len(lines)
                lines = lines[start_idx:end_idx]
                numbered_lines = [f"{start_idx + i + 1}: {line}" for i, line in enumerate(lines)]
                content = '\n'.join(numbered_lines)
            else:
                numbered_lines = [f"{i + 1}: {line}" for i, line in enumerate(lines)]
                content = '\n'.join(numbered_lines)
            
            if len(content) > 15000:
                content = content[:15000] + "\n... [truncated, use start_line/end_line to read specific sections]"
            
            return ToolResult(success=True, content=content)
        except Exception as e:
            return ToolResult(success=False, content="", error=str(e))
    
    
    def _search_in_file(self, file_path: str, pattern: str, context_lines: int = 2) -> ToolResult:
        """Search for pattern in a file"""
        full_path = self.repo_path / file_path
        if not full_path.exists():
            return ToolResult(success=False, content="", error=f"File not found: {file_path}")
        
        try:
            content = full_path.read_text(encoding='utf-8', errors='ignore')
            lines = content.split('\n')
            
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
                    matches.append('\n'.join(context))
            
            if not matches:
                return ToolResult(success=True, content=f"No matches found for pattern: {pattern}")
            
            result = f"Found {len(matches)} matches:\n\n" + "\n\n---\n\n".join(matches[:20])
            if len(matches) > 20:
                result += f"\n\n... and {len(matches) - 20} more matches"
            
            return ToolResult(success=True, content=result)
        except Exception as e:
            return ToolResult(success=False, content="", error=str(e))
    
    def _search_in_folder(self, folder_path: str, pattern: str, max_results: int = 50) -> ToolResult:
        """Search for pattern across files in a folder"""
        full_path = self.repo_path / folder_path
        if not full_path.exists():
            return ToolResult(success=False, content="", error=f"Folder not found: {folder_path}")
        
        try:
            regex = re.compile(pattern, re.IGNORECASE)
            results = []
            
            for py_file in full_path.rglob("*.py"):
                if len(results) >= max_results:
                    break
                    
                try:
                    content = py_file.read_text(encoding='utf-8', errors='ignore')
                    lines = content.split('\n')
                    
                    for i, line in enumerate(lines):
                        if regex.search(line):
                            rel_path = str(py_file.relative_to(self.repo_path))
                            results.append(f"{rel_path}:{i + 1}: {line.strip()}")
                            if len(results) >= max_results:
                                break
                except Exception:
                    continue
            
            if not results:
                return ToolResult(success=True, content=f"No matches found for pattern: {pattern}")
            
            result = f"Found {len(results)} matches:\n\n" + '\n'.join(results)
            return ToolResult(success=True, content=result)
        except Exception as e:
            return ToolResult(success=False, content="", error=str(e))
    
    def _list_files_in_folder(self, folder_path: str, recursive: bool = True) -> ToolResult:
        """List Python files in a folder"""
        full_path = self.repo_path / folder_path
        if not full_path.exists():
            return ToolResult(success=False, content="", error=f"Folder not found: {folder_path}")
        
        try:
            files = []
            glob_pattern = "**/*.py" if recursive else "*.py"
            
            for py_file in full_path.glob(glob_pattern):
                rel_path = str(py_file.relative_to(self.repo_path))
                size = py_file.stat().st_size
                files.append(f"{rel_path} ({size} bytes)")
            
            if not files:
                return ToolResult(success=True, content="No Python files found")
            
            result = f"Found {len(files)} Python files:\n\n" + '\n'.join(files)
            return ToolResult(success=True, content=result)
        except Exception as e:
            return ToolResult(success=False, content="", error=str(e))
    
    def _get_function_code(self, file_path: str, function_name: str) -> ToolResult:
        """Extract function code using AST"""
        full_path = self.repo_path / file_path
        if not full_path.exists():
            return ToolResult(success=False, content="", error=f"File not found: {file_path}")
        
        try:
            content = full_path.read_text(encoding='utf-8', errors='ignore')
            tree = ast.parse(content)
            lines = content.split('\n')
            
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    if node.name == function_name:
                        start_line = node.lineno - 1
                        end_line = node.end_lineno if hasattr(node, 'end_lineno') else start_line + 50
                        
                        func_lines = lines[start_line:end_line]
                        numbered = [f"{start_line + i + 1}: {line}" for i, line in enumerate(func_lines)]
                        
                        return ToolResult(success=True, content='\n'.join(numbered))
            
            return ToolResult(success=False, content="", error=f"Function/class not found: {function_name}")
        except Exception as e:
            return ToolResult(success=False, content="", error=str(e))
    
    def _get_imports(self, file_path: str) -> ToolResult:
        """Get import statements from a file"""
        full_path = self.repo_path / file_path
        if not full_path.exists():
            return ToolResult(success=False, content="", error=f"File not found: {file_path}")
        
        try:
            content = full_path.read_text(encoding='utf-8', errors='ignore')
            tree = ast.parse(content)
            
            imports = []
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.append(f"import {alias.name}" + (f" as {alias.asname}" if alias.asname else ""))
                elif isinstance(node, ast.ImportFrom):
                    module = node.module or ""
                    names = ", ".join(alias.name + (f" as {alias.asname}" if alias.asname else "") for alias in node.names)
                    imports.append(f"from {module} import {names}")
            
            if not imports:
                return ToolResult(success=True, content="No imports found")
            
            return ToolResult(success=True, content='\n'.join(imports))
        except Exception as e:
            return ToolResult(success=False, content="", error=str(e))
    
    def _find_dangerous_patterns(self, path: str, patterns: List[str] = None) -> ToolResult:
        """Find dangerous patterns in code"""
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
            results = []
            
            if full_path.is_file():
                files = [full_path]
            else:
                files = list(full_path.rglob("*.py"))
            
            for py_file in files:
                try:
                    content = py_file.read_text(encoding='utf-8', errors='ignore')
                    lines = content.split('\n')
                    rel_path = str(py_file.relative_to(self.repo_path))
                    
                    for pattern in search_patterns:
                        regex = re.compile(pattern, re.IGNORECASE)
                        for i, line in enumerate(lines):
                            if regex.search(line):
                                results.append({
                                    "file": rel_path,
                                    "line": i + 1,
                                    "pattern": pattern,
                                    "code": line.strip()
                                })
                except Exception:
                    continue
            
            if not results:
                return ToolResult(success=True, content="No dangerous patterns found")
            
            result_str = f"Found {len(results)} potentially dangerous patterns:\n\n"
            for r in results[:100]:
                result_str += f"[{r['file']}:{r['line']}] {r['code']}\n  Pattern: {r['pattern']}\n\n"
            
            if len(results) > 100:
                result_str += f"\n... and {len(results) - 100} more"
            
            return ToolResult(success=True, content=result_str)
        except Exception as e:
            return ToolResult(success=False, content="", error=str(e))
    
    def _analyze_data_flow(self, file_path: str, function_name: str) -> ToolResult:
        """Analyze data flow in a function"""
        full_path = self.repo_path / file_path
        if not full_path.exists():
            return ToolResult(success=False, content="", error=f"File not found: {file_path}")
        
        try:
            content = full_path.read_text(encoding='utf-8', errors='ignore')
            tree = ast.parse(content)
            
            # Find the function
            target_func = None
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if node.name == function_name:
                        target_func = node
                        break
            
            if not target_func:
                return ToolResult(success=False, content="", error=f"Function not found: {function_name}")
            
            # Analyze function
            analysis = {
                "function_name": function_name,
                "parameters": [arg.arg for arg in target_func.args.args],
                "potential_sources": [],
                "potential_sinks": [],
                "external_calls": []
            }
            
            source_patterns = ["input", "read", "request", "args", "params", "config", "cfg", "data"]
            sink_patterns = ["subprocess", "os.system", "eval", "exec", "pickle", "yaml.load", "run", "call", "Popen"]
            
            for node in ast.walk(target_func):
                # Check for potential sources
                if isinstance(node, ast.Name):
                    for pattern in source_patterns:
                        if pattern in node.id.lower():
                            analysis["potential_sources"].append(node.id)
                
                # Check for calls
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Attribute):
                        call_name = f"{ast.unparse(node.func.value)}.{node.func.attr}"
                        for pattern in sink_patterns:
                            if pattern in call_name.lower():
                                analysis["potential_sinks"].append({
                                    "call": call_name,
                                    "line": node.lineno
                                })
                        analysis["external_calls"].append(call_name)
                    elif isinstance(node.func, ast.Name):
                        for pattern in sink_patterns:
                            if pattern in node.func.id.lower():
                                analysis["potential_sinks"].append({
                                    "call": node.func.id,
                                    "line": node.lineno
                                })
            
            # Remove duplicates
            analysis["potential_sources"] = list(set(analysis["potential_sources"]))
            analysis["external_calls"] = list(set(analysis["external_calls"]))[:20]
            
            return ToolResult(success=True, content=json.dumps(analysis, indent=2, ensure_ascii=False))
        except Exception as e:
            return ToolResult(success=False, content="", error=str(e))
    
    def _report_vulnerability(self, **kwargs) -> ToolResult:
        """Report a vulnerability finding"""
        return ToolResult(
            success=True,
            content=json.dumps(kwargs, indent=2, ensure_ascii=False)
        )


# ==================== Agentic Vulnerability Finder ====================

class AgenticVulnFinder:
    """
    Agentic vulnerability finder with autonomous exploration.
    Uses project's customized LLM client for provider flexibility.
    """
    
    def __init__(
        self,
        llm_client: BaseLLMClient,
        repo_path: Path,
        software_profile: SoftwareProfile,
        vulnerability_profile: VulnerabilityProfile,
        max_iterations: int = 30,
        temperature: float = 0.0,
        max_tokens: int = 8192,
        verbose: bool = True
    ):
        self.llm_client = llm_client
        self.repo_path = repo_path
        self.software_profile = software_profile
        self.vulnerability_profile = vulnerability_profile
        self.max_iterations = max_iterations
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.verbose = verbose
        
        self.toolkit = AgenticToolkit(repo_path, software_profile)
        self.found_vulnerabilities: List[Dict[str, Any]] = []
        self.conversation_history: List[Dict[str, str]] = []
    
   
    
    def _build_system_prompt(self) -> str:
        """Build the system prompt with vulnerability context"""
        vuln_dict = self.vulnerability_profile.to_dict()
        
        vuln_summary = {
            "cve_id": vuln_dict.get("cve_id"),
            "vulnerability_type": vuln_dict.get("sink_features", {}).get("type", "unknown") if vuln_dict.get("sink_features") else "unknown",
            "description": vuln_dict.get("vuln_description"),
            "cause": vuln_dict.get("vuln_cause"),
            "payload": vuln_dict.get("payload"),
            "source_features": vuln_dict.get("source_features"),
            "sink_features": vuln_dict.get("sink_features"),
            "flow_features": vuln_dict.get("flow_features"),
            "exploit_scenarios": vuln_dict.get("exploit_scenarios"),
            "exploit_conditions": vuln_dict.get("exploit_conditions"),
        }
        
        tools_desc = "\n".join([
            f"- {t.get('function', {}).get('name', t.get('name', 'unknown'))}: {t.get('function', {}).get('description', t.get('description', ''))}"
            for t in self.toolkit.get_available_tools()
        ])

        return f"""你是一名专注于源代码漏洞挖掘的安全研究员专家。
你的任务是在代码库的其他部分寻找与已知漏洞“相似”的漏洞。

## 已知漏洞分析
{json.dumps(vuln_summary, indent=2, ensure_ascii=False)}

## 什么是“相似漏洞”？
相似漏洞指的是：漏洞类型相同，但实现形式或出现位置不同。例如：
- 已知：`os.system(user_input)` -> 相似：`subprocess.run(cmd, shell=True)`、`os.popen()` 等
- 已知：`pickle.load(file)` -> 相似：`yaml.unsafe_load()`、`marshal.load()`、`shelve.open()` 等
- 已知：字符串拼接导致的 SQL 注入 -> 相似：任何通过 f-string/format 拼接 SQL 查询的写法
- 已知：`open(user_path)` 的路径穿越 -> 相似：`shutil.copy(user_src, dst)`、`os.rename()` 等

关键点：重要的是漏洞“模式（PATTERN）”，而不是某个具体 API 名称。

## 可用工具
{tools_desc}

## 分析策略
1. 深入理解漏洞模式：
    - SOURCE（来源）：不可信数据从哪里进入？
    - SINK（汇点）：执行了什么危险操作？
    - FLOW（流转）：数据如何从来源流向汇点？
   
2. 对每个候选模块：
    - 先用 list_files_in_folder 快速了解模块
    - 用 find_dangerous_patterns 定位潜在汇点（sink）
    - 用 search_in_folder 寻找数据来源（配置解析、用户输入、文件读取等）
    - 用 read_file 或 get_function_code 深入查看可疑代码
    - 用 analyze_data_flow 追踪从来源到汇点的数据流
   
3. 思考替代实现：
    - 同一功能的不同 API
    - 不同数据格式（JSON、YAML、XML、pickle）
    - 不同执行方式（subprocess、os、multiprocessing）

## 工具调用
你有一组可用的工具（functions）可以使用。当需要获取代码信息或报告漏洞时，系统会自动调用相应的函数。

重要提示：
- 当你发现漏洞时，必须使用 report_vulnerability 工具提供完整证据
- 当分析完成后，说明你的结论即可，不需要特殊格式
- 合理使用工具来深入分析代码，不要只基于推测
"""
    
    def _build_initial_user_message(self) -> str:
        """Build the initial user message with project architecture"""
        software_dict = self.software_profile.to_dict()
        
        # 提取项目架构信息
        project_info = {
            "project_name": software_dict.get("project_name"),
            "architecture": software_dict.get("architecture", {}),
            "module_hierarchy": software_dict.get("module_hierarchy", {}),
            "key_modules": []
        }
        
        # 提取关键模块信息（限制数量避免token过多）
        modules = software_dict.get("modules", [])
        for module in modules[:50]:  # 限制前50个模块
            module_summary = {
                "name": module.get("name"),
                "path": module.get("path"),
                "description": module.get("description", "")[:200],  # 限制描述长度
                "key_functions": [f.get("name") for f in module.get("functions", [])[:10]],  # 前10个函数
                "external_dependencies": module.get("external_dependencies", [])[:10]  # 前10个依赖
            }
            project_info["key_modules"].append(module_summary)
        
        return f"""请根据项目架构信息和已知漏洞模式，自主寻找代码库中可能存在相似漏洞的模块。

## 项目架构信息
{json.dumps(project_info, indent=2, ensure_ascii=False)}

## 你的任务
1. **理解已知漏洞的模式**：仔细分析已知漏洞的SOURCE、SINK、FLOW特征
2. **识别相似功能模块**：基于项目架构，找出可能实现类似功能的模块
3. **深入分析代码**：使用工具深入检查这些模块，寻找相似的漏洞模式
4. **报告发现**：对每个发现的潜在漏洞使用 report_vulnerability 工具

## 分析策略建议
- 从架构信息中识别与已知漏洞功能相似的模块
- 寻找处理类似数据类型、执行类似操作的代码
- 注意不同API的等价实现（如 subprocess vs os.system）
- 关注数据流向：从用户输入/配置到危险操作的路径

现在开始你的自主分析。请先使用工具探索项目结构，然后系统地寻找潜在漏洞。"""
    
    def run(self) -> Dict[str, Any]:
        """Run the agentic analysis using native tool calling"""
        if self.verbose:
            print(f"[INFO] Starting agentic vulnerability analysis with native tool calling...")
        
        system_prompt = self._build_system_prompt()
        initial_message = self._build_initial_user_message()
        
        self.conversation_history = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": initial_message}
        ]
        
        # 获取工具定义
        tools = self.toolkit.get_available_tools()
        
        iteration = 0
        for iteration in range(self.max_iterations):
            if self.verbose:
                print(f"\n[ITERATION {iteration + 1}/{self.max_iterations}]")
            
            try:
                # 使用原生 tool calling API
                response = self.llm_client.chat(
                    self.conversation_history,
                    tools=tools,
                    tool_choice="auto",  # 让模型自动决定是否调用工具
                    temperature=self.temperature,
                    max_tokens=self.max_tokens
                )
            except Exception as e:
                print(f"[ERROR] LLM call failed: {e}")
                import traceback
                traceback.print_exc()
                break
            
            # 处理响应 - 检查是否是 tool calling 响应
            if isinstance(response, dict) and "tool_calls" in response:
                # LLM 决定调用工具
                tool_calls = response["tool_calls"]
                assistant_content = response.get("content") or ""
                
                # 添加 assistant 消息（包含 tool_calls）
                self.conversation_history.append({
                    "role": "assistant",
                    "content": assistant_content,
                    "tool_calls": tool_calls
                })
                
                if self.verbose:
                    print(f"  [LLM] Calling {len(tool_calls)} tool(s)")
                    if assistant_content:
                        snippet = assistant_content[:200] + "..." if len(assistant_content) > 200 else assistant_content
                        print(f"  [THINKING] {snippet}")
                
                # 执行每个工具调用
                for tool_call in tool_calls:
                    tool_name = tool_call["function"]["name"]
                    
                    # 解析参数
                    try:
                        parameters = json.loads(tool_call["function"]["arguments"])
                    except json.JSONDecodeError as e:
                        parameters = {}
                        print(f"  [ERROR] Failed to parse tool arguments: {e}")
                    
                    if self.verbose:
                        print(f"  [TOOL] {tool_name}: {json.dumps(parameters, ensure_ascii=False)[:80]}...")
                    
                    # 执行工具
                    result = self.toolkit.execute_tool(tool_name, parameters)
                    
                    # 处理 report_vulnerability
                    if tool_name == "report_vulnerability" and result.success:
                        vuln_report = json.loads(result.content)
                        self.found_vulnerabilities.append(vuln_report)
                        if self.verbose:
                            print(f"  [VULN FOUND] {vuln_report.get('file_path', 'unknown')} - {vuln_report.get('vulnerability_type', 'unknown')}")
                    
                    # 添加工具结果到对话历史
                    tool_result_content = result.content if result.success else f"Error: {result.error}"
                    if len(tool_result_content) > 10000:
                        tool_result_content = tool_result_content[:10000] + "\n... [truncated]"
                    
                    self.conversation_history.append({
                        "role": "tool",
                        "tool_call_id": tool_call["id"],
                        "name": tool_name,
                        "content": tool_result_content
                    })
            
            elif isinstance(response, str):
                # LLM 返回最终答案（不调用工具）
                self.conversation_history.append({
                    "role": "assistant",
                    "content": response
                })
                
                if self.verbose:
                    snippet = response[:400] + "..." if len(response) > 400 else response
                    print(f"  [LLM] {snippet}")
                
                # 检查是否表示完成
                completion_keywords = ["分析完成", "analysis complete", "没有发现", "no more", "finished", "无法找到", "cannot find"]
                if any(keyword in response.lower() for keyword in completion_keywords):
                    if self.verbose:
                        print(f"\n[COMPLETE] LLM indicates analysis is complete")
                    break
                
                # 如果连续3轮都不调用工具，提醒 LLM
                recent_msgs = self.conversation_history[-7:]  # 最近3轮(每轮约2条消息)
                tool_msg_count = sum(1 for msg in recent_msgs if msg.get("role") == "tool")
                if tool_msg_count == 0 and len(recent_msgs) >= 6:
                    self.conversation_history.append({
                        "role": "user",
                        "content": "请使用可用的工具来分析代码。如果你已经完成分析，请明确说明完成原因。"
                    })
            
            else:
                # 未知响应格式
                print(f"[WARNING] Unexpected response format: {type(response)}")
                print(f"Response: {str(response)[:200]}")
                break
        
        return {
            "vulnerabilities": self.found_vulnerabilities,
            "iterations": iteration + 1,
            "conversation_length": len(self.conversation_history)
        }


# ==================== Main Functions ====================

def load_software_profile(repo_name: str, commit_hash: str, base_dir: str = "repo-profiles") -> Optional[SoftwareProfile]:
    """Load software profile"""
    profile_path = Path(base_dir) / repo_name / commit_hash / "software_profile.json"
    
    if not profile_path.exists():
        print(f"[ERROR] Software profile not found: {profile_path}")
        return None
    
    try:
        with open(profile_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return SoftwareProfile.from_dict(data)
    except Exception as e:
        print(f"[ERROR] Failed to load software profile: {e}")
        return None


def load_vulnerability_profile(repo_name: str, commit_hash: str, cve_id: str, base_dir: str = "vuln-profiles") -> Optional[VulnerabilityProfile]:
    """Load vulnerability profile"""
    profile_path = Path(base_dir) / repo_name / commit_hash / cve_id / "vulnerability_profile.json"
    
    if not profile_path.exists():
        print(f"[ERROR] Vulnerability profile not found: {profile_path}")
        return None
    
    try:
        with open(profile_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return VulnerabilityProfile.from_dict(data)
    except Exception as e:
        print(f"[ERROR] Failed to load vulnerability profile: {e}")
        return None


def main():
    parser = argparse.ArgumentParser(description="Agentic Vulnerability Finder (Autonomous Exploration)")
    parser.add_argument("--repo", type=str, required=True, help="Repository name (e.g., NeMo)")
    parser.add_argument("--vuln-commit", type=str, required=True, help="Commit hash where vulnerability profile was generated from")
    parser.add_argument("--target-commit", type=str, default=None, help="Commit hash to scan for vulnerabilities (defaults to vuln-commit if not specified)")
    parser.add_argument("--cve", type=str, required=True, help="CVE or vulnerability ID")
    parser.add_argument("--provider", type=str, default="deepseek", help="LLM provider (deepseek, hku, openai, anthropic)")
    parser.add_argument("--max-iterations", type=int, default=30, help="Maximum iterations")
    parser.add_argument("--output", type=str, default=None, help="Output file path")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    
    args = parser.parse_args()
    
    # Change to project directory
    os.chdir(PROJECT_ROOT / "llm-vulvariant")
    
    # 区分漏洞 commit 和目标 commit
    vuln_commit = args.vuln_commit
    target_commit = args.target_commit if args.target_commit else vuln_commit
    
    # Load vulnerability profile from vuln_commit (漏洞profile总是来自vuln_commit)
    print(f"[INFO] Loading vulnerability profile from {args.repo}@{vuln_commit[:8]}...")
    vulnerability_profile = load_vulnerability_profile(args.repo, vuln_commit, args.cve)
    
    if not vulnerability_profile:
        print("[ERROR] Failed to load vulnerability profile")
        return
    
    repo_path = REPO_BASE_PATH / args.repo
    if not repo_path.exists():
        print(f"[ERROR] Repository not found: {repo_path}")
        return
    
    # Checkout to target commit if different from current
    if vuln_commit != target_commit:
        from utils.git_utils import checkout_commit, get_git_commit
        current = get_git_commit(str(repo_path))
        if current != target_commit:
            print(f"[INFO] Checking out repository to target commit {target_commit[:8]}...")
            if not checkout_commit(str(repo_path), target_commit):
                print(f"[ERROR] Failed to checkout to {target_commit}")
                return
        print(f"[INFO] Will scan target commit: {target_commit[:8]} (different from vuln commit)")
    
    # Load software profile from target_commit (软件架构来自要扫描的target commit)
    print(f"[INFO] Loading software profile from target commit {args.repo}@{target_commit[:8]}...")
    software_profile = load_software_profile(args.repo, target_commit)
    
    if not software_profile:
        print(f"[ERROR] Failed to load software profile for target commit {target_commit}")
        print(f"[INFO] You may need to generate it first using: python generate-software-profile-llama-index.py --repo {args.repo} --commit {target_commit}")
        return
    
    print(f"[INFO] Scanning repository at commit: {target_commit[:8]}")
    
    # Create LLM client
    llm_config = LLMConfig(provider=args.provider)
    llm_client = create_llm_client(llm_config)
    
    print(f"[INFO] Using LLM provider: {args.provider}")
    
    # Create and run finder
    finder = AgenticVulnFinder(
        llm_client=llm_client,
        repo_path=repo_path,
        software_profile=software_profile,
        vulnerability_profile=vulnerability_profile,
        max_iterations=args.max_iterations,
        verbose=args.verbose
    )
    
    results = finder.run()
    
    # Determine output directory
    if args.output:
        output_path = Path(args.output)
        output_dir = output_path.parent
    elif vuln_commit != target_commit:
        output_dir = Path(f"scan-results/{args.repo}_{target_commit}_{args.cve}_from_{vuln_commit[:12]}")
        output_path = output_dir / "agentic_vuln_findings_litellm.json"
    else:
        output_dir = Path(f"scan-results/{args.repo}_{vuln_commit}_{args.cve}")
        output_path = output_dir / "agentic_vuln_findings_litellm.json"
    
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Save vulnerability findings
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    # Save conversation history
    conversation_path = output_dir / "conversation_history.json"
    with open(conversation_path, 'w', encoding='utf-8') as f:
        json.dump(finder.conversation_history, f, indent=2, ensure_ascii=False)
    
    print(f"\n[COMPLETE] Found {len(results['vulnerabilities'])} potential vulnerabilities")
    print(f"[INFO] Results saved to: {output_path}")
    print(f"[INFO] Conversation history saved to: {conversation_path}")

    if results['vulnerabilities']:
        print("\n=== Vulnerability Summary ===")
        for vuln in results['vulnerabilities']:
            print(f"\n- {vuln.get('file_path', 'unknown')}")
            print(f"  Type: {vuln.get('vulnerability_type', 'unknown')}")
            print(f"  Confidence: {vuln.get('confidence', 'unknown')}")
            desc = vuln.get('description', '')
            print(f"  Description: {desc[:100]}..." if len(desc) > 100 else f"  Description: {desc}")


if __name__ == "__main__":
    main()
