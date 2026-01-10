"""Tools exposed to the module analyzer agent."""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class ToolResult:
    """Result of a tool execution."""
    success: bool
    content: str
    error: Optional[str] = None


class ModuleAnalyzerToolkit:
    """Toolkit providing file system operations for module analysis."""
    
    def __init__(self, repo_path: Path, file_list: List[str]):
        """
        Initialize the toolkit.
        
        Args:
            repo_path: Path to the repository root.
            file_list: List of file paths in the repository.
        """
        self.repo_path = repo_path
        self.file_list = file_list
    
    def get_available_tools(self) -> List[Dict[str, Any]]:
        """Return the list of available tools for module analysis."""
        return [
            {
                "type": "function",
                "function": {
                    "name": "list_folder",
                    "description": "列出指定文件夹下的直接子项（文件和子文件夹），用于探索仓库结构。",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "folder_paths": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "一个或多个相对于仓库根目录的文件夹路径。使用空字符串或'.'表示根目录。",
                            },
                        },
                        "required": ["folder_paths"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "read_file",
                    "description": "读取一个或多个文件的完整内容，用于分析代码结构和功能。",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "file_paths": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "一个或多个相对于仓库根目录的文件路径。",
                            },
                        },
                        "required": ["file_paths"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "finalize",
                    "description": "完成模块分析并返回最终结果。当你已经收集了足够的信息来识别所有功能模块时调用此工具。",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "modules": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "name": {"type": "string", "description": "模块名称"},
                                        "category": {"type": "string", "description": "模块类别（如：web_interface, data_loading, core_algorithm等）"},
                                        "description": {"type": "string", "description": "模块功能描述"},
                                        "files": {
                                            "type": "array",
                                            "items": {"type": "string"},
                                            "description": "模块相关文件路径列表",
                                        },
                                        "key_functions": {
                                            "type": "array",
                                            "items": {"type": "string"},
                                            "description": "模块关键函数或类名",
                                        },
                                        "dependencies": {
                                            "type": "array",
                                            "items": {"type": "string"},
                                            "description": "模块依赖的其他模块",
                                        },
                                    },
                                    "required": ["name", "category", "description", "files"],
                                },
                                "description": "识别出的模块列表",
                            },
                        },
                        "required": ["modules"],
                    },
                },
            },
        ]
    
    def execute_tool(self, tool_name: str, parameters: Dict[str, Any]) -> ToolResult:
        """Execute a tool by name with the given parameters."""
        try:
            if tool_name == "list_folder":
                return self._list_folder(**parameters)
            if tool_name == "read_file":
                return self._read_file(**parameters)
            if tool_name == "finalize":
                return self._finalize(**parameters)
            return ToolResult(success=False, content="", error=f"Unknown tool: {tool_name}")
        except Exception as exc:  # pylint: disable=broad-except
            return ToolResult(success=False, content="", error=str(exc))
    
    def _list_folder(self, folder_paths: List[str]) -> ToolResult:
        """List the contents of one or more folders."""
        folder_paths = [p for p in folder_paths if isinstance(p, str)]
        
        if not folder_paths:
            return ToolResult(
                success=False,
                content="",
                error="未提供文件夹路径。请在 folder_paths 中提供一个或多个文件夹相对路径。"
            )
        
        output_chunks: List[str] = []
        
        for raw_folder in folder_paths:
            folder = raw_folder.strip().replace("\\", "/")
            if folder.startswith("./"):
                folder = folder[2:]
            folder = folder.rstrip("/")
            
            prefix = folder + "/" if folder else ""
            matching_files = [f for f in self.file_list if f.startswith(prefix)] if prefix else list(self.file_list)
            
            if not matching_files:
                output_chunks.append(f"未找到文件夹 '{raw_folder}' 下的任何文件。")
                continue
            
            children = []
            for path in matching_files:
                rest = path[len(prefix):] if prefix else path
                first = rest.split("/", 1)[0]
                children.append(first)
            
            unique_children = sorted(set(children))
            subdirs = []
            files = []
            
            for name in unique_children:
                is_dir = any(path.startswith(f"{prefix}{name}/") for path in matching_files)
                if is_dir:
                    subdirs.append(name + "/")
                else:
                    files.append(name)
            
            lines = [f"## 文件夹: {folder or '.'}", f"子目录 ({len(subdirs)}):"]
            if subdirs:
                lines.extend([f"- {d}" for d in subdirs])
            else:
                lines.append("- (无)")
            
            lines.append(f"文件 ({len(files)}):")
            if files:
                lines.extend([f"- {f}" for f in files])
            else:
                lines.append("- (无)")
            
            output_chunks.append("\n".join(lines))
        
        return ToolResult(success=True, content="\n\n".join(output_chunks))
    
    def _read_file(self, file_paths: List[str]) -> ToolResult:
        """Read the contents of one or more files."""
        file_paths = [p for p in file_paths if isinstance(p, str) and p.strip()]
        
        if not file_paths:
            return ToolResult(
                success=False,
                content="",
                error="未提供文件路径。请在 file_paths 中提供一个或多个文件路径。"
            )
        
        files_content = []
        
        for file_path in file_paths:
            try:
                # Find matching file
                actual_path = file_path
                if file_path not in self.file_list:
                    matching = [f for f in self.file_list if file_path in f]
                    if matching:
                        actual_path = matching[0]
                    else:
                        files_content.append(f"未找到文件 '{file_path}'。")
                        continue
                
                # Read file content
                if self.repo_path:
                    absolute_path = self.repo_path / actual_path
                else:
                    absolute_path = Path(actual_path)
                
                content = absolute_path.read_text(encoding="utf-8", errors="ignore")
                if len(content) > 5000:
                    content = content[:5000] + "\n\n... [内容已截断] ..."
                
                files_content.append(f"## 文件完整内容: {actual_path}\n\n```\n{content}\n```")
            
            except Exception as e:
                files_content.append(f"读取文件 '{file_path}' 时出错: {str(e)}")
        
        if not files_content:
            return ToolResult(success=False, content="", error="未能读取任何请求的文件内容。")
        
        return ToolResult(success=True, content="\n\n".join(files_content))
    
    def _finalize(self, modules: List[Dict[str, Any]]) -> ToolResult:
        """Finalize the analysis and return the modules."""
        return ToolResult(
            success=True,
            content=json.dumps({"modules": modules}, ensure_ascii=False, indent=2)
        )
