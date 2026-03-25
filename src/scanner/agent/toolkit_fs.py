"""File-system and source inspection helpers for the agent toolkit."""

from __future__ import annotations

import ast
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from utils.language import get_extensions
from utils.llm_utils import extract_function_snippet_based_on_name_with_ast
from utils.tree_utils import build_path_tree, format_file_size, render_tree

JS_IMPORT_EXTENSIONS = set(get_extensions("javascript"))


@dataclass
class ToolResult:
    success: bool
    content: str
    error: Optional[str] = None
    truncated: bool = False


class ToolkitFSMixin:
    """File-system and source-inspection helpers mixed into ``AgenticToolkit``."""

    @staticmethod
    def _format_size(size_bytes: int) -> str:
        """Format one file size for tree rendering."""
        return format_file_size(size_bytes)

    @staticmethod
    def _build_path_tree(paths_with_values: List[Any]) -> Dict[str, Any]:
        """Build one tree structure from relative paths plus values."""
        return build_path_tree(paths_with_values)

    @staticmethod
    def _render_tree(
        node: Dict[str, Any],
        prefix: str = "",
        value_formatter: Optional[Any] = None,
    ) -> List[str]:
        """Render one path tree into display lines."""
        return render_tree(node, prefix, value_formatter)

    def _is_source_file(self, path: Path) -> bool:
        """Check if *path* is a source file of any configured language."""
        return path.suffix.lower() in self._source_extensions

    def _iter_source_files(self, root: Path, recursive: bool = True) -> Iterator[Path]:
        """Yield source files under *root* matching configured languages."""
        ignored_dirs = {
            ".git",
            "node_modules",
            "__pycache__",
            "build",
            "dist",
            ".tox",
            "venv",
            ".venv",
            "vendor",
            "third_party",
        }
        if recursive:
            for dirpath, dirnames, filenames in os.walk(root):
                dirnames[:] = [dirname for dirname in dirnames if dirname not in ignored_dirs]
                for filename in filenames:
                    file_path = Path(dirpath) / filename
                    if self._is_source_file(file_path):
                        yield file_path
            return
        for file_path in root.iterdir():
            if file_path.is_file() and self._is_source_file(file_path):
                yield file_path

    def _read_file(
        self,
        file_path: str,
        start_line: int = None,
        end_line: int = None,
    ) -> ToolResult:
        """Read file contents with optional line slicing."""
        full_path, error = self._resolve_repo_path(file_path, kind="file")
        if error:
            return ToolResult(success=False, content="", error=error)
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
            truncated = len(content) > 5000
            if truncated:
                content = (
                    content[:5000]
                    + "\n... [truncated, use start_line/end_line to read specific sections]"
                )
            return ToolResult(success=True, content=content, truncated=truncated)
        except Exception as exc:  # pylint: disable=broad-except
            return ToolResult(success=False, content="", error=str(exc))

    def _search_in_file(self, file_path: str, pattern: str, context_lines: int = 2) -> ToolResult:
        """Search one file and return matching lines with context."""
        full_path, error = self._resolve_repo_path(file_path, kind="file")
        if error:
            return ToolResult(success=False, content="", error=error)
        if not full_path.exists():
            return ToolResult(success=False, content="", error=f"File not found: {file_path}")
        try:
            content = full_path.read_text(encoding="utf-8", errors="ignore")
            lines = content.split("\n")
            regex = re.compile(pattern, re.IGNORECASE)
            matches = []
            for index, line in enumerate(lines):
                if regex.search(line):
                    start = max(0, index - context_lines)
                    end = min(len(lines), index + context_lines + 1)
                    context = []
                    for context_index in range(start, end):
                        prefix = ">>> " if context_index == index else "    "
                        context.append(f"{prefix}{context_index + 1}: {lines[context_index]}")
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
        """Search repository source files under one folder."""
        full_path, error = self._resolve_repo_path(folder_path, kind="folder")
        if error:
            return ToolResult(success=False, content="", error=error)
        if not full_path.exists():
            return ToolResult(success=False, content="", error=f"Folder not found: {folder_path}")
        try:
            regex = re.compile(pattern, re.IGNORECASE)
            file_results: Dict[str, List[Any]] = {}
            total_matches = 0
            for source_file in self._iter_source_files(full_path):
                if total_matches >= max_results:
                    break
                try:
                    content = source_file.read_text(encoding="utf-8", errors="ignore")
                    lines = content.split("\n")
                    for index, line in enumerate(lines):
                        if regex.search(line):
                            rel_path = str(source_file.relative_to(self.repo_path))
                            file_results.setdefault(rel_path, []).append((index + 1, line.strip()))
                            total_matches += 1
                            if total_matches >= max_results:
                                break
                except Exception:  # pylint: disable=broad-except
                    continue
            if not file_results:
                return ToolResult(success=True, content=f"No matches found for pattern: {pattern}")
            result_lines = [f"Found {total_matches} matches in {len(file_results)} files:\n"]
            for matched_file in sorted(file_results.keys()):
                result_lines.append(f"\n{matched_file}:")
                for line_num, line_content in file_results[matched_file][:10]:
                    result_lines.append(f"  L{line_num}: {line_content}")
                if len(file_results[matched_file]) > 10:
                    result_lines.append(
                        f"  ... and {len(file_results[matched_file]) - 10} more matches in this file"
                    )
            return ToolResult(success=True, content="\n".join(result_lines))
        except Exception as exc:  # pylint: disable=broad-except
            return ToolResult(success=False, content="", error=str(exc))

    def _list_files_in_folder(self, folder_path: str, recursive: bool = True) -> ToolResult:
        """List source files under one folder."""
        full_path, error = self._resolve_repo_path(folder_path, kind="folder")
        if error:
            return ToolResult(success=False, content="", error=error)
        if not full_path.exists():
            return ToolResult(success=False, content="", error=f"Folder not found: {folder_path}")
        try:
            file_info: List[Any] = []
            total_size = 0
            for source_file in self._iter_source_files(full_path, recursive=recursive):
                rel_path = str(source_file.relative_to(self.repo_path))
                size = source_file.stat().st_size
                total_size += size
                file_info.append((rel_path, size))
            if not file_info:
                return ToolResult(success=True, content="No source files found")
            tree = self._build_path_tree(file_info)
            tree_lines = self._render_tree(tree, value_formatter=self._format_size)
            result = (
                f"Found {len(file_info)} source files (total: {self._format_size(total_size)}):\n\n"
                + "\n".join(tree_lines)
            )
            return ToolResult(success=True, content=result)
        except Exception as exc:  # pylint: disable=broad-except
            return ToolResult(success=False, content="", error=str(exc))

    def _get_function_code(self, file_path: str, function_name: str) -> ToolResult:
        """Extract one function or class definition from a source file."""
        full_path, error = self._resolve_repo_path(file_path, kind="file")
        if error:
            return ToolResult(success=False, content="", error=error)
        if not full_path.exists():
            return ToolResult(success=False, content="", error=f"File not found: {file_path}")
        try:
            content = full_path.read_text(encoding="utf-8", errors="ignore")
            lines = content.split("\n")

            if full_path.suffix == ".py":
                tree = ast.parse(content)
                matches: List[tuple[str, Any]] = []

                class _SymbolVisitor(ast.NodeVisitor):
                    def __init__(self) -> None:
                        self.scope: List[str] = []

                    def visit_ClassDef(self, node: ast.ClassDef) -> None:
                        qualified_name = ".".join(self.scope + [node.name])
                        if node.name == function_name or qualified_name == function_name:
                            matches.append((qualified_name, node))
                        self.scope.append(node.name)
                        self.generic_visit(node)
                        self.scope.pop()

                    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
                        qualified_name = ".".join(self.scope + [node.name])
                        if node.name == function_name or qualified_name == function_name:
                            matches.append((qualified_name, node))
                        self.scope.append(node.name)
                        self.generic_visit(node)
                        self.scope.pop()

                    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
                        qualified_name = ".".join(self.scope + [node.name])
                        if node.name == function_name or qualified_name == function_name:
                            matches.append((qualified_name, node))
                        self.scope.append(node.name)
                        self.generic_visit(node)
                        self.scope.pop()

                _SymbolVisitor().visit(tree)
                if len(matches) > 1:
                    rendered_matches = ", ".join(
                        f"{qualified_name} (line {node.lineno})"
                        for qualified_name, node in matches[:10]
                    )
                    return ToolResult(
                        success=False,
                        content="",
                        error=(
                            f"Ambiguous Python symbol '{function_name}'. "
                            f"Use a qualified name. Matches: {rendered_matches}"
                        ),
                    )
                if matches:
                    _, node = matches[0]
                    start_line = node.lineno - 1
                    end_line = node.end_lineno if hasattr(node, "end_lineno") else start_line + 50
                    function_lines = lines[start_line:end_line]
                    numbered = [f"{start_line + i + 1}: {line}" for i, line in enumerate(function_lines)]
                    return ToolResult(success=True, content="\n".join(numbered))
                return ToolResult(
                    success=False,
                    content="",
                    error=f"Function/class not found: {function_name}",
                )

            snippet = extract_function_snippet_based_on_name_with_ast(
                content,
                function_name,
                with_line_numbers=True,
                line_number_format="standard",
            )
            if not snippet:
                return ToolResult(
                    success=False,
                    content="",
                    error=f"Function/class not found: {function_name}",
                )
            return ToolResult(success=True, content=snippet)
        except Exception as exc:  # pylint: disable=broad-except
            return ToolResult(success=False, content="", error=str(exc))

    def _get_imports(self, file_path: str) -> ToolResult:
        """Extract import statements from one source file."""
        full_path, error = self._resolve_repo_path(file_path, kind="file")
        if error:
            return ToolResult(success=False, content="", error=error)
        if not full_path.exists():
            return ToolResult(success=False, content="", error=f"File not found: {file_path}")
        try:
            content = full_path.read_text(encoding="utf-8", errors="ignore")
            suffix = full_path.suffix.lower()

            imports: List[str] = []

            if suffix == ".py":
                tree = ast.parse(content)
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            imports.append(
                                f"import {alias.name}" + (f" as {alias.asname}" if alias.asname else "")
                            )
                    elif isinstance(node, ast.ImportFrom):
                        module = node.module or ""
                        names = ", ".join(
                            alias.name + (f" as {alias.asname}" if alias.asname else "")
                            for alias in node.names
                        )
                        imports.append(f"from {module} import {names}")
            elif suffix in {".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".hh"}:
                for line in content.splitlines():
                    stripped = line.strip()
                    if stripped.startswith("#include"):
                        imports.append(stripped)
            elif suffix == ".go":
                imports.extend(
                    re.findall(
                        r'^\s*import\s+(?:".+?"|\((?:[^)]+)\))',
                        content,
                        re.MULTILINE | re.DOTALL,
                    )
                )
            elif suffix == ".java":
                for line in content.splitlines():
                    stripped = line.strip()
                    if stripped.startswith("import "):
                        imports.append(stripped.rstrip(";"))
            elif suffix in JS_IMPORT_EXTENSIONS:
                for line in content.splitlines():
                    stripped = line.strip()
                    if self._is_js_import_statement(stripped):
                        imports.append(stripped.rstrip(";"))
            elif suffix == ".rs":
                for line in content.splitlines():
                    stripped = line.strip()
                    if stripped.startswith("use ") or stripped.startswith("extern crate "):
                        imports.append(stripped.rstrip(";"))
            elif suffix == ".rb":
                for line in content.splitlines():
                    stripped = line.strip()
                    if stripped.startswith("require ") or stripped.startswith("require_relative "):
                        imports.append(stripped)
            else:
                for line in content.splitlines():
                    stripped = line.strip()
                    if re.match(r"^(import |from |#include |require |use |extern crate )", stripped):
                        imports.append(stripped)

            if not imports:
                return ToolResult(success=True, content="No imports found")
            return ToolResult(success=True, content="\n".join(imports))
        except Exception as exc:  # pylint: disable=broad-except
            return ToolResult(success=False, content="", error=str(exc))

    @staticmethod
    def _is_js_import_statement(line: str) -> bool:
        """Return whether *line* looks like a JS/TS import statement."""
        if not line:
            return False
        return bool(
            re.match(r"^import\b", line)
            or re.match(r"^export\b.*\bfrom\b", line)
            or re.match(r"^(?:const|let|var)\b.*\b(?:require|import)\s*\(", line)
        )
