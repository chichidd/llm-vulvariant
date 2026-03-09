"""Directory tree building and rendering utilities."""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional, Tuple


def build_path_tree(paths_with_values: List[Tuple[str, Any]]) -> Dict[str, Any]:
    """Build a nested tree structure from path/value pairs.

    Args:
        paths_with_values: ``[(path, value), ...]`` entries.

    Returns:
        Nested dictionary where leaf nodes store the provided value.
    """
    tree: Dict[str, Any] = {}
    for path, value in paths_with_values:
        parts = path.split('/')
        current = tree
        for part in parts[:-1]:
            if part not in current:
                current[part] = {}
            current = current[part]
        filename = parts[-1]
        current[filename] = value
    return tree


def render_tree(
    node: Dict[str, Any],
    prefix: str = "",
    value_formatter: Optional[Callable[[Any], str]] = None,
    max_depth: Optional[int] = None,
    current_depth: int = 0,
) -> List[str]:
    """Render a tree structure as ``tree``-style text output.

    Args:
        node: Tree node produced by :func:`build_path_tree`.
        prefix: Prefix used for nested indentation.
        value_formatter: Optional formatter for leaf values.
        max_depth: Optional depth limit where root depth is ``0``.
        current_depth: Internal recursion depth.

    Returns:
        Formatted output lines.
    """
    lines: List[str] = []
    if max_depth is not None and current_depth >= max_depth:
        return lines

    items = sorted(node.items())
    for i, (name, value) in enumerate(items):
        is_last_item = (i == len(items) - 1)
        connector = "└── " if is_last_item else "├── "

        if isinstance(value, dict):
            lines.append(prefix + connector + name + "/")
            extension = "    " if is_last_item else "│   "
            lines.extend(
                render_tree(
                    value,
                    prefix + extension,
                    value_formatter,
                    max_depth,
                    current_depth + 1,
                )
            )
        else:
            display_name = name
            if value_formatter and value is not None:
                display_name += f" ({value_formatter(value)})"
            lines.append(f"{prefix}{connector}{display_name}")

    return lines


def build_directory_structure_tree(file_list: List[str], max_depth: Optional[int] = None) -> str:
    """Build a compact directory tree from a file list.

    Args:
        file_list: Repository-relative file paths.
        max_depth: Optional rendering depth limit.

    Returns:
        Readable tree string with a short header.
    """
    if not file_list:
        return "Empty directory"

    paths_with_none = [(path, None) for path in file_list]
    tree = build_path_tree(paths_with_none)
    lines = render_tree(tree, max_depth=max_depth)

    header = f"Total files: {len(file_list)}\n"
    if max_depth:
        header += f"(Showing depth: {max_depth})\n"

    return header + "\n".join(lines)


def format_file_size(size_bytes: int) -> str:
    """Format a byte count using compact binary-friendly units.

    Args:
        size_bytes: File size in bytes.

    Returns:
        Human-readable file size string.
    """
    if size_bytes < 1024:
        return f"{size_bytes}B"
    if size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f}KB"
    return f"{size_bytes / (1024 * 1024):.1f}MB"
