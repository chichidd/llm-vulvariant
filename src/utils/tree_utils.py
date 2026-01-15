"""Directory tree building and rendering utilities."""

from typing import Dict, List, Tuple, Any, Optional, Callable
from pathlib import Path


def build_path_tree(paths_with_values: List[Tuple[str, Any]]) -> Dict:
    """
    Build a tree structure from a list of paths (deduplicated).

    Args:
        paths_with_values: [(path, value), ...] where value can be size, None, etc.

    Returns:
        A nested dict; leaf nodes store the provided value.
        
    Example:
        >>> paths = [("src/main.py", 100), ("src/utils/helper.py", 50)]
        >>> tree = build_path_tree(paths)
        >>> # {'src': {'main.py': 100, 'utils': {'helper.py': 50}}}
    """
    tree = {}
    for path, value in paths_with_values:
        parts = path.split('/')
        current = tree
        for i, part in enumerate(parts[:-1]):
            if part not in current:
                current[part] = {}
            current = current[part]
        # The last component (file name or final directory name).
        filename = parts[-1]
        current[filename] = value
    return tree


def render_tree(
    node: Dict, 
    prefix: str = "", 
    value_formatter: Optional[Callable[[Any], str]] = None,
    max_depth: Optional[int] = None,
    current_depth: int = 0
) -> List[str]:
    """
    Recursively render a tree structure.

    Args:
        node: Tree dict.
        prefix: Prefix for the current line.
        value_formatter: Formats values; returns a string. None means do not display.
        max_depth: Maximum depth limit; None means unlimited.
        current_depth: Current depth (internal).

    Returns:
        A list of formatted lines.
    """
    lines = []
    
    # Check depth limit.
    if max_depth is not None and current_depth >= max_depth:
        return lines
    
    items = sorted(node.items())
    for i, (name, value) in enumerate(items):
        is_last_item = (i == len(items) - 1)
        connector = "└── " if is_last_item else "├── "
        
        if isinstance(value, dict):
            # Directory
            lines.append(prefix + connector + name + "/")
            extension = "    " if is_last_item else "│   "
            lines.extend(
                render_tree(
                    value, 
                    prefix + extension,
                    value_formatter,
                    max_depth,
                    current_depth + 1
                )
            )
        else:
            # File or leaf node
            display_name = name
            if value_formatter and value is not None:
                display_name += f" ({value_formatter(value)})"
            lines.append(f"{prefix}{connector}{display_name}")
    
    return lines


def build_directory_structure_tree(file_list: List[str], max_depth: Optional[int] = None) -> str:
    """
    Build a compact directory tree from a file list (deduplicated).

    Args:
        file_list: List of file paths.
        max_depth: Maximum display depth; None means unlimited.

    Returns:
        A formatted tree string.
    """
    if not file_list:
        return "Empty directory"
    
    # Build a path tree (values set to None).
    paths_with_none = [(path, None) for path in file_list]
    tree = build_path_tree(paths_with_none)
    
    # Render the tree.
    lines = render_tree(tree, max_depth=max_depth)
    
    # Add stats.
    header = f"Total files: {len(file_list)}\n"
    if max_depth:
        header += f"(Showing depth: {max_depth})\n"
    
    return header + "\n".join(lines)


def format_file_size(size_bytes: int) -> str:
    """Format a file size."""
    if size_bytes < 1024:
        return f"{size_bytes}B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f}KB"
    else:
        return f"{size_bytes / (1024 * 1024):.1f}MB"


def build_directory_structure_with_sizes(
    paths_with_sizes: List[Tuple[str, int]], 
    max_depth: Optional[int] = None
) -> str:
    """
    Build a directory tree from file paths and sizes.

    Args:
        paths_with_sizes: [(path, size_in_bytes), ...]
        max_depth: Maximum display depth.

    Returns:
        A formatted tree string (with file sizes).
    """
    if not paths_with_sizes:
        return "Empty directory"
    
    # Build the path tree.
    tree = build_path_tree(paths_with_sizes)
    
    # Render the tree (format file sizes).
    lines = render_tree(tree, value_formatter=format_file_size, max_depth=max_depth)
    
    # Add stats.
    total_size = sum(size for _, size in paths_with_sizes)
    header = f"Total files: {len(paths_with_sizes)} ({format_file_size(total_size)})\n"
    if max_depth:
        header += f"(Showing depth: {max_depth})\n"
    
    return header + "\n".join(lines)
