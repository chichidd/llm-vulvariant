"""目录树构建和渲染工具"""

from typing import Dict, List, Tuple, Any, Optional, Callable
from pathlib import Path


def build_path_tree(paths_with_values: List[Tuple[str, Any]]) -> Dict:
    """
    从路径列表构建树形结构（去重）
    
    Args:
        paths_with_values: [(path, value), ...] 其中 value 可以是 size、None 等
        
    Returns:
        嵌套字典，叶子节点存储 value
        
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
        # 最后一个部分（文件名或最后的目录）
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
    递归渲染树形结构
    
    Args:
        node: 树形字典
        prefix: 当前行前缀
        value_formatter: 值格式化函数，接收 value 返回字符串，None 表示不显示
        max_depth: 最大深度限制，None 表示无限制
        current_depth: 当前深度（内部使用）
        
    Returns:
        格式化的行列表
    """
    lines = []
    
    # 检查深度限制
    if max_depth is not None and current_depth >= max_depth:
        return lines
    
    items = sorted(node.items())
    for i, (name, value) in enumerate(items):
        is_last_item = (i == len(items) - 1)
        connector = "└── " if is_last_item else "├── "
        
        if isinstance(value, dict):
            # 目录
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
            # 文件或叶子节点
            display_name = name
            if value_formatter and value is not None:
                display_name += f" ({value_formatter(value)})"
            lines.append(f"{prefix}{connector}{display_name}")
    
    return lines


def build_directory_structure_tree(file_list: List[str], max_depth: Optional[int] = None) -> str:
    """
    根据文件列表构建压缩的目录结构树（去重复路径）
    
    Args:
        file_list: 文件路径列表
        max_depth: 最大显示深度，None 表示无限制
        
    Returns:
        格式化的树形结构字符串
    """
    if not file_list:
        return "Empty directory"
    
    # 构建路径树（value 设为 None）
    paths_with_none = [(path, None) for path in file_list]
    tree = build_path_tree(paths_with_none)
    
    # 渲染树形结构
    lines = render_tree(tree, max_depth=max_depth)
    
    # 添加统计信息
    header = f"Total files: {len(file_list)}\n"
    if max_depth:
        header += f"(Showing depth: {max_depth})\n"
    
    return header + "\n".join(lines)


def format_file_size(size_bytes: int) -> str:
    """格式化文件大小"""
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
    根据文件路径和大小构建目录结构树
    
    Args:
        paths_with_sizes: [(path, size_in_bytes), ...]
        max_depth: 最大显示深度
        
    Returns:
        格式化的树形结构字符串（带文件大小）
    """
    if not paths_with_sizes:
        return "Empty directory"
    
    # 构建路径树
    tree = build_path_tree(paths_with_sizes)
    
    # 渲染树形结构（带文件大小格式化）
    lines = render_tree(tree, value_formatter=format_file_size, max_depth=max_depth)
    
    # 添加统计信息
    total_size = sum(size for _, size in paths_with_sizes)
    header = f"Total files: {len(paths_with_sizes)} ({format_file_size(total_size)})\n"
    if max_depth:
        header += f"(Showing depth: {max_depth})\n"
    
    return header + "\n".join(lines)
