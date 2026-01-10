"""文本处理工具函数"""

import re
from typing import Optional


def extract_readable_text_from_markdown(markdown_content: str) -> str:
    """
    从 Markdown 内容中提取用户可读的文本，去除图标链接、HTML标签等
    
    Args:
        markdown_content: 原始 Markdown 内容
        
    Returns:
        清理后的纯文本
    """
    if not markdown_content:
        return ""
    
    text = markdown_content
    
    # 移除 HTML 注释
    text = re.sub(r'<!--.*?-->', '', text, flags=re.DOTALL)
    
    # 移除 HTML 标签
    text = re.sub(r'<[^>]+>', '', text)
    
    # 移除图片语法 ![alt](url)
    text = re.sub(r'!\[([^\]]*)\]\([^\)]+\)', r'\1', text)
    
    # 移除徽章 (shields.io, badges 等)
    text = re.sub(r'\[!\[.*?\]\(.*?\)\]\(.*?\)', '', text)
    
    # 保留链接文本但移除URL: [text](url) -> text
    text = re.sub(r'\[([^\]]+)\]\([^\)]+\)', r'\1', text)
    
    # 移除内联代码块的反引号（保留内容）
    # 但保留代码块标记让下面处理
    
    # 移除代码块语言标识但保留代码内容
    text = re.sub(r'^```\w*\n', '```\n', text, flags=re.MULTILINE)
    
    # 简化标题符号 (### -> )
    text = re.sub(r'^#+\s+', '', text, flags=re.MULTILINE)
    
    # 移除粗体和斜体标记
    text = re.sub(r'\*\*([^\*]+)\*\*', r'\1', text)  # **bold**
    text = re.sub(r'\*([^\*]+)\*', r'\1', text)  # *italic*
    text = re.sub(r'__([^_]+)__', r'\1', text)  # __bold__
    text = re.sub(r'_([^_]+)_', r'\1', text)  # _italic_
    
    # 移除表格分隔符
    text = re.sub(r'^\|?[\s\-\|:]+\|?\s*$', '', text, flags=re.MULTILINE)
    
    # 移除引用标记 (>)
    text = re.sub(r'^>\s+', '', text, flags=re.MULTILINE)
    
    # 移除水平线
    text = re.sub(r'^[\-\*_]{3,}\s*$', '', text, flags=re.MULTILINE)
    
    # 移除多余的空行（3个以上空行压缩为2个）
    text = re.sub(r'\n{4,}', '\n\n', text)
    
    # 移除首尾空白
    text = text.strip()
    
    return text


def truncate_text(text: str, max_length: int = 60000, suffix: str = "\n\n...(truncated)") -> str:
    """
    截断文本到指定长度
    
    Args:
        text: 原始文本
        max_length: 最大长度
        suffix: 截断后添加的后缀
        
    Returns:
        截断后的文本
    """
    if not text or len(text) <= max_length:
        return text
    
    return text[:max_length - len(suffix)] + suffix


def clean_readme_for_llm(readme_content: str, max_length: int = 60000) -> str:
    """
    清理 README 内容供 LLM 使用，移除噪音并截断
    
    Args:
        readme_content: 原始 README 内容
        max_length: 最大长度
        
    Returns:
        清理和截断后的内容
    """
    if not readme_content:
        return ""
    
    # 提取可读文本
    cleaned = extract_readable_text_from_markdown(readme_content)
    
    # 截断到合适长度
    return truncate_text(cleaned, max_length)
