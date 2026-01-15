"""Text processing utilities."""

import re
from typing import Optional


def extract_readable_text_from_markdown(markdown_content: str) -> str:
    """
    Extract user-readable text from Markdown by removing badges, HTML tags, etc.

    Args:
        markdown_content: Raw Markdown content.

    Returns:
        Cleaned plain text.
    """
    if not markdown_content:
        return ""
    
    text = markdown_content
    
    # Remove HTML comments
    text = re.sub(r'<!--.*?-->', '', text, flags=re.DOTALL)
    
    # Remove HTML tags
    text = re.sub(r'<[^>]+>', '', text)
    
    # Remove image syntax ![alt](url)
    text = re.sub(r'!\[([^\]]*)\]\([^\)]+\)', r'\1', text)
    
    # Remove badges (shields.io, badges, etc.)
    text = re.sub(r'\[!\[.*?\]\(.*?\)\]\(.*?\)', '', text)
    
    # Keep link text but remove URL: [text](url) -> text
    text = re.sub(r'\[([^\]]+)\]\([^\)]+\)', r'\1', text)
    
    # Remove code-fence language tag but keep code content
    text = re.sub(r'^```\w*\n', '```\n', text, flags=re.MULTILINE)
    
    # Simplify heading markers (### -> )
    text = re.sub(r'^#+\s+', '', text, flags=re.MULTILINE)
    
    # Remove bold/italic markers
    text = re.sub(r'\*\*([^\*]+)\*\*', r'\1', text)  # **bold**
    text = re.sub(r'\*([^\*]+)\*', r'\1', text)  # *italic*
    text = re.sub(r'__([^_]+)__', r'\1', text)  # __bold__
    text = re.sub(r'_([^_]+)_', r'\1', text)  # _italic_
    
    # Remove table separators
    text = re.sub(r'^\|?[\s\-\|:]+\|?\s*$', '', text, flags=re.MULTILINE)
    
    # Remove blockquote markers (>)
    text = re.sub(r'^>\s+', '', text, flags=re.MULTILINE)
    
    # Remove horizontal rules
    text = re.sub(r'^[\-\*_]{3,}\s*$', '', text, flags=re.MULTILINE)
    
    # Collapse excessive blank lines (>= 3 blank lines -> 2)
    text = re.sub(r'\n{4,}', '\n\n', text)
    
    # Trim leading/trailing whitespace
    text = text.strip()
    
    return text


def truncate_text(text: str, max_length: int = 60000, suffix: str = "\n\n...(truncated)") -> str:
    """
    Truncate text to a maximum length.

    Args:
        text: Raw text.
        max_length: Maximum length.
        suffix: Suffix appended after truncation.

    Returns:
        Truncated text.
    """
    if not text or len(text) <= max_length:
        return text
    
    return text[:max_length - len(suffix)] + suffix


def clean_readme_for_llm(readme_content: str, max_length: int = 60000) -> str:
    """
    Clean README content for LLM usage by removing noise and truncating.

    Args:
        readme_content: Raw README content.
        max_length: Maximum length.

    Returns:
        Cleaned and truncated content.
    """
    if not readme_content:
        return ""
    
    # Extract readable text
    cleaned = extract_readable_text_from_markdown(readme_content)
    
    # Truncate to a reasonable length
    return truncate_text(cleaned, max_length)
