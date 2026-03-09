"""Text processing utilities."""

from __future__ import annotations

import re


def extract_readable_text_from_markdown(markdown_content: str) -> str:
    """Extract human-readable text from Markdown content.

    Args:
        markdown_content: Raw Markdown content.

    Returns:
        Plain text with presentation-oriented markup removed.
    """
    if not markdown_content:
        return ""

    text = markdown_content

    # Apply broad markup stripping before lighter inline cleanups so visible
    # text survives even when badges or HTML wrappers are present.

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

    return text.strip()


def clean_readme_for_llm(readme_content: str, max_length: int = 60000) -> str:
    """Prepare README content for LLM prompts.

    Args:
        readme_content: Raw README content.
        max_length: Maximum character budget after cleaning.

    Returns:
        Cleaned and truncated content.
    """
    if not readme_content:
        return ""

    cleaned = extract_readable_text_from_markdown(readme_content)
    if max_length > 0 and len(cleaned) > max_length:
        # Preserve an explicit truncation marker so downstream prompts know the
        # README was shortened intentionally rather than cut off by I/O issues.
        suffix = "\n\n...(truncated)"
        cutoff = max(0, max_length - len(suffix))
        return cleaned[:cutoff] + suffix
    return cleaned
