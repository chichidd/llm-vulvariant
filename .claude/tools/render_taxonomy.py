from __future__ import annotations

from typing import Any


def taxonomy_to_markdown(taxonomy: dict) -> str:
    """Render a nested dict/list taxonomy into a Markdown bullet tree."""
    lines: list[str] = []

    def rec(node: Any, indent: int) -> None:
        pad = "  " * indent
        if isinstance(node, dict):
            for k, v in node.items():
                lines.append(f"{pad}- {k}")
                rec(v, indent + 1)
        elif isinstance(node, list):
            for it in node:
                lines.append(f"{pad}- {it}")
        else:
            lines.append(f"{pad}- {node}")

    rec(taxonomy, 0)
    return "\n".join(lines)
