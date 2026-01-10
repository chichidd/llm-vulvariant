"""Shared helpers for agent-style conversations and compression."""

from __future__ import annotations

import copy
import json
import re
import time
from typing import Any, Dict, List, Optional


def clear_reasoning_content(messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Drop provider-specific reasoning fields so histories stay serializable."""
    cleaned: List[Dict[str, Any]] = []
    for msg in messages:
        if hasattr(msg, "reasoning_content"):
            clone = copy.copy(msg)
            clone.reasoning_content = None
            cleaned.append(clone)
        elif isinstance(msg, dict):
            cleaned.append({k: v for k, v in msg.items() if k != "reasoning_content"})
        else:
            cleaned.append(msg)
    return cleaned


def make_serializable(obj: Any):
    """Recursively convert complex objects into JSON-serializable structures."""
    if obj is None:
        return None
    if isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, dict):
        return {k: make_serializable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [make_serializable(item) for item in obj]
    if hasattr(obj, "__dict__"):
        return make_serializable(obj.__dict__)
    if hasattr(obj, "model_dump"):
        try:
            return obj.model_dump()
        except Exception:  # pylint: disable=broad-except
            pass
    if hasattr(obj, "dict") and callable(getattr(obj, "dict")):
        try:
            return make_serializable(obj.dict())
        except Exception:  # pylint: disable=broad-except
            pass
    try:
        return str(obj)
    except Exception:  # pylint: disable=broad-except
        return f"<non-serializable: {type(obj).__name__}>"


DEFAULT_COMPRESSION_PROMPT = """你是一个专业的对话分析和压缩专家。请分析并压缩以下漏洞扫描过程中assistant的扫描记录，提取所有关键信息。

**压缩要求（信息必须完整）：**

1. **推理过程**：总结分析思路和推理链条
   - 为什么检查这些文件/模块
   - 发现了什么线索
   - 得出了什么结论
   - 排除了哪些可能性及原因

2. **漏洞报告**：如果报告了漏洞，保留完整信息
   - 文件路径、函数名、行号
   - 漏洞类型、描述、证据
   - 相似性分析、置信度、攻击场景

3. **失败尝试**：记录未成功的探索
   - 检查了哪些路径但未发现问题
   - 遇到的错误或限制

4. **下一步计划**：如果有提到后续分析方向
   - 还需要检查的模块
   - 待验证的假设

**关键原则：**
- 不要丢失任何可能影响后续分析的信息
- 保留足够的上下文，让后续iteration能理解之前做了什么

**输出格式（JSON格式，确保大括号用```json和```包裹）：**
```json
{
  "iteration_number": <iteration编号>,
  "summary": "<一句话总结这个iteration做了什么>",
  "reasoning": {
    "motivation": "<为什么进行这些检查>",
    "analysis": "<分析思路和逻辑>",
    "conclusions": ["<结论1>", "<结论2>"]
  },
  "vulnerabilities_reported": [
    {<完整的漏洞报告信息>}
  ],
  "failed_attempts": [
    {
      "what": "<尝试了什么>",
      "why_failed": "<为什么失败或未发现问题>"
    }
  ],
  "next_steps": ["<计划1>", "<计划2>"],
  "modules_checked": ["<已检查的模块/文件列表>"],
  "modules_pending": ["<待检查的模块列表>"]
}
```

现在请压缩以下对话记录：
"""


def compress_iteration_conversation(
    llm_client: Any,
    iteration: int,
    iteration_history: List[Dict[str, Any]],
    verbose: bool = False,
    compression_prompt: Optional[str] = None,
    system_prompt: str = "You are a helpful AI assistant specialized in code security analysis.",
) -> Dict[str, Any]:
    """Summarize a single iteration to keep history bounded for long runs.

    A custom compression prompt can be provided to adapt to different agents.
    """

    prompt = compression_prompt or DEFAULT_COMPRESSION_PROMPT

    conversation_text = json.dumps(make_serializable(iteration_history), indent=2, ensure_ascii=False)
    full_prompt = prompt + "\n\n" + conversation_text
    compressed_data: Dict[str, Any] = {}
    try:
        response = llm_client.chat(
            [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": full_prompt},
            ]
        )
        content = response.content if hasattr(response, "content") else str(response)
        json_match = re.search(r"```(?:json)?\s*({.*?})\s*```", content, re.DOTALL)
        if json_match:
            compressed_data["content"] = json.loads(json_match.group(1))
        else:
            compressed_data["content"] = json.loads(content)
        compressed_data["iteration_number"] = iteration
        compressed_data["compression_timestamp"] = time.strftime("%Y-%m-%d %H:%M:%S")
        return compressed_data
    except Exception as exc:  # pylint: disable=broad-except
        if verbose:
            print(f"Failed to compress iteration {iteration}: {exc}")
        return {
            "iteration_number": iteration,
            "error": str(exc),
            "summary": "Compression failed",
            "raw_message_count": len(iteration_history),
        }
