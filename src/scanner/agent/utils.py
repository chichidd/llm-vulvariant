"""Shared helpers for agent-style conversations and compression."""

from __future__ import annotations

import copy
import json
import re
import time
from typing import Any, Dict, List, Optional

from utils.logger import get_logger
from utils.llm_utils import extract_json_from_text

logger = get_logger(__name__)


def _is_compression_payload(payload: Dict[str, Any]) -> bool:
    """Return whether a JSON object matches the iteration-compression schema."""
    summary = payload.get("summary")
    if not isinstance(summary, str) or not summary.strip():
        return False
    if "reasoning" in payload and not isinstance(payload["reasoning"], dict):
        return False
    if "failed_attempts" in payload and not isinstance(payload["failed_attempts"], list):
        return False
    if "next_step_insights" in payload and not isinstance(payload["next_step_insights"], list):
        return False
    if "next_steps" in payload and not isinstance(payload["next_steps"], list):
        return False
    if _contains_placeholder_values(payload):
        return False
    if not _has_meaningful_compression_context(payload):
        return False
    return True


def _contains_placeholder_values(payload: Any) -> bool:
    """Return whether the payload still contains prompt placeholder markers."""
    if isinstance(payload, str):
        return re.fullmatch(r"<[^>\n]+>", payload.strip()) is not None
    if isinstance(payload, dict):
        return any(_contains_placeholder_values(value) for value in payload.values())
    if isinstance(payload, list):
        return any(_contains_placeholder_values(value) for value in payload)
    return False


def _has_meaningful_compression_context(payload: Dict[str, Any]) -> bool:
    """Require real reasoning context so summary-only echoes are rejected."""
    reasoning = payload.get("reasoning")
    if isinstance(reasoning, dict):
        motivation = reasoning.get("motivation")
        analysis = reasoning.get("analysis")
        conclusions = reasoning.get("conclusions")
        if isinstance(motivation, str) and motivation.strip():
            return True
        if isinstance(analysis, str) and analysis.strip():
            return True
        if isinstance(conclusions, str) and conclusions.strip():
            return True
        if isinstance(conclusions, list) and any(
            isinstance(item, str) and item.strip() for item in conclusions
        ):
            return True

    failed_attempts = payload.get("failed_attempts")
    if isinstance(failed_attempts, list):
        for attempt in failed_attempts:
            if isinstance(attempt, dict):
                what = attempt.get("what")
                why_failed = attempt.get("why_failed")
                if isinstance(what, str) and what.strip():
                    return True
                if isinstance(why_failed, str) and why_failed.strip():
                    return True
            elif isinstance(attempt, str) and attempt.strip():
                return True

    for key in ("next_step_insights", "next_steps"):
        values = payload.get(key)
        if isinstance(values, list) and any(
            isinstance(item, str) and item.strip() for item in values
        ):
            return True
    return False


def _extract_compression_payload(response_text: str) -> Optional[Dict[str, Any]]:
    """Extract the last valid compression payload from model output."""
    return extract_json_from_text(
        response_text,
        validator=_is_compression_payload,
        prefer_last=True,
    )


def _to_dict(obj: Any) -> Dict[str, Any]:
    """Best-effort conversion of dataclass-like objects into dictionaries."""
    if hasattr(obj, "to_dict"):
        return obj.to_dict()
    if isinstance(obj, dict):
        return obj
    return {}


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


def make_serializable(obj: Any) -> Any:
    """Recursively convert complex objects into JSON-serializable structures.

    Args:
        obj: Arbitrary Python object.

    Returns:
        Primitive, mapping, or list structures that ``json.dumps`` can handle.
    """
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
            pass  # Try next method
    if hasattr(obj, "dict") and callable(getattr(obj, "dict")):
        try:
            return make_serializable(obj.dict())
        except Exception:  # pylint: disable=broad-except
            pass  # Try next method
    try:
        return str(obj)
    except Exception:  # pylint: disable=broad-except
        return f"<non-serializable: {type(obj).__name__}>"


DEFAULT_COMPRESSION_PROMPT = """You are a professional conversation analysis and compression expert. Please analyze and compress the assistant's scan logs from the following vulnerability scanning process, extracting key REASONING information only.

**Important**: Do NOT include information about:
- Which files/modules were checked (this is tracked separately)
- Which files/modules are pending (this is tracked separately)
- Reported vulnerability details (this is tracked separately)

**Focus on extracting REASONING and INSIGHTS that are NOT tracked elsewhere:**

1. **Reasoning process**: Summarize the analysis approach and reasoning chain
     - Why these files/modules were checked (the motivation/logic)
     - What clues or patterns were found
     - What conclusions were reached about the code
     - Which possibilities were ruled out and why

2. **Failed attempts**: Record explorations that did not succeed
     - What was tried but no vulnerability was found
     - Why it was a false positive or dead end
     - Lessons learned for future analysis

3. **Next-step insights**: Hypotheses and strategies to validate
     - Specific patterns or APIs to look for
     - Suspected vulnerable code paths not yet confirmed
     - Analysis strategies for remaining modules

**Key principles:**
- Only include information that helps understand the REASONING, not raw facts
- Be concise - avoid redundancy with tracked progress data

**Output format (JSON; ensure the object is wrapped by ```json and ```):**
```json
{
    "iteration_number": <iteration_number>,
    "summary": "<one-sentence summary of what this iteration did>",
    "reasoning": {
        "motivation": "<why these checks were performed>",
        "analysis": "<key insights and analysis logic>",
        "conclusions": ["<conclusion_1>", "<conclusion_2>"]
    },
    "failed_attempts": [
        {
            "what": "<what was tried>",
            "why_failed": "<why it failed or why no issue was found>"
        }
    ],
    "next_step_insights": ["<hypothesis or strategy to validate>"]
}
```

Now please compress the following conversation log:
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

    Args:
        llm_client: Chat-capable LLM client.
        iteration: Current iteration number.
        iteration_history: Raw message history for the iteration.
        verbose: Whether to print compression failures.
        compression_prompt: Optional prompt override.
        system_prompt: System message used for the compression request.

    Returns:
        Compression result payload or a structured failure stub.
    """

    prompt = compression_prompt or DEFAULT_COMPRESSION_PROMPT

    # Normalize messages before serializing so provider-specific response
    # objects do not break JSON encoding or leak non-essential internals.
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
        parsed = _extract_compression_payload(content)
        if parsed is None:
            raise ValueError("No valid compression JSON object found in response")
        compressed_data["content"] = parsed
        compressed_data["iteration_number"] = iteration
        compressed_data["compression_timestamp"] = time.strftime("%Y-%m-%d %H:%M:%S")
        return compressed_data
    except Exception as exc:  # pylint: disable=broad-except
        if verbose:
            logger.warning(f"Failed to compress iteration {iteration}: {exc}")
        return {
            "iteration_number": iteration,
            "error": str(exc),
            "summary": "Compression failed",
            "raw_message_count": len(iteration_history),
        }
