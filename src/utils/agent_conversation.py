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


DEFAULT_COMPRESSION_PROMPT = """You are a professional conversation analysis and compression expert. Please analyze and compress the assistant's scan logs from the following vulnerability scanning process, extracting all key information.

**Compression requirements (information must be complete):**

1. **Reasoning process**: Summarize the analysis approach and reasoning chain
     - Why these files/modules were checked
     - What clues were found
     - What conclusions were reached
     - Which possibilities were ruled out and why

2. **Vulnerability report**: If vulnerabilities were reported, preserve complete information
     - File path, function name, line numbers
     - Vulnerability type, description, evidence
     - Similarity analysis, confidence, attack scenario

3. **Failed attempts**: Record explorations that did not succeed
     - Which paths were checked but no issues were found
     - Errors or limitations encountered

4. **Next-step plan**: If future analysis directions were mentioned
     - Modules that still need to be checked
     - Hypotheses to be validated

**Key principles:**
- Do not lose any information that could affect follow-up analysis
- Preserve enough context so later iterations can understand what was done

**Output format (JSON; ensure the object is wrapped by ```json and ```):**
```json
{
    "iteration_number": <iteration_number>,
    "summary": "<one-sentence summary of what this iteration did>",
    "reasoning": {
        "motivation": "<why these checks were performed>",
        "analysis": "<analysis approach and logic>",
        "conclusions": ["<conclusion_1>", "<conclusion_2>"]
    },
    "vulnerabilities_reported": [
        {<full vulnerability report details>}
    ],
    "failed_attempts": [
        {
            "what": "<what was tried>",
            "why_failed": "<why it failed or why no issue was found>"
        }
    ],
    "next_steps": ["<plan_1>", "<plan_2>"],
    "modules_checked": ["<list_of_checked_modules_or_files>"],
    "modules_pending": ["<list_of_pending_modules>" ]
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
