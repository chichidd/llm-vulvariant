"""Utilities for LLM chat completion usage summaries.

This module hosts the normalized fields for a single completion usage payload.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from utils.number_utils import to_int


def _usage_get(value: Any, key: str) -> Any:
    if value is None:
        return None
    if isinstance(value, dict):
        return value.get(key)
    return getattr(value, key, None)


def _first_present(*values: Any) -> Any:
    for value in values:
        if value not in (None, ""):
            return value
    return None


def build_empty_llm_usage_summary(
    *,
    requested_model: Optional[str] = None,
    provider: Optional[str] = None,
    is_error: bool = False,
) -> Dict[str, Any]:
    """Create a normalized empty usage summary for LLM-client responses."""
    available_models = [requested_model] if requested_model else []
    selection_reason = "requested_model" if requested_model else None
    return {
        "source": "llm_client",
        "provider": provider,
        "requested_model": requested_model,
        "preferred_model_hint": None,
        "selected_model": requested_model,
        "selected_model_found": requested_model is not None,
        "selected_model_reason": selection_reason,
        "available_models": available_models,
        "models_usage": {},
        "session_usage": None,
        "selected_model_usage": None,
        "top_level_usage": None,
        "response_id": None,
        "service_tier": None,
        "total_cost_usd": 0.0,
        "is_error": is_error,
        "subtype": None,
        "sessions_total": 0,
        "turns_total": 0,
        "calls_total": 0,
    }


def summarize_chat_completion_usage(
    response: Any,
    *,
    requested_model: Optional[str] = None,
    provider: Optional[str] = None,
) -> Dict[str, Any]:
    """Build a normalized usage summary from OpenAI/Dsocr-style responses."""
    summary = build_empty_llm_usage_summary(
        requested_model=requested_model,
        provider=provider,
    )
    if response is None:
        return summary

    usage = _usage_get(response, "usage")
    prompt_details = _usage_get(usage, "prompt_tokens_details")
    completion_details = _usage_get(usage, "completion_tokens_details")

    input_tokens = to_int(
        _usage_get(usage, "prompt_tokens") or _usage_get(usage, "input_tokens")
    )
    output_tokens = to_int(
        _usage_get(usage, "completion_tokens") or _usage_get(usage, "output_tokens")
    )
    cache_read_input_tokens = to_int(
        _usage_get(prompt_details, "cached_tokens")
        or _usage_get(usage, "cache_read_input_tokens")
    )
    cache_creation_input_tokens = to_int(
        _usage_get(prompt_details, "cache_creation_tokens")
        or _usage_get(usage, "cache_creation_input_tokens")
    )
    reasoning_tokens = to_int(_usage_get(completion_details, "reasoning_tokens"))
    accepted_prediction_tokens = to_int(
        _usage_get(completion_details, "accepted_prediction_tokens")
    )
    rejected_prediction_tokens = to_int(
        _usage_get(completion_details, "rejected_prediction_tokens")
    )

    response_model = _usage_get(response, "model")
    selected_model = response_model or requested_model
    selection_reason = None
    if response_model:
        selection_reason = "response_model"
    elif requested_model:
        selection_reason = "requested_model"

    has_usage = bool(
        usage is not None
        or input_tokens
        or output_tokens
        or cache_read_input_tokens
        or cache_creation_input_tokens
        or reasoning_tokens
        or accepted_prediction_tokens
        or rejected_prediction_tokens
    )
    top_level_usage = None
    session_usage = None
    selected_model_usage = None
    context_window = to_int(
        _first_present(
            _usage_get(response, "context_window"),
            _usage_get(usage, "context_window"),
        )
    )
    if has_usage:
        top_level_usage = {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "cache_read_input_tokens": cache_read_input_tokens,
            "cache_creation_input_tokens": cache_creation_input_tokens,
            "reasoning_tokens": reasoning_tokens,
            "accepted_prediction_tokens": accepted_prediction_tokens,
            "rejected_prediction_tokens": rejected_prediction_tokens,
        }
        session_usage = {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "cache_read_input_tokens": cache_read_input_tokens,
            "cache_creation_input_tokens": cache_creation_input_tokens,
            "cost_usd": 0.0,
        }
        if selected_model:
            selected_model_usage = {
                "model": selected_model,
                "selection_reason": selection_reason,
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "cache_read_input_tokens": cache_read_input_tokens,
                "cache_creation_input_tokens": cache_creation_input_tokens,
                "reasoning_tokens": reasoning_tokens,
                "accepted_prediction_tokens": accepted_prediction_tokens,
                "rejected_prediction_tokens": rejected_prediction_tokens,
                "web_search_requests": 0,
                "cost_usd": 0.0,
                "context_window": context_window,
            }

    summary.update(
        {
            "requested_model": requested_model,
            "selected_model": selected_model,
            "selected_model_found": selected_model is not None,
            "selected_model_reason": selection_reason,
            "available_models": [selected_model] if selected_model else [],
            "models_usage": {selected_model: dict(selected_model_usage)} if selected_model_usage else {},
            "session_usage": session_usage,
            "selected_model_usage": selected_model_usage,
            "top_level_usage": top_level_usage,
            "response_id": _usage_get(response, "id"),
            "service_tier": _usage_get(response, "service_tier") or _usage_get(usage, "service_tier"),
            "is_error": False,
            "sessions_total": 1 if has_usage else 0,
            "turns_total": 1 if has_usage else 0,
            "calls_total": 1 if has_usage else 0,
        }
    )
    return summary
