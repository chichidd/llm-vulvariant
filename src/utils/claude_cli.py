from __future__ import annotations

import hashlib
import json
import re
import subprocess
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from utils.number_utils import to_float, to_int


# Optional diagnostic hint for environments that expect Claude to proxy to DeepSeek.
# This is recorded in metadata, but it is not treated as evidence for model attribution.
DEFAULT_SELECTED_MODEL_HINT = "deepseek-chat"
_SECRET_PATTERNS = [
    re.compile(r"((?:[A-Z0-9_-]*API(?:[_-]?KEY)):\s*)(\"[^\"]*\"|'[^']*'|\S+)", flags=re.IGNORECASE),
    re.compile(r"((?:[A-Z0-9_-]*API(?:[_-]?KEY))=)(\"[^\"]*\"|'[^']*'|\S+)", flags=re.IGNORECASE),
    re.compile(r"((?:[A-Z0-9_-]*AUTHORIZATION)=)(\"[^\"]*\"|'[^']*'|\S+)", flags=re.IGNORECASE),
    re.compile(r"((?:Proxy-)?Authorization:\s*)(\"[^\"]*\"|'[^']*'|[^\r\n]+)", flags=re.IGNORECASE),
]
_JSON_OUTPUT_UNSUPPORTED_PATTERNS = [
    re.compile(r"(?:unknown|unexpected|unrecognized|unsupported)[^\n\r]*--output-format", flags=re.IGNORECASE),
    re.compile(r"--output-format[^\n\r]*(?:unknown|unexpected|unrecognized|unsupported)", flags=re.IGNORECASE),
    re.compile(r"(?:json output|output format)[^\n\r]*(?:not supported|unsupported)", flags=re.IGNORECASE),
]


def _collect_string_field(values_seen: set[str], value: Any) -> None:
    if isinstance(value, str):
        normalized = value.strip()
        if normalized:
            values_seen.add(normalized)


def _set_common_or_mixed_field(target: Dict[str, Any], field_name: str, values_seen: set[str]) -> None:
    if len(values_seen) == 1:
        target[field_name] = next(iter(values_seen))
    elif len(values_seen) > 1:
        target[field_name] = "mixed"


def _set_provider_field(
    target: Dict[str, Any],
    *,
    providers_seen: set[str],
    sources_seen: set[str],
) -> None:
    if len(sources_seen) <= 1:
        _set_common_or_mixed_field(target, "provider", providers_seen)
    elif len(providers_seen) > 1:
        target["provider"] = "mixed"


def aggregated_usage_summary_has_calls(summary: Optional[Dict[str, Any]]) -> bool:
    return isinstance(summary, dict) and max(
        to_int(summary.get("sessions_total")),
        to_int(summary.get("calls_total")),
    ) > 0


def _new_usage_totals() -> Dict[str, Any]:
    return {
        "input_tokens": 0,
        "output_tokens": 0,
        "cache_read_input_tokens": 0,
        "cache_creation_input_tokens": 0,
        "cost_usd": 0.0,
    }


def _normalize_usage_totals(usage: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not isinstance(usage, dict):
        return None

    normalized = _new_usage_totals()
    normalized["input_tokens"] = to_int(usage.get("input_tokens"))
    normalized["output_tokens"] = to_int(usage.get("output_tokens"))
    normalized["cache_read_input_tokens"] = to_int(usage.get("cache_read_input_tokens"))
    normalized["cache_creation_input_tokens"] = to_int(usage.get("cache_creation_input_tokens"))
    normalized["cost_usd"] = to_float(usage.get("cost_usd"))
    return normalized


def _add_usage_totals(target: Dict[str, Any], usage: Optional[Dict[str, Any]]) -> None:
    if not isinstance(usage, dict):
        return
    target["input_tokens"] += to_int(usage.get("input_tokens"))
    target["output_tokens"] += to_int(usage.get("output_tokens"))
    target["cache_read_input_tokens"] += to_int(usage.get("cache_read_input_tokens"))
    target["cache_creation_input_tokens"] += to_int(usage.get("cache_creation_input_tokens"))
    target["cost_usd"] += to_float(usage.get("cost_usd"))


def _finalize_usage_totals(usage: Dict[str, Any]) -> Dict[str, Any]:
    usage["cost_usd"] = round(to_float(usage.get("cost_usd")), 6)
    return usage


def _build_session_usage(
    usage: Optional[Dict[str, Any]],
    *,
    total_cost_usd: float = 0.0,
) -> Optional[Dict[str, Any]]:
    normalized = _normalize_usage_totals(usage)
    if normalized is None:
        return None
    normalized["cost_usd"] = round(total_cost_usd, 6)
    return normalized


def _session_count_from_usage_summary(summary: Optional[Dict[str, Any]]) -> int:
    if not isinstance(summary, dict):
        return 0
    if "sessions_total" in summary or "calls_total" in summary:
        return max(
            to_int(summary.get("sessions_total")),
            to_int(summary.get("calls_total")),
        )
    explicit_count = max(
        to_int(summary.get("sessions_total")),
        to_int(summary.get("calls_total")),
    )
    if explicit_count > 0:
        return explicit_count
    if (
        isinstance(summary.get("session_usage"), dict)
        or isinstance(summary.get("top_level_usage"), dict)
        or isinstance(summary.get("selected_model_usage"), dict)
    ):
        return 1
    return 1 if summary else 0

def _get_model_usage_map(claude_output: Optional[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    if not isinstance(claude_output, dict):
        return {}

    model_usage = claude_output.get("modelUsage")
    if not isinstance(model_usage, dict):
        return {}

    return {
        str(key): value for key, value in model_usage.items()
        if isinstance(key, str) and isinstance(value, dict)
    }


def _extract_requested_model_from_output(
    claude_output: Optional[Dict[str, Any]],
) -> Optional[str]:
    if not isinstance(claude_output, dict):
        return None

    for field_name in (
        "requested_model",
        "requestedModel",
        "backend_model",
        "backendModel",
    ):
        value = claude_output.get(field_name)
        if isinstance(value, str) and value.strip():
            return value.strip()

    model_usage = _get_model_usage_map(claude_output)
    if len(model_usage) > 1:
        return None

    return None


def _extract_requested_model_from_args(extra_args: Optional[List[str]]) -> Optional[str]:
    if not extra_args:
        return None

    for index, arg in enumerate(extra_args):
        if arg == "--model" and index + 1 < len(extra_args):
            model_name = extra_args[index + 1].strip()
            if model_name:
                return model_name
        if arg.startswith("--model="):
            model_name = arg.split("=", 1)[1].strip()
            if model_name:
                return model_name
    return None


def _resolve_selected_model(
    model_usage: Dict[str, Dict[str, Any]],
    requested_model: Optional[str],
) -> Tuple[Optional[str], str]:
    if requested_model and requested_model in model_usage:
        return requested_model, "requested_model"

    if len(model_usage) == 1:
        return next(iter(model_usage.keys())), "single_available_model"

    if not model_usage:
        return None, "no_model_usage"

    def _score(item: Tuple[str, Dict[str, Any]]) -> Tuple[int, int, float]:
        _model, usage = item
        total_tokens = (
            to_int(usage.get("inputTokens", usage.get("input_tokens")))
            + to_int(usage.get("outputTokens", usage.get("output_tokens")))
        )
        cache_tokens = to_int(
            usage.get("cacheReadInputTokens", usage.get("cache_read_input_tokens"))
        )
        cost = to_float(usage.get("costUSD", usage.get("cost_usd")))
        return total_tokens, cache_tokens, cost

    selected_model, _ = max(model_usage.items(), key=_score)
    return selected_model, "highest_usage_score"


def normalize_claude_model_usage(
    claude_output: Optional[Dict[str, Any]],
    selected_model: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Extract normalized usage for the effective backend model from Claude JSON."""
    model_usage = _get_model_usage_map(claude_output)
    requested_model = selected_model or _extract_requested_model_from_output(claude_output)
    resolved_model, selection_reason = _resolve_selected_model(
        model_usage=model_usage,
        requested_model=requested_model,
    )
    if not resolved_model:
        return None

    raw = model_usage.get(resolved_model)
    if not isinstance(raw, dict):
        return None

    return {
        "model": resolved_model,
        "selection_reason": selection_reason,
        "input_tokens": to_int(raw.get("inputTokens", raw.get("input_tokens"))),
        "output_tokens": to_int(raw.get("outputTokens", raw.get("output_tokens"))),
        "cache_read_input_tokens": to_int(
            raw.get("cacheReadInputTokens", raw.get("cache_read_input_tokens"))
        ),
        "cache_creation_input_tokens": to_int(
            raw.get("cacheCreationInputTokens", raw.get("cache_creation_input_tokens"))
        ),
        "web_search_requests": to_int(raw.get("webSearchRequests", raw.get("web_search_requests"))),
        "cost_usd": to_float(raw.get("costUSD", raw.get("cost_usd"))),
        "context_window": to_int(raw.get("contextWindow", raw.get("context_window"))),
    }


def _normalize_top_level_usage(claude_output: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not isinstance(claude_output, dict):
        return None

    usage = claude_output.get("usage")
    if not isinstance(usage, dict):
        return None

    return {
        "input_tokens": to_int(usage.get("input_tokens")),
        "output_tokens": to_int(usage.get("output_tokens")),
        "cache_read_input_tokens": to_int(
            usage.get("cache_read_input_tokens", usage.get("cache_read_tokens"))
        ),
        "cache_creation_input_tokens": to_int(
            usage.get("cache_creation_input_tokens", usage.get("cache_creation_tokens"))
        ),
        "service_tier": usage.get("service_tier"),
        "server_tool_use": usage.get("server_tool_use"),
    }


def _normalize_models_usage(claude_output: Optional[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    normalized: Dict[str, Dict[str, Any]] = {}
    for model_name, usage in _get_model_usage_map(claude_output).items():
        model_usage = normalize_claude_model_usage(
            {"modelUsage": {model_name: usage}},
            selected_model=model_name,
        )
        if isinstance(model_usage, dict):
            normalized[model_name] = model_usage
    return normalized


def summarize_claude_usage(
    claude_output: Optional[Dict[str, Any]],
    selected_model: Optional[str] = None,
    preferred_model_hint: Optional[str] = None,
    is_error: bool = False,
) -> Dict[str, Any]:
    """Build a compact usage summary for downstream storage and aggregation."""
    model_usage = _get_model_usage_map(claude_output)
    requested_model = selected_model or _extract_requested_model_from_output(claude_output)
    top_level_usage = _normalize_top_level_usage(claude_output)
    total_cost_usd = (
        to_float(claude_output.get("total_cost_usd"))
        if isinstance(claude_output, dict) else 0.0
    )
    session_usage = _build_session_usage(
        top_level_usage,
        total_cost_usd=total_cost_usd,
    )
    turns_total = (
        to_int(claude_output.get("num_turns", claude_output.get("numTurns")))
        if isinstance(claude_output, dict) else 0
    )

    selected_model_usage = normalize_claude_model_usage(
        claude_output=claude_output,
        selected_model=requested_model,
    )
    models_usage = _normalize_models_usage(claude_output)
    effective_model = selected_model_usage.get("model") if isinstance(selected_model_usage, dict) else None
    selection_reason = (
        selected_model_usage.get("selection_reason")
        if isinstance(selected_model_usage, dict) else None
    )
    if effective_model is None and isinstance(top_level_usage, dict):
        if requested_model:
            effective_model = requested_model
            selection_reason = "requested_model"

    available_models: List[str] = sorted(model_usage.keys())
    if effective_model and effective_model not in available_models:
        available_models.append(effective_model)
        available_models.sort()
    selected_models = [effective_model] if effective_model else []
    has_usage = any(
        isinstance(usage, dict)
        for usage in (
            session_usage,
            top_level_usage,
            selected_model_usage,
        )
    )

    return {
        "source": "claude_cli",
        "requested_model": requested_model,
        "preferred_model_hint": preferred_model_hint,
        "selected_model": effective_model,
        "selected_models": selected_models,
        "selected_model_found": effective_model is not None,
        "selected_model_reason": selection_reason,
        "available_models": available_models,
        "models_usage": models_usage,
        "session_usage": session_usage,
        "selected_model_usage": selected_model_usage,
        "top_level_usage": top_level_usage,
        "session_id": claude_output.get("session_id") if isinstance(claude_output, dict) else None,
        "uuid": claude_output.get("uuid") if isinstance(claude_output, dict) else None,
        "duration_ms": to_int(claude_output.get("duration_ms")) if isinstance(claude_output, dict) else 0,
        "duration_api_ms": to_int(claude_output.get("duration_api_ms")) if isinstance(claude_output, dict) else 0,
        "total_cost_usd": total_cost_usd,
        "is_error": (
            is_error
            or (bool(claude_output.get("is_error")) if isinstance(claude_output, dict) else False)
        ),
        "subtype": claude_output.get("subtype") if isinstance(claude_output, dict) else None,
        "sessions_total": 1 if has_usage else 0,
        "turns_total": turns_total,
        "calls_total": 1 if has_usage else 0,
    }


def count_claude_cli_attempts(response: Any) -> int:
    """Count Claude CLI sessions represented by a response."""
    if response is None:
        return 0

    usage_summary = getattr(response, "usage_summary", None)
    if isinstance(usage_summary, dict) and (
        usage_summary.get("session_usage")
        or usage_summary.get("top_level_usage")
        or usage_summary.get("selected_model_usage")
    ):
        return 1
    if getattr(response, "timed_out", False):
        return 1
    if getattr(response, "returncode", None) == 0:
        return 1
    return 0


def count_claude_cli_turns(response: Any) -> int:
    """Return the reported Claude CLI turn count when available."""
    if response is None:
        return 0

    parsed_output = getattr(response, "parsed_output", None)
    if isinstance(parsed_output, dict):
        return to_int(parsed_output.get("num_turns", parsed_output.get("numTurns")))

    usage_summary = getattr(response, "usage_summary", None)
    if isinstance(usage_summary, dict):
        return to_int(usage_summary.get("turns_total"))
    return 0


def apply_claude_cli_usage_counters(
    usage_summary: Optional[Dict[str, Any]],
    response: Any,
) -> Dict[str, Any]:
    summary = dict(usage_summary or {})
    sessions_total = count_claude_cli_attempts(response)
    turns_total = count_claude_cli_turns(response)
    summary["sessions_total"] = sessions_total
    summary["turns_total"] = turns_total
    summary["calls_total"] = sessions_total
    return summary


def _is_aggregated_usage_summary(usage: Dict[str, Any]) -> bool:
    aggregated_markers = (
        "calls_with_session_usage",
        "calls_with_selected_model_usage",
        "calls_with_selected_model_usage_session_fallback",
        "calls_with_top_level_usage_fallback",
        "calls_missing_selected_model_usage",
        "calls_missing_usage",
        "request_cost_usd",
        "session_usage_summary",
        "selected_model_usage_summary",
    )
    if any(key in usage for key in aggregated_markers):
        return True

    if "selected_models" in usage:
        raw_markers = (
            "preferred_model_hint",
            "selected_model_found",
            "selected_model_reason",
            "available_models",
            "models_usage",
            "session_usage",
            "selected_model_usage",
            "top_level_usage",
            "session_id",
            "uuid",
            "duration_ms",
            "duration_api_ms",
            "total_cost_usd",
            "is_error",
            "subtype",
        )
        if any(key in usage for key in raw_markers):
            return False
        return True

    return any(
        key in usage
        for key in aggregated_markers
    )


def aggregate_usage_summaries(
    usage_summaries: Iterable[Optional[Dict[str, Any]]],
    selected_model: Optional[str] = None,
) -> Dict[str, Any]:
    """Aggregate usage summaries with session totals as the default flat totals."""
    selected_models_seen = set()
    sources_seen = set()
    providers_seen = set()
    requested_models_seen = set()
    aggregate = {
        "source": "claude_cli",
        "requested_model": selected_model,
        "selected_model": None,
        "selected_models": [],
        "sessions_total": 0,
        "turns_total": 0,
        "calls_total": 0,
        "calls_with_session_usage": 0,
        "calls_with_selected_model_usage": 0,
        "calls_with_selected_model_usage_session_fallback": 0,
        "calls_with_top_level_usage_fallback": 0,
        "calls_missing_selected_model_usage": 0,
        "calls_missing_usage": 0,
        "input_tokens": 0,
        "output_tokens": 0,
        "cache_read_input_tokens": 0,
        "cache_creation_input_tokens": 0,
        "cost_usd": 0.0,
        "request_cost_usd": 0.0,
        "session_usage_summary": _new_usage_totals(),
        "selected_model_usage_summary": None,
    }
    selected_usage_summary = _new_usage_totals()

    for item in usage_summaries:
        if not isinstance(item, dict):
            continue

        _collect_string_field(sources_seen, item.get("source"))
        _collect_string_field(providers_seen, item.get("provider"))
        if selected_model is None:
            _collect_string_field(requested_models_seen, item.get("requested_model"))

        item_sessions = _session_count_from_usage_summary(item)
        aggregate["sessions_total"] += item_sessions
        aggregate["turns_total"] += to_int(item.get("turns_total"))

        selected_usage_raw = item.get("selected_model_usage")
        selected_usage = _normalize_usage_totals(selected_usage_raw)
        model_name = None
        if isinstance(selected_usage_raw, dict):
            aggregate["calls_with_selected_model_usage"] += item_sessions
            model_name = selected_usage_raw.get("model")
            if model_name:
                selected_models_seen.add(str(model_name))
            _add_usage_totals(selected_usage_summary, selected_usage)
        else:
            aggregate["calls_missing_selected_model_usage"] += item_sessions

        session_usage = _normalize_usage_totals(item.get("session_usage"))
        usage_for_totals = None
        if session_usage is not None:
            aggregate["calls_with_session_usage"] += item_sessions
            usage_for_totals = dict(session_usage)
        else:
            top_level_usage = _normalize_usage_totals(item.get("top_level_usage"))
            if top_level_usage is not None:
                aggregate["calls_with_top_level_usage_fallback"] += item_sessions
                usage_for_totals = dict(top_level_usage)
            elif selected_usage is not None:
                # Compatibility fallback for legacy raw summaries that only stored
                # selected-model usage. This keeps resume/merge flows stable even
                # though session totals are unavailable for those historical items.
                aggregate["calls_with_selected_model_usage_session_fallback"] += item_sessions
                usage_for_totals = dict(selected_usage)
            else:
                aggregate["calls_missing_usage"] += item_sessions

        if model_name is None:
            model_name = item.get("selected_model") or item.get("requested_model")
            if model_name and usage_for_totals is not None:
                selected_models_seen.add(str(model_name))

        if usage_for_totals is not None:
            session_cost = to_float(item.get("total_cost_usd"))
            if session_cost == 0.0:
                session_cost = to_float(usage_for_totals.get("cost_usd"))
            if session_cost == 0.0:
                session_cost = to_float(item.get("cost_usd"))
            usage_for_totals["cost_usd"] = session_cost
            _add_usage_totals(aggregate["session_usage_summary"], usage_for_totals)

            aggregate["input_tokens"] += to_int(usage_for_totals.get("input_tokens"))
            aggregate["output_tokens"] += to_int(usage_for_totals.get("output_tokens"))
            aggregate["cache_read_input_tokens"] += to_int(usage_for_totals.get("cache_read_input_tokens"))
            aggregate["cache_creation_input_tokens"] += to_int(
                usage_for_totals.get("cache_creation_input_tokens")
            )
            aggregate["cost_usd"] += session_cost
            aggregate["request_cost_usd"] += session_cost

    aggregate["calls_total"] = aggregate["sessions_total"]
    aggregate["cost_usd"] = round(aggregate["cost_usd"], 6)
    aggregate["request_cost_usd"] = round(aggregate["request_cost_usd"], 6)
    aggregate["session_usage_summary"] = _finalize_usage_totals(aggregate["session_usage_summary"])
    aggregate["session_usage_summary"]["request_cost_usd"] = aggregate["request_cost_usd"]
    if aggregate["calls_with_selected_model_usage"] > 0:
        aggregate["selected_model_usage_summary"] = _finalize_usage_totals(selected_usage_summary)
    aggregate["selected_models"] = sorted(selected_models_seen)
    _set_common_or_mixed_field(aggregate, "source", sources_seen)
    _set_provider_field(
        aggregate,
        providers_seen=providers_seen,
        sources_seen=sources_seen,
    )
    if selected_model is None:
        _set_common_or_mixed_field(aggregate, "requested_model", requested_models_seen)
    if len(selected_models_seen) == 1:
        aggregate["selected_model"] = next(iter(selected_models_seen))
    elif len(selected_models_seen) > 1:
        aggregate["selected_model"] = "mixed"
    if isinstance(aggregate.get("selected_model_usage_summary"), dict) and aggregate.get("selected_model"):
        aggregate["selected_model_usage_summary"]["model"] = aggregate.get("selected_model")
    return aggregate


def merge_aggregated_usage_summaries(
    summaries: Iterable[Optional[Dict[str, Any]]],
) -> Dict[str, Any]:
    """Merge already-aggregated usage summaries."""
    merged = {
        "source": "claude_cli",
        "requested_model": None,
        "selected_model": None,
        "selected_models": [],
        "sessions_total": 0,
        "turns_total": 0,
        "calls_total": 0,
        "calls_with_session_usage": 0,
        "calls_with_selected_model_usage": 0,
        "calls_with_selected_model_usage_session_fallback": 0,
        "calls_with_top_level_usage_fallback": 0,
        "calls_missing_selected_model_usage": 0,
        "calls_missing_usage": 0,
        "input_tokens": 0,
        "output_tokens": 0,
        "cache_read_input_tokens": 0,
        "cache_creation_input_tokens": 0,
        "cost_usd": 0.0,
        "request_cost_usd": 0.0,
        "session_usage_summary": _new_usage_totals(),
        "selected_model_usage_summary": None,
    }
    sources_seen = set()
    providers_seen = set()
    requested_models_seen = set()
    requested_model_is_mixed = False
    selected_models_seen = set()
    selected_usage_summary = _new_usage_totals()

    for summary in summaries:
        if not isinstance(summary, dict):
            continue

        normalized_summary = coerce_aggregated_usage_summary(summary)

        if aggregated_usage_summary_has_calls(normalized_summary):
            _collect_string_field(sources_seen, normalized_summary.get("source"))
            _collect_string_field(providers_seen, normalized_summary.get("provider"))
            requested_model = normalized_summary.get("requested_model")
            if requested_model == "mixed":
                requested_model_is_mixed = True
            elif requested_model not in (None, ""):
                requested_models_seen.add(str(requested_model))

            for model_name in normalized_summary.get("selected_models", []):
                if model_name:
                    selected_models_seen.add(str(model_name))
            selected_model = normalized_summary.get("selected_model")
            if selected_model not in (None, "", "mixed"):
                selected_models_seen.add(str(selected_model))

        merged["sessions_total"] += max(
            to_int(normalized_summary.get("sessions_total")),
            to_int(normalized_summary.get("calls_total")),
        )
        merged["turns_total"] += to_int(normalized_summary.get("turns_total"))
        merged["calls_with_session_usage"] += to_int(normalized_summary.get("calls_with_session_usage"))
        merged["calls_with_selected_model_usage"] += to_int(normalized_summary.get("calls_with_selected_model_usage"))
        merged["calls_with_selected_model_usage_session_fallback"] += to_int(
            normalized_summary.get("calls_with_selected_model_usage_session_fallback")
        )
        merged["calls_with_top_level_usage_fallback"] += to_int(
            normalized_summary.get("calls_with_top_level_usage_fallback")
        )
        merged["calls_missing_selected_model_usage"] += to_int(
            normalized_summary.get("calls_missing_selected_model_usage")
        )
        merged["calls_missing_usage"] += to_int(normalized_summary.get("calls_missing_usage"))
        merged["input_tokens"] += to_int(normalized_summary.get("input_tokens"))
        merged["output_tokens"] += to_int(normalized_summary.get("output_tokens"))
        merged["cache_read_input_tokens"] += to_int(normalized_summary.get("cache_read_input_tokens"))
        merged["cache_creation_input_tokens"] += to_int(normalized_summary.get("cache_creation_input_tokens"))
        merged["cost_usd"] += to_float(normalized_summary.get("cost_usd"))
        merged["request_cost_usd"] += to_float(
            normalized_summary.get("request_cost_usd", normalized_summary.get("cost_usd"))
        )
        _add_usage_totals(merged["session_usage_summary"], normalized_summary.get("session_usage_summary"))
        _add_usage_totals(selected_usage_summary, normalized_summary.get("selected_model_usage_summary"))

    merged["calls_total"] = merged["sessions_total"]
    merged["cost_usd"] = round(merged["cost_usd"], 6)
    merged["request_cost_usd"] = round(merged["request_cost_usd"], 6)
    merged["session_usage_summary"] = _finalize_usage_totals(merged["session_usage_summary"])
    merged["session_usage_summary"]["request_cost_usd"] = merged["request_cost_usd"]
    if merged["calls_with_selected_model_usage"] > 0:
        merged["selected_model_usage_summary"] = _finalize_usage_totals(selected_usage_summary)
    merged["selected_models"] = sorted(selected_models_seen)
    _set_common_or_mixed_field(merged, "source", sources_seen)
    _set_provider_field(
        merged,
        providers_seen=providers_seen,
        sources_seen=sources_seen,
    )
    if len(selected_models_seen) == 1:
        merged["selected_model"] = next(iter(selected_models_seen))
    elif len(selected_models_seen) > 1:
        merged["selected_model"] = "mixed"
    if isinstance(merged.get("selected_model_usage_summary"), dict) and merged.get("selected_model"):
        merged["selected_model_usage_summary"]["model"] = merged.get("selected_model")

    if requested_model_is_mixed:
        merged["requested_model"] = "mixed"
    else:
        _set_common_or_mixed_field(merged, "requested_model", requested_models_seen)

    return merged


def coerce_aggregated_usage_summary(usage: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Normalize raw single-call or aggregated usage into aggregated form."""
    if not isinstance(usage, dict) or not usage:
        return aggregate_usage_summaries([])
    if _is_aggregated_usage_summary(usage):
        summary = aggregate_usage_summaries([])
        summary["source"] = usage.get("source", summary.get("source"))
        provider = usage.get("provider")
        if provider:
            summary["provider"] = provider

        requested_model = usage.get("requested_model")
        if requested_model not in (None, ""):
            summary["requested_model"] = requested_model

        selected_models = sorted(
            {
                str(model)
                for model in (usage.get("selected_models") or [])
                if model not in (None, "")
            }
        )
        selected_model = usage.get("selected_model")
        if selected_model not in (None, "", "mixed"):
            selected_models = sorted(set(selected_models) | {str(selected_model)})
        summary["selected_models"] = selected_models
        if selected_model in (None, "") and len(selected_models) == 1:
            selected_model = selected_models[0]
        summary["selected_model"] = selected_model

        sessions_total = max(
            to_int(usage.get("sessions_total")),
            to_int(usage.get("calls_total")),
        )
        summary["sessions_total"] = sessions_total
        summary["turns_total"] = to_int(usage.get("turns_total"))
        summary["calls_total"] = sessions_total
        summary["calls_with_session_usage"] = to_int(usage.get("calls_with_session_usage"))
        summary["calls_with_selected_model_usage"] = to_int(usage.get("calls_with_selected_model_usage"))
        summary["calls_with_selected_model_usage_session_fallback"] = to_int(
            usage.get("calls_with_selected_model_usage_session_fallback")
        )
        summary["calls_with_top_level_usage_fallback"] = to_int(
            usage.get("calls_with_top_level_usage_fallback")
        )
        summary["calls_missing_selected_model_usage"] = to_int(
            usage.get("calls_missing_selected_model_usage")
        )
        summary["calls_missing_usage"] = to_int(usage.get("calls_missing_usage"))
        summary["input_tokens"] = to_int(usage.get("input_tokens"))
        summary["output_tokens"] = to_int(usage.get("output_tokens"))
        summary["cache_read_input_tokens"] = to_int(usage.get("cache_read_input_tokens"))
        summary["cache_creation_input_tokens"] = to_int(usage.get("cache_creation_input_tokens"))
        summary["cost_usd"] = round(to_float(usage.get("cost_usd")), 6)
        request_cost_usd = to_float(usage.get("request_cost_usd", usage.get("cost_usd")))
        summary["request_cost_usd"] = round(request_cost_usd, 6)

        session_usage_summary = _normalize_usage_totals(usage.get("session_usage_summary"))
        if session_usage_summary is None:
            session_usage_summary = _new_usage_totals()
            session_usage_summary["input_tokens"] = summary["input_tokens"]
            session_usage_summary["output_tokens"] = summary["output_tokens"]
            session_usage_summary["cache_read_input_tokens"] = summary["cache_read_input_tokens"]
            session_usage_summary["cache_creation_input_tokens"] = summary["cache_creation_input_tokens"]
            session_usage_summary["cost_usd"] = summary["cost_usd"]
        summary["session_usage_summary"] = _finalize_usage_totals(session_usage_summary)
        summary["session_usage_summary"]["request_cost_usd"] = summary["request_cost_usd"]

        selected_model_usage_summary = _normalize_usage_totals(usage.get("selected_model_usage_summary"))
        if selected_model_usage_summary is None and to_int(usage.get("calls_with_selected_model_usage")) > 0:
            selected_model_usage_summary = _new_usage_totals()
            selected_model_usage_summary["input_tokens"] = summary["input_tokens"]
            selected_model_usage_summary["output_tokens"] = summary["output_tokens"]
            selected_model_usage_summary["cache_read_input_tokens"] = summary["cache_read_input_tokens"]
            selected_model_usage_summary["cache_creation_input_tokens"] = summary["cache_creation_input_tokens"]
            selected_model_usage_summary["cost_usd"] = round(to_float(usage.get("cost_usd")), 6)
        summary["selected_model_usage_summary"] = (
            _finalize_usage_totals(selected_model_usage_summary)
            if selected_model_usage_summary is not None
            else None
        )

        if summary["calls_with_session_usage"] <= 0 and sessions_total > 0:
            if isinstance(usage.get("session_usage_summary"), dict):
                summary["calls_with_session_usage"] = sessions_total
            elif to_int(usage.get("calls_with_top_level_usage_fallback")) > 0:
                summary["calls_with_session_usage"] = 0
            elif summary["input_tokens"] or summary["output_tokens"] or summary["cost_usd"]:
                summary["calls_with_selected_model_usage_session_fallback"] = max(
                    summary["calls_with_selected_model_usage_session_fallback"],
                    min(sessions_total, max(1, to_int(usage.get("calls_with_selected_model_usage")))),
        )

        return summary

    requested_model = usage.get("requested_model")
    summary = aggregate_usage_summaries([usage], selected_model=requested_model)

    explicit_calls_total = max(
        to_int(usage.get("sessions_total")),
        to_int(usage.get("calls_total")),
    )
    if "sessions_total" in usage or "calls_total" in usage:
        if explicit_calls_total <= 0:
            summary = aggregate_usage_summaries([], selected_model=requested_model)
        else:
            summary["sessions_total"] = explicit_calls_total
            summary["calls_total"] = explicit_calls_total
            summary["calls_missing_selected_model_usage"] = max(
                explicit_calls_total - to_int(summary.get("calls_with_selected_model_usage")),
                0,
            )
            usage_covered_calls = max(
                to_int(summary.get("calls_with_session_usage")),
                to_int(summary.get("calls_with_top_level_usage_fallback")),
                to_int(summary.get("calls_with_selected_model_usage_session_fallback")),
            )
            summary["calls_missing_usage"] = max(
                explicit_calls_total
                - usage_covered_calls,
                0,
            )

    summary["source"] = usage.get("source", summary.get("source"))
    provider = usage.get("provider")
    if provider:
        summary["provider"] = provider
    if isinstance(summary.get("selected_model_usage_summary"), dict) and summary.get("selected_model"):
        summary["selected_model_usage_summary"]["model"] = summary.get("selected_model")
    return summary


@dataclass
class ClaudeCLIResponse:
    success: bool
    command: List[str]
    prompt: str
    cwd: str
    returncode: Optional[int]
    stdout: str
    stderr: str
    parsed_output: Optional[Dict[str, Any]]
    usage_summary: Dict[str, Any]
    record_path: Optional[Path]
    parse_error: Optional[str] = None
    error_type: Optional[str] = None
    error_message: Optional[str] = None
    timed_out: bool = False
    output_format: str = "json"
    fallback_from_json_output: bool = False
    fallback_reason: Optional[str] = None
    prior_attempts: Optional[List[Dict[str, Any]]] = None


def _sanitize_text(text: str) -> str:
    try:
        parsed = json.loads(text)
    except (TypeError, ValueError, json.JSONDecodeError):
        sanitized = text
        for pattern in _SECRET_PATTERNS:
            sanitized = pattern.sub(r"\1[REDACTED]", sanitized)
        return sanitized
    return json.dumps(_sanitize_record_value(parsed), ensure_ascii=False)


def _coerce_process_output_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _is_sensitive_key_name(key_name: Optional[str]) -> bool:
    if not key_name:
        return False

    normalized = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", key_name)
    normalized = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", normalized)
    normalized = re.sub(r"[^A-Za-z0-9]+", "_", normalized).strip("_").upper()
    return (
        normalized == "AUTHORIZATION"
        or normalized.endswith("_AUTHORIZATION")
        or normalized == "API_KEY"
        or normalized.endswith("_API_KEY")
        or normalized == "APIKEY"
        or normalized.endswith("_APIKEY")
    )


def _sanitize_record_value(value: Any, key_name: Optional[str] = None) -> Any:
    if _is_sensitive_key_name(key_name):
        return "[REDACTED]"
    if isinstance(value, str):
        return _sanitize_text(value)
    if isinstance(value, dict):
        return {key: _sanitize_record_value(item, str(key)) for key, item in value.items()}
    if isinstance(value, list):
        return [_sanitize_record_value(item, key_name) for item in value]
    return value


def _redacted_command(command: List[str], prompt: str) -> List[str]:
    if not command:
        return []
    redacted = list(command)
    redacted[-1] = f"<prompt-redacted:{len(prompt)} chars>"
    return redacted


def _write_record(record_path: Path, response: ClaudeCLIResponse) -> None:
    record_path.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "timestamp": datetime.now().isoformat(),
        "success": response.success,
        "timed_out": response.timed_out,
        "command": _redacted_command(response.command, response.prompt),
        "cwd": response.cwd,
        "prompt_sha256": hashlib.sha256(response.prompt.encode("utf-8")).hexdigest(),
        "prompt_length": len(response.prompt),
        "prompt_line_count": response.prompt.count("\n") + 1 if response.prompt else 0,
        "returncode": response.returncode,
        "parse_error": response.parse_error,
        "error_type": response.error_type,
        "error_message": _sanitize_record_value(response.error_message),
        "usage_summary": response.usage_summary,
        "stdout": _sanitize_record_value(response.stdout),
        "stderr": _sanitize_record_value(response.stderr),
        "parsed_output": _sanitize_record_value(response.parsed_output),
        "output_format": response.output_format,
        "fallback_from_json_output": response.fallback_from_json_output,
        "fallback_reason": response.fallback_reason,
        "prior_attempts": _sanitize_record_value(response.prior_attempts or []),
    }
    record_path.write_text(json.dumps(record, indent=2, ensure_ascii=False), encoding="utf-8")


def _should_retry_without_json_output(response: ClaudeCLIResponse) -> bool:
    if response.returncode in (None, 0):
        return False
    if response.timed_out or response.error_type == "FileNotFoundError":
        return False

    haystack = "\n".join(
        part for part in (response.stderr, response.stdout, response.error_message) if part
    )
    return any(pattern.search(haystack) for pattern in _JSON_OUTPUT_UNSUPPORTED_PATTERNS)


def run_claude_cli(
    prompt: str,
    *,
    cwd: str,
    env: Optional[Dict[str, str]] = None,
    timeout: Optional[int] = None,
    extra_args: Optional[List[str]] = None,
    record_path: Optional[Path] = None,
    selected_model: Optional[str] = None,
    preferred_model_hint: Optional[str] = None,
    json_output: bool = True,
    allow_plain_text_fallback: bool = False,
) -> ClaudeCLIResponse:
    """Run ``claude -p`` and optionally persist the raw call record."""
    command = ["claude", "-p", *(extra_args or [])]
    if json_output:
        command.extend(["--output-format", "json"])
    command.append(prompt)
    requested_model = selected_model or _extract_requested_model_from_args(extra_args)

    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            cwd=cwd,
            env=env,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        response = ClaudeCLIResponse(
            success=False,
            command=command,
            prompt=prompt,
            cwd=cwd,
            returncode=None,
            stdout=_coerce_process_output_text(exc.stdout),
            stderr=_coerce_process_output_text(exc.stderr),
            parsed_output=None,
            usage_summary=summarize_claude_usage(
                None,
                selected_model=requested_model,
                preferred_model_hint=preferred_model_hint,
                is_error=True,
            ),
            record_path=record_path,
            error_type=type(exc).__name__,
            error_message=str(exc),
            timed_out=True,
            output_format="json" if json_output else "text",
        )
    except FileNotFoundError as exc:
        response = ClaudeCLIResponse(
            success=False,
            command=command,
            prompt=prompt,
            cwd=cwd,
            returncode=None,
            stdout="",
            stderr="",
            parsed_output=None,
            usage_summary=summarize_claude_usage(
                None,
                selected_model=requested_model,
                preferred_model_hint=preferred_model_hint,
                is_error=True,
            ),
            record_path=record_path,
            error_type=type(exc).__name__,
            error_message=str(exc),
            output_format="json" if json_output else "text",
        )
    except Exception as exc:
        response = ClaudeCLIResponse(
            success=False,
            command=command,
            prompt=prompt,
            cwd=cwd,
            returncode=None,
            stdout="",
            stderr="",
            parsed_output=None,
            usage_summary=summarize_claude_usage(
                None,
                selected_model=requested_model,
                preferred_model_hint=preferred_model_hint,
                is_error=True,
            ),
            record_path=record_path,
            error_type=type(exc).__name__,
            error_message=str(exc),
            output_format="json" if json_output else "text",
        )
    else:
        parsed_output: Optional[Dict[str, Any]] = None
        parse_error: Optional[str] = None
        if result.stdout:
            try:
                parsed = json.loads(result.stdout)
                if isinstance(parsed, dict):
                    parsed_output = parsed
                else:
                    parse_error = f"Expected JSON object from Claude CLI, got {type(parsed).__name__}"
            except json.JSONDecodeError as exc:
                parse_error = str(exc)

        usage_source = parsed_output if isinstance(parsed_output, dict) else None
        response = ClaudeCLIResponse(
            success=result.returncode == 0,
            command=command,
            prompt=prompt,
            cwd=cwd,
            returncode=result.returncode,
            stdout=result.stdout or "",
            stderr=result.stderr or "",
            parsed_output=parsed_output,
            usage_summary=summarize_claude_usage(
                usage_source,
                selected_model=requested_model,
                preferred_model_hint=preferred_model_hint,
                is_error=result.returncode != 0,
            ),
            record_path=record_path,
            parse_error=parse_error,
            error_type=None if result.returncode == 0 else "ClaudeCLIError",
            error_message=(result.stderr or "").strip() or None,
            output_format="json" if json_output else "text",
        )

    if allow_plain_text_fallback and json_output and _should_retry_without_json_output(response):
        fallback_response = run_claude_cli(
            prompt=prompt,
            cwd=cwd,
            env=env,
            timeout=timeout,
            extra_args=extra_args,
            record_path=None,
            selected_model=selected_model,
            preferred_model_hint=preferred_model_hint,
            json_output=False,
            allow_plain_text_fallback=False,
        )
        fallback_response.record_path = record_path
        fallback_response.fallback_from_json_output = True
        fallback_response.fallback_reason = "json_output_flag_unsupported"
        fallback_response.prior_attempts = [
            {
                "command": _redacted_command(response.command, response.prompt),
                "returncode": response.returncode,
                "stdout": response.stdout,
                "stderr": response.stderr,
                "parse_error": response.parse_error,
                "error_type": response.error_type,
                "error_message": response.error_message,
                "timed_out": response.timed_out,
                "output_format": response.output_format,
            }
        ]
        response = fallback_response

    response.usage_summary = apply_claude_cli_usage_counters(response.usage_summary, response)
    if record_path is not None:
        _write_record(record_path, response)
    return response
