import json
import subprocess

from utils.claude_cli import (
    aggregate_usage_summaries,
    coerce_aggregated_usage_summary,
    count_claude_cli_attempts,
    merge_aggregated_usage_summaries,
    run_claude_cli,
    summarize_claude_usage,
)


def test_summarize_claude_usage_prefers_deepseek_model_usage():
    summary = summarize_claude_usage(
        {
            "usage": {
                "input_tokens": 195,
                "output_tokens": 213,
            },
            "modelUsage": {
                "claude-haiku-4-5-20251001": {
                    "inputTokens": 64,
                    "outputTokens": 28,
                },
                "deepseek-chat": {
                    "inputTokens": 198,
                    "outputTokens": 245,
                    "cacheReadInputTokens": 32640,
                    "cacheCreationInputTokens": 0,
                    "costUSD": 0.014061,
                },
            },
        }
    )

    assert summary["selected_model_found"] is True
    assert summary["selected_model_usage"]["model"] == "deepseek-chat"
    assert summary["selected_model"] == "deepseek-chat"
    assert summary["selected_model_reason"] == "highest_usage_score"
    assert summary["session_usage"]["input_tokens"] == 195
    assert summary["session_usage"]["output_tokens"] == 213
    assert summary["selected_model_usage"]["input_tokens"] == 198
    assert summary["selected_model_usage"]["output_tokens"] == 245
    assert "claude-haiku-4-5-20251001" in summary["available_models"]


def test_summarize_claude_usage_reuses_selected_model_cost_for_session_totals():
    summary = summarize_claude_usage(
        {
            "usage": {
                "input_tokens": 195,
                "output_tokens": 213,
            },
            "modelUsage": {
                "deepseek-chat": {
                    "inputTokens": 198,
                    "outputTokens": 245,
                    "costUSD": 0.014061,
                },
            },
        }
    )

    assert summary["total_cost_usd"] == 0.014061
    assert summary["session_usage"]["cost_usd"] == 0.014061
    assert summary["selected_model_usage"]["cost_usd"] == 0.014061


def test_summarize_claude_usage_uses_single_available_model():
    summary = summarize_claude_usage(
        {
            "usage": {
                "input_tokens": 12,
                "output_tokens": 34,
            },
            "modelUsage": {
                "claude-sonnet-4-5": {
                    "inputTokens": 12,
                    "outputTokens": 34,
                    "costUSD": 0.5,
                },
            },
        }
    )

    assert summary["selected_model_found"] is True
    assert summary["selected_model"] == "claude-sonnet-4-5"
    assert summary["selected_model_reason"] == "single_available_model"
    assert summary["selected_model_usage"]["model"] == "claude-sonnet-4-5"


def test_summarize_claude_usage_chooses_highest_score_without_deepseek_hint():
    summary = summarize_claude_usage(
        {
            "usage": {
                "input_tokens": 100,
                "output_tokens": 50,
            },
            "modelUsage": {
                "deepseek-chat": {
                    "inputTokens": 10,
                    "outputTokens": 5,
                    "costUSD": 0.01,
                },
                "claude-sonnet-4-5": {
                    "inputTokens": 100,
                    "outputTokens": 50,
                    "costUSD": 1.2,
                },
            },
        }
    )

    assert summary["selected_model_found"] is True
    assert summary["selected_model"] == "claude-sonnet-4-5"
    assert summary["selected_model_reason"] == "highest_usage_score"
    assert summary["selected_model_usage"]["model"] == "claude-sonnet-4-5"


def test_summarize_claude_usage_respects_explicit_requested_model():
    summary = summarize_claude_usage(
        {
            "usage": {
                "input_tokens": 100,
                "output_tokens": 50,
            },
            "modelUsage": {
                "deepseek-chat": {
                    "inputTokens": 10,
                    "outputTokens": 5,
                    "costUSD": 0.01,
                },
                "claude-sonnet-4-5": {
                    "inputTokens": 100,
                    "outputTokens": 50,
                    "costUSD": 1.2,
                },
            },
        },
        selected_model="deepseek-chat",
    )

    assert summary["requested_model"] == "deepseek-chat"
    assert summary["selected_model"] == "deepseek-chat"
    assert summary["selected_model_reason"] == "requested_model"


def test_summarize_claude_usage_ignores_top_level_orchestrator_model_for_mixed_backends():
    summary = summarize_claude_usage(
        {
            "model": "claude-haiku-4-5-20251001",
            "usage": {
                "input_tokens": 100,
                "output_tokens": 50,
            },
            "modelUsage": {
                "claude-haiku-4-5-20251001": {
                    "inputTokens": 12,
                    "outputTokens": 8,
                    "costUSD": 0.1,
                },
                "deepseek-chat": {
                    "inputTokens": 150,
                    "outputTokens": 90,
                    "costUSD": 1.2,
                },
            },
        }
    )

    assert summary["requested_model"] is None
    assert summary["selected_model"] == "deepseek-chat"
    assert summary["selected_model_reason"] == "highest_usage_score"
    assert summary["selected_model_usage"]["model"] == "deepseek-chat"


def test_summarize_claude_usage_uses_explicit_backend_field_before_top_level_model():
    summary = summarize_claude_usage(
        {
            "model": "claude-haiku-4-5-20251001",
            "backendModel": "deepseek-chat",
            "usage": {
                "input_tokens": 100,
                "output_tokens": 50,
            },
            "modelUsage": {
                "claude-haiku-4-5-20251001": {
                    "inputTokens": 12,
                    "outputTokens": 8,
                    "costUSD": 0.1,
                },
                "deepseek-chat": {
                    "inputTokens": 150,
                    "outputTokens": 90,
                    "costUSD": 1.2,
                },
            },
        }
    )

    assert summary["requested_model"] == "deepseek-chat"
    assert summary["selected_model"] == "deepseek-chat"
    assert summary["selected_model_reason"] == "requested_model"


def test_summarize_claude_usage_does_not_let_hint_override_real_model_usage():
    summary = summarize_claude_usage(
        {
            "usage": {
                "input_tokens": 100,
                "output_tokens": 50,
            },
            "modelUsage": {
                "deepseek-chat": {
                    "inputTokens": 10,
                    "outputTokens": 5,
                    "costUSD": 0.01,
                },
                "claude-sonnet-4-5": {
                    "inputTokens": 100,
                    "outputTokens": 50,
                    "costUSD": 1.2,
                },
            },
        },
        preferred_model_hint="deepseek-chat",
    )

    assert summary["selected_model"] == "claude-sonnet-4-5"
    assert summary["selected_model_reason"] == "highest_usage_score"
    assert summary["selected_model_usage"]["model"] == "claude-sonnet-4-5"


def test_summarize_claude_usage_preserves_requested_model_with_top_level_usage_only():
    summary = summarize_claude_usage(
        {
            "usage": {
                "input_tokens": 12,
                "output_tokens": 34,
            },
        },
        selected_model="deepseek-chat",
    )

    assert summary["selected_model"] == "deepseek-chat"
    assert summary["selected_models"] == ["deepseek-chat"]
    assert summary["selected_model_reason"] == "requested_model"
    assert summary["selected_model_found"] is True
    assert summary["available_models"] == ["deepseek-chat"]
    assert summary["session_usage"]["input_tokens"] == 12
    assert summary["session_usage"]["output_tokens"] == 34
    assert summary["sessions_total"] == 1
    assert summary["calls_total"] == 1


def test_summarize_claude_usage_does_not_fabricate_model_from_top_level_hint():
    summary = summarize_claude_usage(
        {
            "usage": {
                "input_tokens": 12,
                "output_tokens": 34,
            },
        },
        preferred_model_hint="deepseek-chat",
    )

    assert summary["preferred_model_hint"] == "deepseek-chat"
    assert summary["selected_model"] is None
    assert summary["selected_model_reason"] is None
    assert summary["selected_model_found"] is False
    assert summary["available_models"] == []


def test_summarize_claude_usage_ignores_top_level_claude_model_for_backend_selection():
    summary = summarize_claude_usage(
        {
            "model": "claude-sonnet-4-5",
            "usage": {
                "input_tokens": 195,
                "output_tokens": 213,
            },
            "modelUsage": {
                "claude-sonnet-4-5": {
                    "inputTokens": 64,
                    "outputTokens": 28,
                    "costUSD": 0.2,
                },
                "deepseek-chat": {
                    "inputTokens": 198,
                    "outputTokens": 245,
                    "cacheReadInputTokens": 32640,
                    "cacheCreationInputTokens": 0,
                    "costUSD": 0.014061,
                },
            },
        }
    )

    assert summary["requested_model"] is None
    assert summary["selected_model"] == "deepseek-chat"
    assert summary["selected_model_reason"] == "highest_usage_score"
    assert summary["selected_model_usage"]["model"] == "deepseek-chat"


def test_summarize_claude_usage_ignores_primary_model_for_backend_selection():
    summary = summarize_claude_usage(
        {
            "primaryModel": "claude-sonnet-4-5",
            "usage": {
                "input_tokens": 195,
                "output_tokens": 213,
            },
            "modelUsage": {
                "claude-sonnet-4-5": {
                    "inputTokens": 64,
                    "outputTokens": 28,
                    "costUSD": 0.2,
                },
                "deepseek-chat": {
                    "inputTokens": 198,
                    "outputTokens": 245,
                    "cacheReadInputTokens": 32640,
                    "cacheCreationInputTokens": 0,
                    "costUSD": 0.014061,
                },
            },
        }
    )

    assert summary["requested_model"] is None
    assert summary["selected_model"] == "deepseek-chat"
    assert summary["selected_model_reason"] == "highest_usage_score"
    assert summary["selected_model_usage"]["model"] == "deepseek-chat"


def test_summarize_claude_usage_does_not_use_top_level_model_without_model_usage():
    summary = summarize_claude_usage(
        {
            "model": "claude-sonnet-4-5",
            "usage": {
                "input_tokens": 195,
                "output_tokens": 213,
            },
        }
    )

    assert summary["requested_model"] is None
    assert summary["selected_model"] is None
    assert summary["selected_model_reason"] is None
    assert summary["selected_models"] == []
    assert summary["selected_model_found"] is False


def test_summarize_claude_usage_can_mark_missing_output_as_error():
    summary = summarize_claude_usage(
        None,
        preferred_model_hint="deepseek-chat",
        is_error=True,
    )

    assert summary["preferred_model_hint"] == "deepseek-chat"
    assert summary["selected_model"] is None
    assert summary["is_error"] is True


def test_aggregate_usage_summaries_ignores_missing_selected_model():
    aggregate = aggregate_usage_summaries(
        [
            {
                "selected_model_usage": {
                    "model": "deepseek-chat",
                    "input_tokens": 10,
                    "output_tokens": 20,
                    "cost_usd": 0.5,
                },
                "total_cost_usd": 0.6,
            },
            {"selected_model_usage": None},
            {
                "selected_model_usage": {
                    "model": "deepseek-chat",
                    "input_tokens": 1,
                    "output_tokens": 2,
                    "cost_usd": 0.25,
                },
                "total_cost_usd": 0.3,
            },
        ]
    )

    assert aggregate["calls_total"] == 3
    assert aggregate["calls_with_selected_model_usage"] == 2
    assert aggregate["calls_missing_selected_model_usage"] == 1
    assert aggregate["selected_model"] == "deepseek-chat"
    assert aggregate["selected_models"] == ["deepseek-chat"]
    assert aggregate["input_tokens"] == 11
    assert aggregate["output_tokens"] == 22
    assert aggregate["cost_usd"] == 0.9
    assert aggregate["request_cost_usd"] == 0.9
    assert aggregate["selected_model_usage_summary"]["cost_usd"] == 0.75
    assert aggregate["session_usage_summary"]["cost_usd"] == 0.9


def test_aggregate_usage_summaries_falls_back_to_top_level_usage():
    aggregate = aggregate_usage_summaries(
        [
            {
                "selected_model_usage": None,
                "top_level_usage": {
                    "input_tokens": 7,
                    "output_tokens": 8,
                    "cache_read_input_tokens": 9,
                    "cache_creation_input_tokens": 10,
                },
                "total_cost_usd": 1.25,
            }
        ]
    )

    assert aggregate["calls_total"] == 1
    assert aggregate["calls_with_selected_model_usage"] == 0
    assert aggregate["calls_with_top_level_usage_fallback"] == 1
    assert aggregate["calls_missing_selected_model_usage"] == 1
    assert aggregate["calls_missing_usage"] == 0
    assert aggregate["selected_model"] is None
    assert aggregate["selected_models"] == []
    assert aggregate["input_tokens"] == 7
    assert aggregate["output_tokens"] == 8
    assert aggregate["cache_read_input_tokens"] == 9
    assert aggregate["cache_creation_input_tokens"] == 10
    assert aggregate["cost_usd"] == 1.25
    assert aggregate["request_cost_usd"] == 1.25
    assert aggregate["selected_model_usage_summary"] is None
    assert aggregate["session_usage_summary"]["cost_usd"] == 1.25


def test_aggregate_usage_summaries_uses_selected_model_cost_when_top_level_cost_is_missing():
    aggregate = aggregate_usage_summaries(
        [
            {
                "selected_model_usage": {
                    "model": "deepseek-chat",
                    "input_tokens": 10,
                    "output_tokens": 20,
                    "cost_usd": 0.5,
                },
                "top_level_usage": {
                    "input_tokens": 7,
                    "output_tokens": 8,
                },
            }
        ]
    )

    assert aggregate["calls_total"] == 1
    assert aggregate["calls_with_top_level_usage_fallback"] == 1
    assert aggregate["cost_usd"] == 0.5
    assert aggregate["request_cost_usd"] == 0.5
    assert aggregate["session_usage_summary"]["cost_usd"] == 0.5
    assert aggregate["selected_model_usage_summary"]["cost_usd"] == 0.5


def test_aggregate_usage_summaries_preserves_common_source_provider_and_requested_model():
    aggregate = aggregate_usage_summaries(
        [
            {
                "source": "llm_client",
                "provider": "deepseek",
                "requested_model": "deepseek-chat",
                "selected_model_usage": {
                    "model": "deepseek-chat",
                    "input_tokens": 7,
                    "output_tokens": 8,
                    "cost_usd": 0.4,
                },
                "total_cost_usd": 0.4,
            },
            {
                "source": "llm_client",
                "provider": "deepseek",
                "requested_model": "deepseek-chat",
                "selected_model_usage": {
                    "model": "deepseek-chat",
                    "input_tokens": 1,
                    "output_tokens": 2,
                    "cost_usd": 0.1,
                },
                "total_cost_usd": 0.1,
            },
        ]
    )

    assert aggregate["source"] == "llm_client"
    assert aggregate["provider"] == "deepseek"
    assert aggregate["requested_model"] == "deepseek-chat"
    assert aggregate["selected_model"] == "deepseek-chat"


def test_aggregate_usage_summaries_preserves_selected_model_for_top_level_usage():
    aggregate = aggregate_usage_summaries(
        [
            {
                "selected_model": "deepseek-chat",
                "requested_model": "deepseek-chat",
                "top_level_usage": {
                    "input_tokens": 7,
                    "output_tokens": 8,
                    "cache_read_input_tokens": 9,
                    "cache_creation_input_tokens": 10,
                },
                "total_cost_usd": 1.25,
            }
        ]
    )

    assert aggregate["calls_total"] == 1
    assert aggregate["selected_model"] == "deepseek-chat"
    assert aggregate["selected_models"] == ["deepseek-chat"]
    assert aggregate["calls_with_top_level_usage_fallback"] == 1
    assert aggregate["input_tokens"] == 7
    assert aggregate["output_tokens"] == 8


def test_merge_aggregated_usage_summaries_combines_totals():
    merged = merge_aggregated_usage_summaries(
        [
            {
                "source": "llm_client",
                "provider": "deepseek",
                "requested_model": None,
                "selected_model": "deepseek-chat",
                "selected_models": ["deepseek-chat"],
                "calls_total": 1,
                "calls_with_selected_model_usage": 1,
                "calls_with_top_level_usage_fallback": 0,
                "calls_missing_selected_model_usage": 0,
                "calls_missing_usage": 0,
                "input_tokens": 10,
                "output_tokens": 20,
                "cache_read_input_tokens": 30,
                "cache_creation_input_tokens": 40,
                "cost_usd": 0.5,
                "request_cost_usd": 0.6,
            },
            {
                "source": "llm_client",
                "provider": "deepseek",
                "requested_model": None,
                "selected_model": "deepseek-chat",
                "selected_models": ["deepseek-chat"],
                "calls_total": 2,
                "calls_with_selected_model_usage": 1,
                "calls_with_top_level_usage_fallback": 1,
                "calls_missing_selected_model_usage": 1,
                "calls_missing_usage": 0,
                "input_tokens": 1,
                "output_tokens": 2,
                "cache_read_input_tokens": 3,
                "cache_creation_input_tokens": 4,
                "cost_usd": 0.25,
                "request_cost_usd": 0.3,
            },
        ]
    )

    assert merged["source"] == "llm_client"
    assert merged["provider"] == "deepseek"
    assert merged["selected_model"] == "deepseek-chat"
    assert merged["calls_total"] == 3
    assert merged["calls_with_selected_model_usage"] == 2
    assert merged["calls_with_top_level_usage_fallback"] == 1
    assert merged["input_tokens"] == 11
    assert merged["cost_usd"] == 0.75
    assert merged["request_cost_usd"] == 0.9


def test_merge_aggregated_usage_summaries_does_not_carry_provider_into_mixed_sources():
    merged = merge_aggregated_usage_summaries(
        [
            {
                "source": "llm_client",
                "provider": "deepseek",
                "requested_model": "deepseek-chat",
                "selected_model": "deepseek-chat",
                "selected_models": ["deepseek-chat"],
                "calls_total": 1,
            },
            {
                "source": "claude_cli",
                "selected_model": "deepseek-chat",
                "selected_models": ["deepseek-chat"],
                "calls_total": 1,
            },
        ]
    )

    assert merged["source"] == "mixed"
    assert "provider" not in merged


def test_merge_aggregated_usage_summaries_ignores_zero_call_attribution():
    merged = merge_aggregated_usage_summaries(
        [
            {
                "source": "claude_cli",
                "requested_model": "claude-sonnet-4-5",
                "selected_model": "claude-sonnet-4-5",
                "selected_models": ["claude-sonnet-4-5"],
                "calls_total": 0,
            },
            {
                "source": "llm_client",
                "provider": "deepseek",
                "requested_model": "deepseek-chat",
                "selected_model": "deepseek-chat",
                "selected_models": ["deepseek-chat"],
                "calls_total": 1,
                "calls_with_selected_model_usage": 1,
                "input_tokens": 12,
                "output_tokens": 34,
            },
        ]
    )

    assert merged["source"] == "llm_client"
    assert merged["provider"] == "deepseek"
    assert merged["requested_model"] == "deepseek-chat"
    assert merged["selected_model"] == "deepseek-chat"
    assert merged["selected_models"] == ["deepseek-chat"]
    assert merged["calls_total"] == 1
    assert merged["input_tokens"] == 12
    assert merged["output_tokens"] == 34


def test_merge_aggregated_usage_summaries_preserves_mixed_requested_model():
    merged = merge_aggregated_usage_summaries(
        [
            {
                "source": "llm_client",
                "provider": "deepseek",
                "requested_model": "mixed",
                "selected_model": "mixed",
                "selected_models": ["deepseek-chat", "gpt-5.1"],
                "calls_total": 2,
            },
            {
                "source": "llm_client",
                "provider": "deepseek",
                "requested_model": "deepseek-chat",
                "selected_model": "deepseek-chat",
                "selected_models": ["deepseek-chat"],
                "calls_total": 1,
            },
        ]
    )

    assert merged["source"] == "llm_client"
    assert merged["provider"] == "deepseek"
    assert merged["requested_model"] == "mixed"
    assert merged["selected_model"] == "mixed"


def test_coerce_aggregated_usage_summary_preserves_zero_call_raw_usage():
    summary = coerce_aggregated_usage_summary(
        {
            "source": "claude_cli",
            "calls_total": 0,
            "selected_model": "deepseek-chat",
            "selected_model_usage": None,
            "top_level_usage": None,
        }
    )

    assert summary["calls_total"] == 0
    assert summary["calls_missing_usage"] == 0
    assert summary["input_tokens"] == 0
    assert summary["output_tokens"] == 0


def test_coerce_aggregated_usage_summary_treats_empty_dict_as_zero_call_usage():
    summary = coerce_aggregated_usage_summary({})

    assert summary["calls_total"] == 0
    assert summary["calls_with_selected_model_usage"] == 0
    assert summary["calls_with_top_level_usage_fallback"] == 0
    assert summary["calls_missing_usage"] == 0
    assert summary["selected_models"] == []
    assert summary["input_tokens"] == 0
    assert summary["output_tokens"] == 0


def test_coerce_aggregated_usage_summary_keeps_raw_usage_totals_with_explicit_call_count():
    summary = coerce_aggregated_usage_summary(
        {
            "source": "claude_cli",
            "calls_total": 1,
            "requested_model": "deepseek-chat",
            "selected_model": "deepseek-chat",
            "selected_model_usage": {
                "model": "deepseek-chat",
                "input_tokens": 12,
                "output_tokens": 34,
                "cache_read_input_tokens": 56,
                "cache_creation_input_tokens": 0,
                "cost_usd": 0.1,
            },
            "top_level_usage": {
                "input_tokens": 12,
                "output_tokens": 34,
                "cache_read_input_tokens": 56,
                "cache_creation_input_tokens": 0,
            },
            "total_cost_usd": 0.1,
        }
    )

    assert summary["calls_total"] == 1
    assert summary["calls_with_selected_model_usage"] == 1
    assert summary["calls_with_top_level_usage_fallback"] == 1
    assert summary["input_tokens"] == 12
    assert summary["output_tokens"] == 34
    assert summary["selected_model_usage_summary"]["cost_usd"] == 0.1
    assert summary["session_usage_summary"]["cost_usd"] == 0.1


def test_coerce_aggregated_usage_summary_preserves_direct_summarize_claude_usage_output():
    raw_summary = summarize_claude_usage(
        {
            "usage": {
                "input_tokens": 12,
                "output_tokens": 34,
            },
        },
        selected_model="deepseek-chat",
    )

    summary = coerce_aggregated_usage_summary(raw_summary)

    assert summary["calls_total"] == 1
    assert summary["calls_with_session_usage"] == 1
    assert summary["calls_with_selected_model_usage"] == 0
    assert summary["calls_with_top_level_usage_fallback"] == 0
    assert summary["calls_missing_usage"] == 0
    assert summary["selected_model"] == "deepseek-chat"
    assert summary["selected_models"] == ["deepseek-chat"]
    assert summary["input_tokens"] == 12
    assert summary["output_tokens"] == 34


def test_coerce_aggregated_usage_summary_treats_raw_claude_summary_with_sessions_as_raw():
    summary = coerce_aggregated_usage_summary(
        {
            "source": "claude_cli",
            "sessions_total": 1,
            "turns_total": 17,
            "calls_total": 1,
            "selected_model": "deepseek-chat",
            "selected_model_usage": {
                "model": "deepseek-chat",
                "input_tokens": 21325,
                "output_tokens": 3454,
                "cache_read_input_tokens": 316928,
                "cache_creation_input_tokens": 0,
                "cost_usd": 0.2108634,
            },
            "session_usage": {
                "input_tokens": 18271,
                "output_tokens": 2493,
                "cache_read_input_tokens": 304896,
                "cache_creation_input_tokens": 0,
                "cost_usd": 0.222381,
            },
            "top_level_usage": {
                "input_tokens": 18271,
                "output_tokens": 2493,
                "cache_read_input_tokens": 304896,
                "cache_creation_input_tokens": 0,
            },
            "total_cost_usd": 0.222381,
        }
    )

    assert summary["sessions_total"] == 1
    assert summary["turns_total"] == 17
    assert summary["calls_with_session_usage"] == 1
    assert summary["calls_with_selected_model_usage"] == 1
    assert summary["input_tokens"] == 18271
    assert summary["output_tokens"] == 2493
    assert summary["cost_usd"] == 0.222381
    assert summary["selected_model_usage_summary"]["cost_usd"] == 0.210863


def test_coerce_aggregated_usage_summary_does_not_imply_llm_client_session_usage():
    summary = coerce_aggregated_usage_summary(
        {
            "source": "llm_client",
            "provider": "deepseek",
            "sessions_total": 2,
            "calls_total": 2,
            "calls_with_session_usage": 0,
            "calls_with_selected_model_usage": 0,
            "calls_with_selected_model_usage_session_fallback": 0,
            "calls_with_top_level_usage_fallback": 0,
            "calls_missing_usage": 2,
            "calls_missing_selected_model_usage": 2,
            "input_tokens": 0,
            "output_tokens": 0,
            "cache_read_input_tokens": 0,
            "cache_creation_input_tokens": 0,
            "cost_usd": 0.0,
            "request_cost_usd": 0.0,
            "session_usage_summary": None,
            "selected_model_usage_summary": None,
        }
    )

    assert summary["calls_with_session_usage"] == 0
    assert summary["calls_missing_usage"] == 2
    assert summary["calls_with_selected_model_usage_session_fallback"] == 0


def test_coerce_aggregated_usage_summary_preserves_explicit_top_level_fallback_provenance():
    summary = coerce_aggregated_usage_summary(
        {
            "source": "claude_cli",
            "sessions_total": 2,
            "calls_total": 2,
            "calls_with_session_usage": 0,
            "calls_with_top_level_usage_fallback": 2,
            "calls_missing_usage": 0,
            "calls_missing_selected_model_usage": 2,
            "input_tokens": 12,
            "output_tokens": 34,
            "cache_read_input_tokens": 0,
            "cache_creation_input_tokens": 0,
            "cost_usd": 0.5,
            "request_cost_usd": 0.5,
            "session_usage_summary": {
                "input_tokens": 12,
                "output_tokens": 34,
                "cache_read_input_tokens": 0,
                "cache_creation_input_tokens": 0,
                "cost_usd": 0.5,
            },
        }
    )

    assert summary["calls_total"] == 2
    assert summary["calls_with_session_usage"] == 0
    assert summary["calls_with_top_level_usage_fallback"] == 2
    assert summary["calls_with_selected_model_usage_session_fallback"] == 0


def test_count_claude_cli_attempts_counts_current_and_prior_subprocess_runs():
    class _Response:
        def __init__(self, returncode, timed_out=False, prior_attempts=None, usage_summary=None):
            self.returncode = returncode
            self.timed_out = timed_out
            self.prior_attempts = prior_attempts or []
            self.usage_summary = usage_summary or {}

    assert count_claude_cli_attempts(_Response(returncode=None, timed_out=False)) == 0
    assert count_claude_cli_attempts(_Response(returncode=None, timed_out=True)) == 1
    assert count_claude_cli_attempts(_Response(returncode=0, timed_out=False, prior_attempts=[{}])) == 2
    assert count_claude_cli_attempts(
        _Response(
            returncode=1,
            timed_out=False,
            usage_summary={"selected_model_usage": {"model": "deepseek-chat"}},
        )
    ) == 1


def test_run_claude_cli_writes_record(monkeypatch, tmp_path):
    record_path = tmp_path / "claude_cli_invocation.json"
    prompt = "line 1\nAPI_KEY: super-secret-token"

    class _Result:
        returncode = 0
        stdout = '{"type":"result","subtype":"success","result":"API_KEY: super-secret-token","modelUsage":{"deepseek-chat":{"inputTokens":3,"outputTokens":4}}}'
        stderr = ""

    def _fake_run(*args, **kwargs):
        return _Result()

    monkeypatch.setattr("utils.claude_cli.subprocess.run", _fake_run)

    response = run_claude_cli(
        prompt=prompt,
        cwd=str(tmp_path),
        record_path=record_path,
    )

    assert response.success is True
    assert response.usage_summary["sessions_total"] == 1
    assert response.usage_summary["selected_model_usage"]["output_tokens"] == 4
    saved = record_path.read_text(encoding="utf-8")
    assert '"prompt_sha256":' in saved
    assert f'"prompt_length": {len(prompt)}' in saved
    assert f"<prompt-redacted:{len(prompt)} chars>" in saved
    assert '"prompt":' not in saved
    assert "super-secret-token" not in saved
    assert "API_KEY: [REDACTED]" in saved
    assert '"output_tokens": 4' in saved


def test_run_claude_cli_preserves_json_stdout_after_redaction(monkeypatch, tmp_path):
    record_path = tmp_path / "claude_cli_invocation.json"

    class _Result:
        returncode = 0
        stdout = (
            '{"type":"result","subtype":"success","result":"API_KEY: super-secret-token",'
            '"tool_output":"Authorization: Bearer auth-secret",'
            '"modelUsage":{"deepseek-chat":{"inputTokens":3,"outputTokens":4}}}'
        )
        stderr = ""

    def _fake_run(*args, **kwargs):
        return _Result()

    monkeypatch.setattr("utils.claude_cli.subprocess.run", _fake_run)

    response = run_claude_cli(
        prompt="json stdout redaction",
        cwd=str(tmp_path),
        record_path=record_path,
    )

    assert response.success is True
    saved_record = json.loads(record_path.read_text(encoding="utf-8"))
    sanitized_stdout = json.loads(saved_record["stdout"])
    assert sanitized_stdout["result"] == "API_KEY: [REDACTED]"
    assert sanitized_stdout["tool_output"] == "Authorization: [REDACTED]"
    assert sanitized_stdout["modelUsage"]["deepseek-chat"]["outputTokens"] == 4


def test_run_claude_cli_redacts_structured_api_key_fields(monkeypatch, tmp_path):
    record_path = tmp_path / "claude_cli_invocation.json"

    class _Result:
        returncode = 0
        stdout = (
            '{"type":"result","subtype":"success","result":"ok",'
            '"tool_output":{"OPENAI_API_KEY":"sk-secret","nested":{"DEEPSEEK_API_KEY":"ds-secret"}},'
            '"modelUsage":{"deepseek-chat":{"inputTokens":3,"outputTokens":4}}}'
        )
        stderr = ""

    def _fake_run(*args, **kwargs):
        return _Result()

    monkeypatch.setattr("utils.claude_cli.subprocess.run", _fake_run)

    response = run_claude_cli(
        prompt="structured output",
        cwd=str(tmp_path),
        record_path=record_path,
    )

    assert response.success is True
    saved = record_path.read_text(encoding="utf-8")
    assert "sk-secret" not in saved
    assert "ds-secret" not in saved
    assert '"OPENAI_API_KEY": "[REDACTED]"' in saved
    assert '"DEEPSEEK_API_KEY": "[REDACTED]"' in saved


def test_run_claude_cli_redacts_structured_hyphenated_auth_headers(monkeypatch, tmp_path):
    record_path = tmp_path / "claude_cli_invocation.json"

    class _Result:
        returncode = 0
        stdout = (
            '{"type":"result","subtype":"success","result":"ok",'
            '"tool_output":{"headers":{"Proxy-Authorization":"Basic proxy-secret","X-API-Key":"x-api-secret"}},'
            '"modelUsage":{"deepseek-chat":{"inputTokens":3,"outputTokens":4}}}'
        )
        stderr = ""

    def _fake_run(*args, **kwargs):
        return _Result()

    monkeypatch.setattr("utils.claude_cli.subprocess.run", _fake_run)

    response = run_claude_cli(
        prompt="structured hyphenated headers",
        cwd=str(tmp_path),
        record_path=record_path,
    )

    assert response.success is True
    saved = record_path.read_text(encoding="utf-8")
    assert "proxy-secret" not in saved
    assert "x-api-secret" not in saved
    assert '"Proxy-Authorization": "[REDACTED]"' in saved
    assert '"X-API-Key": "[REDACTED]"' in saved


def test_run_claude_cli_redacts_structured_camel_case_auth_headers(monkeypatch, tmp_path):
    record_path = tmp_path / "claude_cli_invocation.json"

    class _Result:
        returncode = 0
        stdout = (
            '{"type":"result","subtype":"success","result":"ok",'
            '"tool_output":{"headers":{"proxyAuthorization":"Basic proxy-secret","xApiKey":"x-api-secret"}},'
            '"modelUsage":{"deepseek-chat":{"inputTokens":3,"outputTokens":4}}}'
        )
        stderr = ""

    def _fake_run(*args, **kwargs):
        return _Result()

    monkeypatch.setattr("utils.claude_cli.subprocess.run", _fake_run)

    response = run_claude_cli(
        prompt="structured camel case headers",
        cwd=str(tmp_path),
        record_path=record_path,
    )

    assert response.success is True
    saved = record_path.read_text(encoding="utf-8")
    assert "proxy-secret" not in saved
    assert "x-api-secret" not in saved
    assert '"proxyAuthorization": "[REDACTED]"' in saved
    assert '"xApiKey": "[REDACTED]"' in saved


def test_run_claude_cli_uses_explicit_model_arg_for_selection(monkeypatch, tmp_path):
    record_path = tmp_path / "claude_cli_invocation.json"

    class _Result:
        returncode = 0
        stdout = (
            '{"type":"result","subtype":"success","result":"ok",'
            '"modelUsage":{"deepseek-chat":{"inputTokens":300,"outputTokens":400,"costUSD":1.0},'
            '"claude-sonnet-4-5":{"inputTokens":3,"outputTokens":4,"costUSD":0.1}}}'
        )
        stderr = ""

    def _fake_run(*args, **kwargs):
        return _Result()

    monkeypatch.setattr("utils.claude_cli.subprocess.run", _fake_run)

    response = run_claude_cli(
        prompt="explicit model argument",
        cwd=str(tmp_path),
        extra_args=["--model", "claude-sonnet-4-5"],
        record_path=record_path,
    )

    assert response.success is True
    assert response.usage_summary["requested_model"] == "claude-sonnet-4-5"
    assert response.usage_summary["selected_model"] == "claude-sonnet-4-5"
    assert response.usage_summary["selected_model_reason"] == "requested_model"


def test_run_claude_cli_falls_back_to_plain_text_when_json_output_is_unsupported(monkeypatch, tmp_path):
    record_path = tmp_path / "claude_cli_invocation.json"
    commands = []

    class _JsonUnsupportedResult:
        returncode = 2
        stdout = ""
        stderr = "error: unexpected argument '--output-format' found"

    class _PlainTextResult:
        returncode = 0
        stdout = "analysis completed"
        stderr = ""

    results = [_JsonUnsupportedResult(), _PlainTextResult()]

    def _fake_run(cmd, *args, **kwargs):
        commands.append(cmd)
        return results.pop(0)

    monkeypatch.setattr("utils.claude_cli.subprocess.run", _fake_run)

    response = run_claude_cli(
        prompt="fallback run",
        cwd=str(tmp_path),
        record_path=record_path,
        allow_plain_text_fallback=True,
    )

    assert response.success is True
    assert response.output_format == "text"
    assert response.fallback_from_json_output is True
    assert response.fallback_reason == "json_output_flag_unsupported"
    assert len(response.prior_attempts or []) == 1
    assert len(commands) == 2
    assert response.usage_summary["sessions_total"] == 2
    assert response.usage_summary["calls_total"] == 2
    assert "--output-format" in commands[0]
    assert "--output-format" not in commands[1]

    saved_record = json.loads(record_path.read_text(encoding="utf-8"))
    assert saved_record["output_format"] == "text"
    assert saved_record["fallback_from_json_output"] is True
    assert saved_record["prior_attempts"][0]["output_format"] == "json"
    assert saved_record["prior_attempts"][0]["command"][-1].startswith("<prompt-redacted:")


def test_run_claude_cli_marks_zero_exit_non_json_as_success(monkeypatch, tmp_path):
    record_path = tmp_path / "claude_cli_invocation.json"

    class _Result:
        returncode = 0
        stdout = "plain text success"
        stderr = ""

    def _fake_run(*args, **kwargs):
        return _Result()

    monkeypatch.setattr("utils.claude_cli.subprocess.run", _fake_run)

    response = run_claude_cli(
        prompt="plain text run",
        cwd=str(tmp_path),
        record_path=record_path,
    )

    assert response.success is True
    assert response.parsed_output is None
    assert response.parse_error is not None
    assert response.usage_summary["selected_model"] is None
    saved = record_path.read_text(encoding="utf-8")
    assert '"success": true' in saved


def test_run_claude_cli_redacts_timeout_error_message(monkeypatch, tmp_path):
    record_path = tmp_path / "claude_cli_invocation.json"
    prompt = "API_KEY: super-secret-token"

    def _fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(
            cmd=["claude", "-p", prompt],
            timeout=5,
            output=b"API_KEY: super-secret-token",
            stderr=b"Authorization: Bearer auth-secret",
        )

    monkeypatch.setattr("utils.claude_cli.subprocess.run", _fake_run)

    response = run_claude_cli(
        prompt=prompt,
        cwd=str(tmp_path),
        record_path=record_path,
    )

    assert response.success is False
    saved = record_path.read_text(encoding="utf-8")
    assert "super-secret-token" not in saved
    assert "auth-secret" not in saved
    assert "API_KEY: [REDACTED]" in saved
    assert "Authorization: [REDACTED]" in saved


def test_run_claude_cli_timeout_decodes_bytes_stdout_stderr(monkeypatch, tmp_path):
    record_path = tmp_path / "claude_cli_invocation.json"

    def _fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(
            cmd=["claude", "-p", "prompt"],
            timeout=5,
            output=b"stdout-bytes",
            stderr=b"stderr-bytes",
        )

    monkeypatch.setattr("utils.claude_cli.subprocess.run", _fake_run)

    response = run_claude_cli(
        prompt="prompt",
        cwd=str(tmp_path),
        record_path=record_path,
    )

    assert response.success is False
    assert response.stdout == "stdout-bytes"
    assert response.stderr == "stderr-bytes"
    assert response.usage_summary["is_error"] is True
    saved = json.loads(record_path.read_text(encoding="utf-8"))
    assert saved["stdout"] == "stdout-bytes"
    assert saved["stderr"] == "stderr-bytes"
    assert saved["usage_summary"]["is_error"] is True


def test_run_claude_cli_marks_missing_binary_usage_as_error(monkeypatch, tmp_path):
    record_path = tmp_path / "claude_cli_invocation.json"

    def _fake_run(*args, **kwargs):
        raise FileNotFoundError("claude not found")

    monkeypatch.setattr("utils.claude_cli.subprocess.run", _fake_run)

    response = run_claude_cli(
        prompt="prompt",
        cwd=str(tmp_path),
        record_path=record_path,
    )

    assert response.success is False
    assert response.usage_summary["is_error"] is True
    saved = json.loads(record_path.read_text(encoding="utf-8"))
    assert saved["usage_summary"]["is_error"] is True


def test_run_claude_cli_redacts_plain_text_auth_secrets(monkeypatch, tmp_path):
    record_path = tmp_path / "claude_cli_invocation.json"

    class _Result:
        returncode = 1
        stdout = (
            "ANTHROPIC_API_KEY=anth-secret\n"
            "Authorization: Bearer auth-secret\n"
            "curl -H 'Authorization: Bearer quoted-secret' https://example.test\n"
        )
        stderr = 'export OPENAI_API_KEY="openai-secret"\nProxy-Authorization: Basic proxy-secret\n'

    def _fake_run(*args, **kwargs):
        return _Result()

    monkeypatch.setattr("utils.claude_cli.subprocess.run", _fake_run)

    response = run_claude_cli(
        prompt="plain text secret output",
        cwd=str(tmp_path),
        record_path=record_path,
    )

    assert response.success is False
    assert response.usage_summary["is_error"] is True
    saved = record_path.read_text(encoding="utf-8")
    assert "anth-secret" not in saved
    assert "auth-secret" not in saved
    assert "quoted-secret" not in saved
    assert "openai-secret" not in saved
    assert "proxy-secret" not in saved
    assert "ANTHROPIC_API_KEY=[REDACTED]" in saved
    assert "Authorization: [REDACTED]" in saved
    assert "OPENAI_API_KEY=[REDACTED]" in saved
    assert '"is_error": true' in saved
    assert "Proxy-Authorization: [REDACTED]" in saved
