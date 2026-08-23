import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from llm.client import (
    BaseLLMClient,
    DeepSeekClient,
    LLMConfig,
    LLMNoResultError,
    LLMResponseIdentityError,
    LLMRetryExhaustedError,
    OpenAIClient,
    build_empty_llm_usage_summary,
    create_llm_client,
    load_llm_config_from_yaml,
    safe_chat_call,
    summarize_chat_completion_usage,
)
from utils.claude_cli import aggregate_usage_summaries


class _UsageDetails:
    def __init__(self, cached_tokens=0, reasoning_tokens=0):
        self.cached_tokens = cached_tokens
        self.reasoning_tokens = reasoning_tokens


class _CompletionDetails:
    def __init__(self, reasoning_tokens=0):
        self.reasoning_tokens = reasoning_tokens


class _Usage:
    def __init__(self):
        self.prompt_tokens = 120
        self.completion_tokens = 45
        self.prompt_tokens_details = _UsageDetails(cached_tokens=33)
        self.completion_tokens_details = _CompletionDetails(reasoning_tokens=7)


class _Response:
    def __init__(self):
        self.id = "resp_123"
        self.model = "deepseek-chat"
        self.service_tier = "standard"
        self.usage = _Usage()


class _DummyClient(BaseLLMClient):
    def __init__(self):
        self.config = SimpleNamespace(model="deepseek-chat", provider="deepseek")
        self.context_limit = 8192
        self._last_usage_summary = build_empty_llm_usage_summary(
            requested_model=self.config.model,
            provider=self.config.provider,
        )
        self._usage_history = []
        self.max_retries = 1
        self.initial_delay = 0.0
        self.max_delay = 0.0
        self.backoff_factor = 1.0

    def chat(self, messages, tools=None, **kwargs):
        raise NotImplementedError

    def complete(self, prompt, **kwargs):
        raise NotImplementedError


class _FakeOpenAI:
    def __init__(self, api_key=None, base_url=None, max_retries=None):
        self.api_key = api_key
        self.base_url = base_url
        self.max_retries = max_retries


class _ScriptedClient(BaseLLMClient):
    def __init__(self, config, chat_script, record_success_usage=False):
        super().__init__(config)
        self.chat_script = list(chat_script)
        self.chat_calls = []
        self.record_success_usage = record_success_usage

    def _make_chat_request(self, messages, tools=None, **kwargs):
        self.chat_calls.append(
            {
                "messages": messages,
                "tools": tools,
                "kwargs": kwargs,
            }
        )
        outcome = self.chat_script.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        if self.record_success_usage:
            usage_summary = build_empty_llm_usage_summary(
                requested_model=self.config.model,
                provider=self.config.provider,
            )
            usage_summary["selected_model"] = self.config.model
            usage_summary["selected_model_reason"] = "configured_model"
            usage_summary["selected_model_usage"] = {
                "input_tokens": 11,
                "output_tokens": 5,
                "context_window": self.context_limit,
            }
            usage_summary["calls_total"] = 1
            self._record_usage_summary(usage_summary)
        return outcome

    def chat(self, messages, tools=None, **kwargs):
        return self._execute_with_retry(self._make_chat_request, messages, tools=tools, **kwargs)

    def complete(self, prompt, **kwargs):
        raise NotImplementedError


def test_summarize_chat_completion_usage_extracts_openai_style_usage():
    summary = summarize_chat_completion_usage(
        _Response(),
        requested_model="deepseek-chat",
        provider="deepseek",
    )

    assert summary["source"] == "llm_client"
    assert summary["provider"] == "deepseek"
    assert summary["selected_model"] == "deepseek-chat"
    assert summary["selected_model_reason"] == "response_model"
    assert summary["selected_model_usage"]["input_tokens"] == 120
    assert summary["selected_model_usage"]["output_tokens"] == 45
    assert summary["selected_model_usage"]["cache_read_input_tokens"] == 33
    assert summary["selected_model_usage"]["reasoning_tokens"] == 7
    assert summary["response_id"] == "resp_123"


def test_summarize_chat_completion_usage_coerces_mapping_usage_values():
    summary = summarize_chat_completion_usage(
        {
            "id": "resp_map",
            "model": "deepseek-chat",
            "usage": {
                "prompt_tokens": "120",
                "completion_tokens": "45",
                "context_window": "16384",
                "service_tier": "priority",
                "prompt_tokens_details": {
                    "cached_tokens": "33",
                    "cache_creation_tokens": "4",
                },
                "completion_tokens_details": {
                    "reasoning_tokens": "7",
                    "accepted_prediction_tokens": "8",
                    "rejected_prediction_tokens": "9",
                },
            },
        },
        requested_model="deepseek-chat",
        provider="deepseek",
    )

    assert summary["service_tier"] == "priority"
    assert summary["calls_total"] == 1
    assert summary["selected_model_usage"]["input_tokens"] == 120
    assert summary["selected_model_usage"]["output_tokens"] == 45
    assert summary["selected_model_usage"]["cache_read_input_tokens"] == 33
    assert summary["selected_model_usage"]["cache_creation_input_tokens"] == 4
    assert summary["selected_model_usage"]["reasoning_tokens"] == 7
    assert summary["selected_model_usage"]["accepted_prediction_tokens"] == 8
    assert summary["selected_model_usage"]["rejected_prediction_tokens"] == 9
    assert summary["selected_model_usage"]["context_window"] == 16384


def test_execute_with_retry_does_not_append_empty_usage_for_pre_request_failure():
    client = _DummyClient()

    with pytest.raises(ValueError):
        client._execute_with_retry(lambda: (_ for _ in ()).throw(ValueError("boom")))

    assert client._usage_history == []
    assert client.get_last_usage_summary()["is_error"] is True


def test_execute_with_retry_does_not_double_record_usage_after_post_response_failure():
    client = _DummyClient()
    usage_summary = summarize_chat_completion_usage(
        _Response(),
        requested_model=client.config.model,
        provider=client.config.provider,
    )

    def _func():
        client._record_usage_summary(usage_summary)
        raise ValueError("malformed response")

    with pytest.raises(ValueError):
        client._execute_with_retry(_func)

    assert len(client._usage_history) == 1
    assert client._usage_history[0]["selected_model"] == "deepseek-chat"
    assert client._usage_history[0]["is_error"] is False
    assert client.get_last_usage_summary()["selected_model"] == "deepseek-chat"
    assert client.get_last_usage_summary()["is_error"] is True


def test_execute_with_retry_does_not_retry_local_error_with_timeout_in_message():
    client = _DummyClient()
    client.max_retries = 3

    calls = []

    def _func():
        calls.append("called")
        raise ValueError("request timeout while validating schema")

    with pytest.raises(ValueError, match="request timeout while validating schema"):
        client._execute_with_retry(_func)

    assert calls == ["called"]
    assert client._usage_history == []


def test_execute_with_retry_retries_statusless_sdk_connection_errors():
    client = _DummyClient()
    client.max_retries = 3

    calls = []

    class APIConnectionError(Exception):
        status_code = None

    def _func():
        calls.append("called")
        raise APIConnectionError("temporary network failure")

    with pytest.raises(LLMRetryExhaustedError) as exc_info:
        client._execute_with_retry(_func)

    assert calls == ["called", "called", "called"]
    assert isinstance(exc_info.value.last_error, APIConnectionError)


def test_last_request_usage_helpers_prefer_selected_model_usage():
    client = _DummyClient()
    client._set_last_usage_summary(
        {
            "selected_model_usage": {
                "input_tokens": 321,
                "output_tokens": 45,
                "context_window": 16384,
            },
            "top_level_usage": {
                "input_tokens": 111,
                "output_tokens": 22,
            },
        }
    )

    assert client.get_last_request_input_tokens() == 321
    assert client.get_last_request_output_tokens() == 45
    assert client.get_last_request_context_limit() == 16384


def test_last_request_context_limit_falls_back_to_client_setting():
    client = _DummyClient()
    client._set_last_usage_summary(
        {
            "selected_model_usage": {
                "input_tokens": 12,
                "output_tokens": 3,
                "context_window": 0,
            }
        }
    )

    assert client.get_last_request_context_limit() == 8192


def test_safe_chat_call_only_falls_back_for_simple_chat_signatures():
    class _SimpleChatClient:
        def __init__(self):
            self.calls = []

        def chat(self, messages):
            self.calls.append(messages)
            return {"ok": True}

    client = _SimpleChatClient()
    result = safe_chat_call(client, [{"role": "user", "content": "hi"}], temperature=0.1)

    assert result == {"ok": True}
    assert len(client.calls) == 1


def test_safe_chat_call_does_not_swallow_internal_typeerror():
    class _KwargChatClient:
        def __init__(self):
            self.calls = 0

        def chat(self, messages, **kwargs):
            self.calls += 1
            raise TypeError("unexpected keyword argument from downstream parser")

    client = _KwargChatClient()

    with pytest.raises(TypeError, match="unexpected keyword argument from downstream parser"):
        safe_chat_call(client, [{"role": "user", "content": "hi"}], temperature=0.1)

    assert client.calls == 1


def test_openai_provider_uses_configured_context_limit():
    config = LLMConfig(provider="openai", model="glm-4.6")
    assert config.context_limit == 65536


def test_openai_provider_fallback_sets_context_limit(monkeypatch):
    monkeypatch.setattr("llm.client.load_llm_config_from_yaml", lambda config_path=None: {"llm": {"default": {}, "providers": {}}})

    config = LLMConfig(provider="openai", model="")

    assert config.context_limit == 65536


def test_deepseek_provider_fills_missing_context_limit_even_when_yaml_has_base_url(monkeypatch):
    monkeypatch.setattr(
        "llm.client.load_llm_config_from_yaml",
        lambda config_path=None: {
            "llm": {
                "default": {"enable_thinking": True},
                "providers": {
                    "deepseek": {
                        "base_url": "https://yaml.example/v1",
                        "model": "yaml-deepseek",
                        "max_tokens": 8192,
                    }
                },
            }
        },
    )

    config = LLMConfig(provider="deepseek")

    assert config.base_url == "https://yaml.example/v1"
    assert config.model == "yaml-deepseek"
    assert config.max_tokens == 8192
    assert config.context_limit == 131072
    assert config.enable_thinking is True


def test_llm_config_preserves_explicit_enable_thinking_false(monkeypatch):
    monkeypatch.setattr(
        "llm.client.load_llm_config_from_yaml",
        lambda config_path=None: {
            "llm": {
                "default": {"enable_thinking": True},
                "providers": {
                    "deepseek": {
                        "base_url": "https://yaml.example/v1",
                        "model": "yaml-deepseek",
                        "max_tokens": 8192,
                    }
                },
            }
        },
    )

    config = LLMConfig(provider="deepseek", model="explicit-model", enable_thinking=False)

    assert config.enable_thinking is False


def test_llm_config_preserves_explicit_default_values_against_yaml_defaults(monkeypatch):
    monkeypatch.setattr(
        "llm.client.load_llm_config_from_yaml",
        lambda config_path=None: {
            "llm": {
                "default": {
                    "temperature": 0.25,
                    "top_p": 0.4,
                    "timeout": 90,
                    "max_retries": 3,
                    "initial_delay": 2.5,
                    "max_delay": 30.0,
                    "backoff_factor": 1.5,
                    "enable_thinking": True,
                },
                "providers": {
                    "deepseek": {
                        "base_url": "https://yaml.example/v1",
                        "model": "yaml-deepseek",
                        "max_tokens": 8192,
                        "context_limit": 32768,
                    }
                },
            }
        },
    )

    config = LLMConfig(
        provider="deepseek",
        temperature=1.0,
        top_p=0.9,
        max_tokens=0,
        timeout=120,
        context_limit=0,
        max_retries=10,
        initial_delay=1.0,
        max_delay=60.0,
        backoff_factor=2.0,
        enable_thinking=False,
    )

    assert config.temperature == 1.0
    assert config.top_p == 0.9
    assert config.max_tokens == 0
    assert config.timeout == 120
    assert config.context_limit == 0
    assert config.max_retries == 10
    assert config.initial_delay == 1.0
    assert config.max_delay == 60.0
    assert config.backoff_factor == 2.0
    assert config.enable_thinking is False
    assert config.base_url == "https://yaml.example/v1"
    assert config.model == "yaml-deepseek"


def test_load_llm_config_from_yaml_falls_back_for_empty_file(tmp_path):
    config_path = tmp_path / "llm_config.yaml"
    config_path.write_text("", encoding="utf-8")

    config = load_llm_config_from_yaml(config_path)

    assert config["llm"]["default"]["timeout"] == 120
    assert config["llm"]["providers"] == {}


def test_load_llm_config_from_yaml_raises_for_invalid_yaml(tmp_path):
    config_path = tmp_path / "llm_config.yaml"
    config_path.write_text("llm: [\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="Failed to parse LLM config"):
        load_llm_config_from_yaml(config_path)


def test_llm_config_keeps_explicit_api_key_when_provider_yaml_has_env(monkeypatch):
    monkeypatch.setattr(
        "llm.client.load_llm_config_from_yaml",
        lambda config_path=None: {
            "llm": {
                "default": {},
                "providers": {
                    "openai": {
                        "api_key_env": "NY_API_KEY",
                        "base_url": "https://yaml.example/v1",
                        "model": "yaml-model",
                    }
                },
            }
        },
    )
    monkeypatch.setenv("NY_API_KEY", "env-key")

    config = LLMConfig(provider="openai", model="explicit-model", api_key="explicit-key")

    assert config.api_key == "explicit-key"
    assert config.model == "explicit-model"


def test_llm_config_fallback_keeps_explicit_model_and_api_key(monkeypatch):
    monkeypatch.setattr("llm.client.load_llm_config_from_yaml", lambda config_path=None: {"llm": {"default": {}, "providers": {}}})

    config = LLMConfig(provider="openai", model="explicit-model", api_key="explicit-key")

    assert config.api_key == "explicit-key"
    assert config.model == "explicit-model"
    assert config.base_url == "https://ai.nengyongai.cn/v1"


def test_aggregate_usage_summaries_counts_raw_claude_cli_summary_once():
    aggregate = aggregate_usage_summaries(
        [
            {
                "source": "claude_cli",
                "sessions_total": 2,
                "calls_total": 2,
                "selected_model_usage": {
                    "model": "deepseek-chat",
                    "input_tokens": 10,
                    "output_tokens": 20,
                    "cache_read_input_tokens": 0,
                    "cache_creation_input_tokens": 0,
                    "cost_usd": 0.5,
                },
                "session_usage": {
                    "input_tokens": 10,
                    "output_tokens": 20,
                    "cache_read_input_tokens": 0,
                    "cache_creation_input_tokens": 0,
                    "cost_usd": 0.5,
                },
            }
        ]
    )

    assert aggregate["sessions_total"] == 2
    assert aggregate["calls_total"] == 2
    assert aggregate["calls_with_session_usage"] == 1
    assert aggregate["calls_with_selected_model_usage"] == 1
    assert aggregate["calls_missing_usage"] == 0


def test_aggregate_identity_is_not_all_matched_with_unchecked_call():
    aggregate = aggregate_usage_summaries(
        [
            {
                "source": "llm_client",
                "calls_total": 1,
                "response_identity_enforced": True,
                "response_identity_matched": True,
                "request_model_id": "GLM-5.2",
                "expected_response_model_id": "GLM-5.2",
                "observed_response_model_id": "GLM-5.2",
            },
            {"source": "llm_client", "calls_total": 1},
        ]
    )

    assert aggregate["calls_total"] == 2
    assert aggregate["response_identity_checks_total"] == 1
    assert aggregate["calls_without_response_identity_check"] == 1
    assert aggregate["response_identity_all_matched"] is False


def test_openai_client_clamps_zero_max_retries_to_single_attempt(monkeypatch):
    class _FakeOpenAI:
        def __init__(self, api_key=None, base_url=None, max_retries=None):
            self.api_key = api_key
            self.base_url = base_url
            self.max_retries = max_retries

    monkeypatch.setitem(sys.modules, "openai", SimpleNamespace(OpenAI=_FakeOpenAI))
    monkeypatch.setattr("llm.client.load_llm_config_from_yaml", lambda config_path=None: {"llm": {"default": {}, "providers": {}}})

    client = OpenAIClient(LLMConfig(provider="openai", model="glm-4.6", max_retries=0))
    calls = []

    assert client._execute_with_retry(lambda: calls.append("called") or "ok") == "ok"
    assert calls == ["called"]
    assert client.max_retries == 1
    assert client.sdk_max_retries == 0
    assert client.client.max_retries == 0


def test_execute_with_retry_honors_numeric_retry_after(monkeypatch):
    client = _DummyClient()
    client.max_retries = 2
    client.initial_delay = 1.0
    client.max_delay = 60.0
    delays = []
    monkeypatch.setattr("llm.client.time.sleep", delays.append)

    class _RateLimitedError(Exception):
        status_code = 429
        response = SimpleNamespace(headers={"Retry-After": "7"})

    calls = []

    def _func():
        calls.append("called")
        raise _RateLimitedError("rate limited")

    with pytest.raises(LLMRetryExhaustedError):
        client._execute_with_retry(_func)

    assert calls == ["called", "called"]
    assert delays == [7.0]


def test_lab_provider_reads_yaml_defaults_and_env(monkeypatch):
    monkeypatch.setattr(
        "llm.client.load_llm_config_from_yaml",
        lambda config_path=None: {
            "llm": {
                "default": {"enable_thinking": True},
                "providers": {
                    "lab": {
                        "base_url": "https://hkucvm.dynv6.net/v1",
                        "model": "DeepSeek-V3.2",
                        "api_key_env": "LAB_LLM_API_KEY",
                        "max_tokens": 8192,
                        "context_limit": 163840,
                    }
                },
            }
        },
    )
    monkeypatch.setenv("LAB_LLM_API_KEY", "lab-env-key")

    config = LLMConfig(provider="lab")

    assert config.api_key == "lab-env-key"
    assert config.base_url == "https://hkucvm.dynv6.net/v1"
    assert config.model == "DeepSeek-V3.2"
    assert config.max_tokens == 8192
    assert config.context_limit == 163840
    assert config.enable_thinking is True


def test_revision_lab_yaml_matches_verified_deployment():
    config_path = Path(__file__).resolve().parents[1] / "config" / "llm_config.yaml"
    lab = load_llm_config_from_yaml(config_path)["llm"]["providers"]["lab"]

    assert lab == {
        "base_url": "https://llm.shtech.org/v1",
        "base_url_env": "LAB_LLM_API_BASE",
        "model": "GLM-5.2",
        "model_env": "LAB_LLM_MODEL",
        "api_key_env": "LAB_LLM_API_KEY",
        "max_tokens": 32000,
        "context_limit": 200000,
    }


def test_lab_provider_reads_endpoint_and_model_env_overrides(monkeypatch):
    monkeypatch.setattr(
        "llm.client.load_llm_config_from_yaml",
        lambda config_path=None: {
            "llm": {
                "default": {},
                "providers": {
                    "lab": {
                        "base_url": "https://yaml.example/v1",
                        "base_url_env": "LAB_LLM_API_BASE",
                        "model": "yaml-model",
                        "model_env": "LAB_LLM_MODEL",
                        "api_key_env": "LAB_LLM_API_KEY",
                    }
                },
            }
        },
    )
    monkeypatch.setenv("LAB_LLM_API_BASE", "https://fixture.example/v1")
    monkeypatch.setenv("LAB_LLM_MODEL", "fixture-model")
    monkeypatch.setenv("LAB_LLM_API_KEY", "fixture-key")

    config = LLMConfig(provider="lab")

    assert config.base_url == "https://fixture.example/v1"
    assert config.model == "fixture-model"
    assert config.api_key == "fixture-key"


def test_lab_provider_explicit_endpoint_and_model_win_over_env(monkeypatch):
    monkeypatch.setattr(
        "llm.client.load_llm_config_from_yaml",
        lambda config_path=None: {
            "llm": {
                "default": {},
                "providers": {
                    "lab": {
                        "base_url": "https://yaml.example/v1",
                        "base_url_env": "LAB_LLM_API_BASE",
                        "model": "yaml-model",
                        "model_env": "LAB_LLM_MODEL",
                        "api_key_env": "LAB_LLM_API_KEY",
                    }
                },
            }
        },
    )
    monkeypatch.setenv("LAB_LLM_API_BASE", "https://fixture.example/v1")
    monkeypatch.setenv("LAB_LLM_MODEL", "fixture-model")

    config = LLMConfig(
        provider="lab",
        base_url="https://explicit.example/v1",
        model="explicit-model",
    )

    assert config.base_url == "https://explicit.example/v1"
    assert config.model == "explicit-model"


def test_lab_provider_without_fallback_stays_disabled(monkeypatch):
    monkeypatch.setattr(
        "llm.client.load_llm_config_from_yaml",
        lambda config_path=None: {
            "llm": {
                "default": {},
                "providers": {
                    "lab": {
                        "base_url": "https://llm.shtech.org/v1",
                        "model": "GLM-5.2",
                        "api_key_env": "LAB_LLM_API_KEY",
                    }
                },
            }
        },
    )

    config = LLMConfig(provider="lab")

    assert config.fallback_provider is None
    assert config.fallback_on_retry_exhausted is False


def test_lab_provider_loads_fallback_provider_from_yaml(monkeypatch):
    monkeypatch.setattr(
        "llm.client.load_llm_config_from_yaml",
        lambda config_path=None: {
            "llm": {
                "default": {"enable_thinking": True},
                "providers": {
                    "lab": {
                        "base_url": "https://hkucvm.dynv6.net/v1",
                        "model": "DeepSeek-V3.2",
                        "api_key_env": "LAB_LLM_API_KEY",
                        "max_tokens": 8192,
                        "context_limit": 163840,
                        "fallback_provider": "deepseek",
                        "fallback_on_retry_exhausted": True,
                    }
                },
            }
        },
    )

    config = LLMConfig(provider="lab")

    assert config.fallback_provider == "deepseek"
    assert config.fallback_on_retry_exhausted is True


def test_create_llm_client_supports_lab_provider(monkeypatch):
    class _FakeOpenAI:
        def __init__(self, api_key=None, base_url=None, max_retries=None):
            self.api_key = api_key
            self.base_url = base_url
            self.max_retries = max_retries

    monkeypatch.setitem(sys.modules, "openai", SimpleNamespace(OpenAI=_FakeOpenAI))
    monkeypatch.setattr(
        "llm.client.load_llm_config_from_yaml",
        lambda config_path=None: {
            "llm": {
                "default": {},
                "providers": {
                    "lab": {
                        "base_url": "https://hkucvm.dynv6.net/v1",
                        "model": "DeepSeek-V3.2",
                        "api_key_env": "LAB_LLM_API_KEY",
                        "max_tokens": 8192,
                        "context_limit": 163840,
                    }
                },
            }
        },
    )
    monkeypatch.setenv("LAB_LLM_API_KEY", "lab-env-key")

    client = create_llm_client(LLMConfig(provider="lab"))

    assert isinstance(client, OpenAIClient)
    assert client.config.provider == "lab"
    assert client.config.model == "DeepSeek-V3.2"


def test_lab_context_limit_error_retries_with_reduced_max_tokens(monkeypatch):
    monkeypatch.setitem(sys.modules, "openai", SimpleNamespace(OpenAI=_FakeOpenAI))
    monkeypatch.setattr("llm.client.time.sleep", lambda _: None)

    client = _ScriptedClient(
        LLMConfig(
            provider="lab",
            model="lab-model",
            max_tokens=65536,
            context_limit=65536,
            max_retries=2,
            initial_delay=0.0,
            max_delay=0.0,
        ),
        chat_script=[
            RuntimeError(
                "This model's maximum context length is 163840 tokens. "
                "However, you requested 65536 output tokens and your prompt contains "
                "at least 98305 input tokens, for a total of at least 163841 tokens. "
                "Please reduce the length of the input prompt or the number of requested "
                "output tokens. (parameter=input_tokens, value=98305)"
            ),
            "primary-ok",
        ],
    )

    assert client.chat([{"role": "user", "content": "ping"}]) == "primary-ok"
    assert len(client.chat_calls) == 2
    assert client.chat_calls[0]["kwargs"] == {}
    assert client.chat_calls[1]["kwargs"]["max_tokens"] == 63487
    assert client.context_limit == 163840
    assert client.config.context_limit == 163840


def test_lab_retry_exhaustion_uses_deepseek_fallback(monkeypatch):
    monkeypatch.setitem(sys.modules, "openai", SimpleNamespace(OpenAI=_FakeOpenAI))
    monkeypatch.setattr("llm.client.time.sleep", lambda _: None)

    fallback_client = _ScriptedClient(
        LLMConfig(
            provider="deepseek",
            model="deepseek-chat",
            max_retries=1,
            initial_delay=0.0,
            max_delay=0.0,
        ),
        chat_script=["fallback-ok"],
        record_success_usage=True,
    )
    factory_calls = []
    monkeypatch.setattr(
        "llm.client.create_llm_client",
        lambda config: factory_calls.append(config.provider) or fallback_client,
    )

    client = _ScriptedClient(
        LLMConfig(
            provider="lab",
            model="lab-model",
            max_retries=2,
            initial_delay=0.0,
            max_delay=0.0,
            fallback_provider="deepseek",
            fallback_on_retry_exhausted=True,
        ),
        chat_script=[TimeoutError("primary timeout 1"), TimeoutError("primary timeout 2")],
    )
    messages = [{"role": "user", "content": "ping"}]
    tools = [{"type": "function", "function": {"name": "lookup", "parameters": {}}}]

    assert client.chat(messages, tools=tools, temperature=0.25, tool_choice="required") == "fallback-ok"
    assert factory_calls == ["deepseek"]
    assert fallback_client.chat_calls == [
        {
            "messages": messages,
            "tools": tools,
            "kwargs": {
                "temperature": 0.25,
                "tool_choice": "required",
            },
        }
    ]
    summary = client.get_last_usage_summary()
    assert summary["provider"] == "deepseek"
    assert summary["selected_model"] == "deepseek-chat"
    assert summary["fallback_used"] is True
    assert summary["fallback_from_provider"] == "lab"
    assert summary["fallback_to_provider"] == "deepseek"


def test_lab_keyword_retriable_error_uses_fallback(monkeypatch):
    monkeypatch.setitem(sys.modules, "openai", SimpleNamespace(OpenAI=_FakeOpenAI))
    monkeypatch.setattr("llm.client.time.sleep", lambda _: None)

    fallback_client = _ScriptedClient(
        LLMConfig(
            provider="deepseek",
            model="deepseek-chat",
            max_retries=1,
            initial_delay=0.0,
            max_delay=0.0,
        ),
        chat_script=["fallback-ok"],
    )
    factory_calls = []
    monkeypatch.setattr(
        "llm.client.create_llm_client",
        lambda config: factory_calls.append(config.provider) or fallback_client,
    )

    client = _ScriptedClient(
        LLMConfig(
            provider="lab",
            model="lab-model",
            max_retries=1,
            initial_delay=0.0,
            max_delay=0.0,
            fallback_provider="deepseek",
            fallback_on_retry_exhausted=True,
        ),
        chat_script=[RuntimeError("service unavailable")],
    )

    assert client._should_retry(RuntimeError("service unavailable")) is True
    assert client.chat([{"role": "user", "content": "ping"}]) == "fallback-ok"
    assert factory_calls == ["deepseek"]
    assert len(client.chat_calls) == 1
    assert len(fallback_client.chat_calls) == 1


def test_lab_no_result_error_uses_deepseek_fallback_after_retry_exhaustion(monkeypatch):
    monkeypatch.setitem(sys.modules, "openai", SimpleNamespace(OpenAI=_FakeOpenAI))
    monkeypatch.setattr("llm.client.time.sleep", lambda _: None)

    fallback_client = _ScriptedClient(
        LLMConfig(
            provider="deepseek",
            model="deepseek-chat",
            max_retries=1,
            initial_delay=0.0,
            max_delay=0.0,
        ),
        chat_script=["fallback-ok"],
    )
    factory_calls = []
    monkeypatch.setattr(
        "llm.client.create_llm_client",
        lambda config: factory_calls.append(config.provider) or fallback_client,
    )

    client = _ScriptedClient(
        LLMConfig(
            provider="lab",
            model="lab-model",
            max_retries=2,
            initial_delay=0.0,
            max_delay=0.0,
            fallback_provider="deepseek",
            fallback_on_retry_exhausted=True,
        ),
        chat_script=[
            LLMNoResultError("empty response from lab"),
            LLMNoResultError("empty response from lab"),
        ],
    )

    assert client.chat([{"role": "user", "content": "ping"}]) == "fallback-ok"
    assert factory_calls == ["deepseek"]
    assert len(client.chat_calls) == 2
    assert len(fallback_client.chat_calls) == 1


def test_lab_no_result_error_retries_primary_before_fallback(monkeypatch):
    monkeypatch.setitem(sys.modules, "openai", SimpleNamespace(OpenAI=_FakeOpenAI))
    monkeypatch.setattr("llm.client.time.sleep", lambda _: None)

    fallback_client = _ScriptedClient(
        LLMConfig(
            provider="deepseek",
            model="deepseek-chat",
            max_retries=1,
            initial_delay=0.0,
            max_delay=0.0,
        ),
        chat_script=["fallback-ok"],
    )
    factory_calls = []
    monkeypatch.setattr(
        "llm.client.create_llm_client",
        lambda config: factory_calls.append(config.provider) or fallback_client,
    )

    client = _ScriptedClient(
        LLMConfig(
            provider="lab",
            model="lab-model",
            max_retries=3,
            initial_delay=0.0,
            max_delay=0.0,
            fallback_provider="deepseek",
            fallback_on_retry_exhausted=True,
        ),
        chat_script=[
            LLMNoResultError("empty response from lab"),
            LLMNoResultError("empty response from lab"),
            "primary-ok",
        ],
    )

    assert client.chat([{"role": "user", "content": "ping"}]) == "primary-ok"
    assert factory_calls == []
    assert len(client.chat_calls) == 3
    assert len(fallback_client.chat_calls) == 0


def test_lab_parser_value_error_does_not_retry_or_fallback(monkeypatch):
    monkeypatch.setitem(sys.modules, "openai", SimpleNamespace(OpenAI=_FakeOpenAI))
    monkeypatch.setattr("llm.client.time.sleep", lambda _: None)

    fallback_client = _ScriptedClient(
        LLMConfig(
            provider="deepseek",
            model="deepseek-chat",
            max_retries=1,
            initial_delay=0.0,
            max_delay=0.0,
        ),
        chat_script=["fallback-ok"],
    )
    factory_calls = []
    monkeypatch.setattr(
        "llm.client.create_llm_client",
        lambda config: factory_calls.append(config.provider) or fallback_client,
    )

    client = _ScriptedClient(
        LLMConfig(
            provider="lab",
            model="lab-model",
            max_retries=3,
            initial_delay=0.0,
            max_delay=0.0,
            fallback_provider="deepseek",
            fallback_on_retry_exhausted=True,
        ),
        chat_script=[ValueError("expecting value from local parser")],
    )

    with pytest.raises(ValueError, match="expecting value from local parser"):
        client.chat([{"role": "user", "content": "ping"}])

    assert factory_calls == []
    assert len(client.chat_calls) == 1
    assert len(fallback_client.chat_calls) == 0


def test_is_no_result_error_requires_explicit_llm_no_result_signal():
    client = _DummyClient()

    assert client._is_no_result_error(LLMNoResultError("empty response")) is True
    assert client._is_no_result_error(ValueError("no content in local parser")) is False
    assert client._is_no_result_error(json.JSONDecodeError("Expecting value", "", 0)) is False


def test_openai_client_raises_no_result_error_when_choices_missing(monkeypatch):
    class _FakeCompletions:
        @staticmethod
        def create(**_kwargs):
            return SimpleNamespace(choices=[], usage=None, model="lab-model")

    class _FakeChat:
        completions = _FakeCompletions()

    class _FakeOpenAIClient:
        def __init__(self, api_key=None, base_url=None, max_retries=None):
            self.api_key = api_key
            self.base_url = base_url
            self.max_retries = max_retries
            self.chat = _FakeChat()

    monkeypatch.setitem(sys.modules, "openai", SimpleNamespace(OpenAI=_FakeOpenAIClient))
    monkeypatch.setattr("llm.client.load_llm_config_from_yaml", lambda config_path=None: {"llm": {"default": {}, "providers": {}}})

    client = OpenAIClient(LLMConfig(provider="lab", model="lab-model", api_key="k", base_url="https://lab"))

    with pytest.raises(LLMNoResultError, match="no choices"):
        client._make_chat_request([{"role": "user", "content": "ping"}])


def _capturing_openai_sdk(captured, response_model="fixture-model"):
    class _CaptureCompletions:
        @staticmethod
        def create(**kwargs):
            captured.append(dict(kwargs))
            return SimpleNamespace(
                choices=[
                    SimpleNamespace(
                        message=SimpleNamespace(
                            content="ok",
                            tool_calls=None,
                        )
                    )
                ],
                usage=None,
                model=response_model,
                id="fixture-response",
            )

    class _CaptureOpenAI:
        def __init__(self, api_key=None, base_url=None, max_retries=None):
            self.api_key = api_key
            self.base_url = base_url
            self.max_retries = max_retries
            self.chat = SimpleNamespace(
                completions=_CaptureCompletions()
            )

    return _CaptureOpenAI


@pytest.mark.parametrize("response_model", [None, "GLM-5.2-proxy"])
def test_formal_response_model_identity_failure_keeps_usage(
    monkeypatch,
    response_model,
):
    captured = []
    monkeypatch.setitem(
        sys.modules,
        "openai",
        SimpleNamespace(
            OpenAI=_capturing_openai_sdk(captured, response_model)
        ),
    )
    monkeypatch.setattr(
        "llm.client.load_llm_config_from_yaml",
        lambda config_path=None: {"llm": {"default": {}, "providers": {}}},
    )
    client = OpenAIClient(
        LLMConfig(
            provider="lab",
            model="GLM-5.2",
            api_key="fixture-key",
            base_url="https://llm.shtech.org/v1",
            max_retries=1,
            enforce_exact_decoding=True,
        )
    )

    with pytest.raises(LLMNoResultError, match="response.model"):
        client._make_chat_request(
            [{"role": "user", "content": "ping"}]
        )

    usage = client.get_usage_history_since(0)
    assert len(usage) == 1
    assert usage[0]["is_error"] is True
    assert usage[0]["provider"] == "lab"
    assert usage[0]["api_family"] == "openai_compatible"
    assert usage[0]["request_model_id"] == "GLM-5.2"
    assert usage[0]["expected_response_model_id"] == "GLM-5.2"
    assert usage[0]["observed_response_model_id"] == response_model
    assert usage[0]["response_identity_enforced"] is True
    assert usage[0]["response_identity_matched"] is False


def test_formal_response_model_identity_match_is_recorded(monkeypatch):
    captured = []
    monkeypatch.setitem(
        sys.modules,
        "openai",
        SimpleNamespace(
            OpenAI=_capturing_openai_sdk(captured, "GLM-5.2")
        ),
    )
    monkeypatch.setattr(
        "llm.client.load_llm_config_from_yaml",
        lambda config_path=None: {"llm": {"default": {}, "providers": {}}},
    )
    client = OpenAIClient(
        LLMConfig(
            provider="lab",
            model="GLM-5.2",
            api_key="fixture-key",
            base_url="https://llm.shtech.org/v1",
            max_retries=1,
            enforce_exact_decoding=True,
        )
    )

    response = client._make_chat_request(
        [{"role": "user", "content": "ping"}]
    )
    assert response.content == "ok"
    usage = client.get_usage_history_since(0)
    assert len(usage) == 1
    assert usage[0]["is_error"] is False
    assert usage[0]["response_identity_enforced"] is True
    assert usage[0]["response_identity_matched"] is True
    aggregate = client.aggregate_usage_since(0)
    assert aggregate["response_identity_checks_total"] == 1
    assert aggregate["response_identity_matches_total"] == 1
    assert aggregate["response_identity_mismatches_total"] == 0
    assert aggregate["calls_without_response_identity_check"] == 0
    assert aggregate["response_identity_all_matched"] is True
    assert aggregate["expected_response_model_ids"] == ["GLM-5.2"]
    assert aggregate["observed_response_model_ids"] == ["GLM-5.2"]


def test_formal_public_chat_does_not_retry_response_model_mismatch(monkeypatch):
    calls = []

    class _SequenceCompletions:
        def create(self, **kwargs):
            calls.append(kwargs)
            response_model = "GLM-5.2-proxy" if len(calls) == 1 else "GLM-5.2"
            return SimpleNamespace(
                choices=[
                    SimpleNamespace(
                        message=SimpleNamespace(content="ok", tool_calls=None)
                    )
                ],
                usage=None,
                model=response_model,
                id=f"fixture-{len(calls)}",
            )

    class _SequenceOpenAI:
        def __init__(self, api_key=None, base_url=None, max_retries=None):
            del api_key, base_url, max_retries
            self.chat = SimpleNamespace(completions=_SequenceCompletions())

    monkeypatch.setitem(
        sys.modules,
        "openai",
        SimpleNamespace(OpenAI=_SequenceOpenAI),
    )
    monkeypatch.setattr(
        "llm.client.load_llm_config_from_yaml",
        lambda config_path=None: {"llm": {"default": {}, "providers": {}}},
    )
    client = OpenAIClient(
        LLMConfig(
            provider="lab",
            model="GLM-5.2",
            api_key="fixture-key",
            base_url="https://llm.shtech.org/v1",
            max_retries=2,
            enforce_exact_decoding=True,
        )
    )

    with pytest.raises(LLMResponseIdentityError, match="response.model"):
        client.chat([{"role": "user", "content": "ping"}])

    assert len(calls) == 1
    usage = client.get_usage_history_since(0)
    assert len(usage) == 1
    assert usage[0]["observed_response_model_id"] == "GLM-5.2-proxy"
    assert usage[0]["response_identity_matched"] is False
    assert usage[0]["is_error"] is True
    aggregate = client.aggregate_usage_since(0)
    assert aggregate["response_identity_checks_total"] == 1
    assert aggregate["response_identity_matches_total"] == 0
    assert aggregate["response_identity_mismatches_total"] == 1
    assert aggregate["calls_without_response_identity_check"] == 0
    assert aggregate["response_identity_all_matched"] is False
    assert aggregate["expected_response_model_ids"] == ["GLM-5.2"]
    assert aggregate["observed_response_model_ids"] == ["GLM-5.2-proxy"]


@pytest.mark.parametrize(
    ("provider", "client_class"),
    [
        ("openai", OpenAIClient),
        ("lab", OpenAIClient),
        ("deepseek", DeepSeekClient),
    ],
)
def test_null_decoding_fields_are_omitted_from_actual_request(
    monkeypatch,
    provider,
    client_class,
):
    captured = []
    monkeypatch.setitem(
        sys.modules,
        "openai",
        SimpleNamespace(OpenAI=_capturing_openai_sdk(captured)),
    )
    monkeypatch.setattr(
        "llm.client.load_llm_config_from_yaml",
        lambda config_path=None: {
            "llm": {
                "default": {"enable_thinking": True},
                "providers": {},
            }
        },
    )
    config = LLMConfig(
        provider=provider,
        model="fixture-model",
        model_revision="operator-attested-revision-a",
        api_key="fixture-key",
        base_url="https://api.example.invalid/v1",
        temperature=0.0,
        top_p=1.0,
        max_tokens=1024,
        enable_thinking=None,
        reasoning_effort=None,
        service_tier=None,
        enforce_exact_decoding=True,
    )
    client = client_class(config)

    client._make_chat_request([{"role": "user", "content": "ping"}])

    assert config.enable_thinking is None
    assert config.model_revision == "operator-attested-revision-a"
    assert len(captured) == 1
    request = captured[0]
    assert request["temperature"] == 0.0
    assert request["top_p"] == 1.0
    assert request["max_tokens"] == 1024
    assert "reasoning_effort" not in request
    assert "service_tier" not in request
    assert "extra_body" not in request
    assert "model_revision" not in request


@pytest.mark.parametrize("model_revision", ["", " revision-a "])
def test_llm_config_rejects_nonexact_model_revision(model_revision):
    with pytest.raises(ValueError, match="non-empty exact string"):
        LLMConfig(
            provider="lab",
            model="fixture-model",
            model_revision=model_revision,
        )


def test_llm_config_model_revision_preserves_legacy_positional_arguments():
    config = LLMConfig(
        "openai",
        "fixture-model",
        "fixture-key",
        "https://api.example.invalid/v1",
    )

    assert config.provider == "openai"
    assert config.model == "fixture-model"
    assert config.api_key == "fixture-key"
    assert config.base_url == "https://api.example.invalid/v1"
    assert config.model_revision is None


@pytest.mark.parametrize(
    ("provider", "client_class"),
    [
        ("openai", OpenAIClient),
        ("lab", OpenAIClient),
        ("deepseek", DeepSeekClient),
    ],
)
def test_nonnull_decoding_fields_reach_actual_request(
    monkeypatch,
    provider,
    client_class,
):
    captured = []
    monkeypatch.setitem(
        sys.modules,
        "openai",
        SimpleNamespace(OpenAI=_capturing_openai_sdk(captured)),
    )
    monkeypatch.setattr(
        "llm.client.load_llm_config_from_yaml",
        lambda config_path=None: {"llm": {"default": {}, "providers": {}}},
    )
    client = client_class(
        LLMConfig(
            provider=provider,
            model="fixture-model",
            api_key="fixture-key",
            base_url="https://api.example.invalid/v1",
            temperature=0.25,
            top_p=0.75,
            max_tokens=2048,
            enable_thinking=False,
            reasoning_effort="high",
            service_tier="priority",
            enforce_exact_decoding=True,
        )
    )

    client._make_chat_request([{"role": "user", "content": "ping"}])

    request = captured[0]
    assert request["temperature"] == 0.25
    assert request["top_p"] == 0.75
    assert request["max_tokens"] == 2048
    assert request["reasoning_effort"] == "high"
    assert request["service_tier"] == "priority"
    assert request["extra_body"] == {
        "thinking": {"type": "disabled"}
    }


def test_exact_decoding_rejects_per_call_override_before_request(monkeypatch):
    captured = []
    monkeypatch.setitem(
        sys.modules,
        "openai",
        SimpleNamespace(OpenAI=_capturing_openai_sdk(captured)),
    )
    monkeypatch.setattr(
        "llm.client.load_llm_config_from_yaml",
        lambda config_path=None: {"llm": {"default": {}, "providers": {}}},
    )
    client = OpenAIClient(
        LLMConfig(
            provider="openai",
            model="fixture-model",
            api_key="fixture-key",
            base_url="https://api.example.invalid/v1",
            temperature=0.0,
            top_p=1.0,
            max_tokens=1024,
            enable_thinking=None,
            reasoning_effort=None,
            service_tier=None,
            enforce_exact_decoding=True,
        )
    )

    with pytest.raises(
        ValueError,
        match="rejects per-call decoding overrides",
    ):
        client._make_chat_request(
            [{"role": "user", "content": "ping"}],
            temperature=0.5,
        )

    assert captured == []


def test_exact_decoding_rejects_context_limit_adaptation(monkeypatch):
    monkeypatch.setitem(
        sys.modules,
        "openai",
        SimpleNamespace(OpenAI=_FakeOpenAI),
    )
    monkeypatch.setattr("llm.client.time.sleep", lambda _: None)
    context_error = RuntimeError(
        "maximum context length is 163840 tokens; "
        "requested 65536 output tokens; "
        "prompt contains at least 98305 input tokens"
    )
    client = _ScriptedClient(
        LLMConfig(
            provider="lab",
            model="fixture-model",
            max_tokens=65536,
            context_limit=65536,
            max_retries=2,
            initial_delay=0.0,
            max_delay=0.0,
            enforce_exact_decoding=True,
        ),
        chat_script=[context_error, "must-not-run"],
    )

    with pytest.raises(RuntimeError, match="maximum context length"):
        client.chat([{"role": "user", "content": "ping"}])

    assert len(client.chat_calls) == 1
    assert client.context_limit == 65536
    assert client.config.context_limit == 65536


def test_exact_decoding_disables_provider_fallback(monkeypatch):
    monkeypatch.setitem(
        sys.modules,
        "openai",
        SimpleNamespace(OpenAI=_FakeOpenAI),
    )
    monkeypatch.setattr("llm.client.time.sleep", lambda _: None)
    factory_calls = []
    monkeypatch.setattr(
        "llm.client.create_llm_client",
        lambda config: factory_calls.append(config.provider),
    )
    client = _ScriptedClient(
        LLMConfig(
            provider="lab",
            model="fixture-model",
            max_retries=1,
            initial_delay=0.0,
            max_delay=0.0,
            fallback_provider="deepseek",
            fallback_on_retry_exhausted=True,
            enforce_exact_decoding=True,
        ),
        chat_script=[TimeoutError("primary timeout")],
    )

    with pytest.raises(LLMRetryExhaustedError):
        client.chat([{"role": "user", "content": "ping"}])

    assert factory_calls == []


def test_exact_decoding_retry_recovers_without_parameter_drift(monkeypatch):
    monkeypatch.setitem(
        sys.modules,
        "openai",
        SimpleNamespace(OpenAI=_FakeOpenAI),
    )
    monkeypatch.setattr("llm.client.time.sleep", lambda _: None)
    client = _ScriptedClient(
        LLMConfig(
            provider="lab",
            model="GLM-5.2",
            temperature=0.1,
            top_p=0.9,
            max_tokens=32000,
            context_limit=200000,
            timeout=120.0,
            max_retries=3,
            initial_delay=0.0,
            max_delay=0.0,
            fallback_on_retry_exhausted=False,
            enforce_exact_decoding=True,
        ),
        chat_script=[TimeoutError("temporary timeout"), "ok"],
    )
    request_kwargs = {
        "temperature": 0.1,
        "top_p": 0.9,
        "max_tokens": 32000,
    }

    result = client.chat(
        [{"role": "user", "content": "ping"}],
        **request_kwargs,
    )

    assert result == "ok"
    assert len(client.chat_calls) == 2
    assert client.chat_calls[0]["kwargs"] == request_kwargs
    assert client.chat_calls[1]["kwargs"] == request_kwargs


def test_exact_decoding_allows_equal_per_call_values(monkeypatch):
    captured = []
    monkeypatch.setitem(
        sys.modules,
        "openai",
        SimpleNamespace(OpenAI=_capturing_openai_sdk(captured)),
    )
    monkeypatch.setattr(
        "llm.client.load_llm_config_from_yaml",
        lambda config_path=None: {"llm": {"default": {}, "providers": {}}},
    )
    client = OpenAIClient(
        LLMConfig(
            provider="openai",
            model="fixture-model",
            api_key="fixture-key",
            base_url="https://api.example.invalid/v1",
            temperature=0.0,
            top_p=1.0,
            max_tokens=1024,
            enable_thinking=None,
            reasoning_effort=None,
            service_tier=None,
            enforce_exact_decoding=True,
        )
    )

    client._make_chat_request(
        [{"role": "user", "content": "ping"}],
        temperature=0.0,
        top_p=1.0,
        max_tokens=1024,
        enable_thinking=None,
        reasoning_effort=None,
        service_tier=None,
    )

    assert len(captured) == 1
    request = captured[0]
    assert request["temperature"] == 0.0
    assert request["top_p"] == 1.0
    assert request["max_tokens"] == 1024
    assert "reasoning_effort" not in request
    assert "service_tier" not in request
    assert "extra_body" not in request


@pytest.mark.parametrize(
    "override",
    [
        {"temperature": False},
        {"temperature": -0.0},
        {"top_p": 1},
        {"max_tokens": 1024.0},
    ],
)
def test_exact_decoding_rejects_type_and_signed_zero_confusion(
    monkeypatch,
    override,
):
    captured = []
    monkeypatch.setitem(
        sys.modules,
        "openai",
        SimpleNamespace(OpenAI=_capturing_openai_sdk(captured)),
    )
    monkeypatch.setattr(
        "llm.client.load_llm_config_from_yaml",
        lambda config_path=None: {"llm": {"default": {}, "providers": {}}},
    )
    client = OpenAIClient(
        LLMConfig(
            provider="openai",
            model="fixture-model",
            api_key="fixture-key",
            base_url="https://api.example.invalid/v1",
            temperature=0.0,
            top_p=1.0,
            max_tokens=1024,
            enable_thinking=None,
            reasoning_effort=None,
            service_tier=None,
            enforce_exact_decoding=True,
        )
    )

    with pytest.raises(
        ValueError,
        match="rejects per-call decoding overrides",
    ):
        client._make_chat_request(
            [{"role": "user", "content": "ping"}],
            **override,
        )

    assert captured == []
