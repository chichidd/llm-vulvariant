import json
import sys
from types import SimpleNamespace

import pytest

from llm.client import (
    BaseLLMClient,
    LLMConfig,
    LLMNoResultError,
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
    def __init__(self, api_key=None, base_url=None):
        self.api_key = api_key
        self.base_url = base_url


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


def test_openai_client_clamps_zero_max_retries_to_single_attempt(monkeypatch):
    class _FakeOpenAI:
        def __init__(self, api_key=None, base_url=None):
            self.api_key = api_key
            self.base_url = base_url

    monkeypatch.setitem(sys.modules, "openai", SimpleNamespace(OpenAI=_FakeOpenAI))
    monkeypatch.setattr("llm.client.load_llm_config_from_yaml", lambda config_path=None: {"llm": {"default": {}, "providers": {}}})

    client = OpenAIClient(LLMConfig(provider="openai", model="glm-4.6", max_retries=0))
    calls = []

    assert client._execute_with_retry(lambda: calls.append("called") or "ok") == "ok"
    assert calls == ["called"]
    assert client.max_retries == 1


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
                        "max_tokens": 65536,
                        "context_limit": 65536,
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
    assert config.max_tokens == 65536
    assert config.context_limit == 65536
    assert config.enable_thinking is True


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
                        "max_tokens": 65536,
                        "context_limit": 65536,
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
        def __init__(self, api_key=None, base_url=None):
            self.api_key = api_key
            self.base_url = base_url

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
                        "max_tokens": 65536,
                        "context_limit": 65536,
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
        def __init__(self, api_key=None, base_url=None):
            self.api_key = api_key
            self.base_url = base_url
            self.chat = _FakeChat()

    monkeypatch.setitem(sys.modules, "openai", SimpleNamespace(OpenAI=_FakeOpenAIClient))
    monkeypatch.setattr("llm.client.load_llm_config_from_yaml", lambda config_path=None: {"llm": {"default": {}, "providers": {}}})

    client = OpenAIClient(LLMConfig(provider="lab", model="lab-model", api_key="k", base_url="https://lab"))

    with pytest.raises(LLMNoResultError, match="no choices"):
        client._make_chat_request([{"role": "user", "content": "ping"}])
