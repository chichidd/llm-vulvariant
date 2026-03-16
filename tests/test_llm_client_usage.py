import sys
from types import SimpleNamespace

import pytest

from llm.client import (
    BaseLLMClient,
    LLMConfig,
    OpenAIClient,
    build_empty_llm_usage_summary,
    create_llm_client,
    load_llm_config_from_yaml,
    summarize_chat_completion_usage,
)


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


def test_openai_provider_uses_configured_context_limit():
    config = LLMConfig(provider="openai", model="glm-4.6")
    assert config.context_limit == 65536


def test_openai_provider_fallback_sets_context_limit(monkeypatch):
    monkeypatch.setattr("llm.client.load_llm_config_from_yaml", lambda config_path=None: {"llm": {"default": {}, "providers": {}}})

    config = LLMConfig(provider="openai", model="")

    assert config.context_limit == 65536


def test_load_llm_config_from_yaml_falls_back_for_empty_file(tmp_path):
    config_path = tmp_path / "llm_config.yaml"
    config_path.write_text("", encoding="utf-8")

    config = load_llm_config_from_yaml(config_path)

    assert config["llm"]["default"]["timeout"] == 120
    assert config["llm"]["providers"] == {}


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


def test_create_llm_client_rejects_removed_lab_provider():
    with pytest.raises(ValueError, match="Unknown LLM provider: lab"):
        create_llm_client(LLMConfig(provider="lab", model="custom-lab-model"))
