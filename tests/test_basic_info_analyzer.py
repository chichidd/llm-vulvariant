import json
from types import SimpleNamespace

from profiler.profile_storage import ProfileStorageManager
from profiler.software.basic_info_analyzer import BasicInfoAnalyzer
from utils.claude_cli import aggregate_usage_summaries


class _Response:
    def __init__(self, content):
        self.content = content


class _TrackedLLMClient:
    def __init__(self):
        self.config = SimpleNamespace(model="deepseek-chat", provider="deepseek")
        self._usage_history = []

    def usage_history_snapshot(self):
        return len(self._usage_history)

    def aggregate_usage_since(self, snapshot):
        summary = aggregate_usage_summaries(
            self._usage_history[snapshot:],
            selected_model=self.config.model,
        )
        summary["source"] = "llm_client"
        summary["provider"] = self.config.provider
        return summary

    def chat(self, messages, **kwargs):
        assert messages
        self._usage_history.append(
            {
                "source": "llm_client",
                "provider": self.config.provider,
                "requested_model": self.config.model,
                "selected_model": self.config.model,
                "selected_model_found": True,
                "selected_model_reason": "requested_model",
                "available_models": [self.config.model],
                "selected_model_usage": {
                    "model": self.config.model,
                    "selection_reason": "requested_model",
                    "input_tokens": 12,
                    "output_tokens": 34,
                    "cache_read_input_tokens": 56,
                    "cache_creation_input_tokens": 0,
                    "web_search_requests": 0,
                    "cost_usd": 0.0,
                    "context_window": 0,
                },
                "top_level_usage": {
                    "input_tokens": 12,
                    "output_tokens": 34,
                    "cache_read_input_tokens": 56,
                    "cache_creation_input_tokens": 0,
                },
                "total_cost_usd": 0.0,
                "is_error": False,
                "subtype": None,
            }
        )
        return _Response(
            json.dumps(
                {
                    "description": "demo",
                    "target_application": ["training"],
                    "target_user": ["researcher"],
                }
            )
        )


def test_basic_info_analyzer_records_llm_usage(tmp_path):
    storage_manager = ProfileStorageManager(base_dir=tmp_path, profile_type="software")
    analyzer = BasicInfoAnalyzer(llm_client=_TrackedLLMClient())

    result = analyzer.analyze(
        repo_path=tmp_path / "repo",
        repo_info={"readme_content": "demo", "config_files": []},
        repo_name="repo",
        version="abc123",
        storage_manager=storage_manager,
    )

    assert result["description"] == "demo"
    assert result["llm_calls"] == 1
    assert result["llm_usage"]["input_tokens"] == 12
    assert result["llm_usage"]["output_tokens"] == 34

    saved = json.loads(
        (tmp_path / "repo" / "abc123" / "conversations" / "basic_info" / "basic_info.json").read_text(
            encoding="utf-8"
        )
    )
    assert saved["llm_usage"]["calls_total"] == 1
    assert saved["llm_usage"]["input_tokens"] == 12
