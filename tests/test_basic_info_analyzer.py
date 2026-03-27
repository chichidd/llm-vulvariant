import json
from types import SimpleNamespace

from profiler.profile_storage import ProfileStorageManager
from profiler.software.basic_info_analyzer import BasicInfoAnalyzer
from profiler.software.prompts import BASIC_INFO_PROMPT
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
                    "capabilities": ["model training orchestration"],
                    "interfaces": ["CLI"],
                    "deployment_style": ["self-hosted"],
                    "operator_inputs": ["training config"],
                    "external_surfaces": ["command line arguments"],
                    "evidence_summary": "README documents a CLI workflow for launching training jobs.",
                    "confidence": "high",
                    "open_questions": ["Does the repo also expose a web dashboard?"],
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
    assert result["capabilities"] == ["model training orchestration"]
    assert result["interfaces"] == ["CLI"]
    assert result["deployment_style"] == ["self-hosted"]
    assert result["operator_inputs"] == ["training config"]
    assert result["external_surfaces"] == ["command line arguments"]
    assert result["evidence_summary"] == "README documents a CLI workflow for launching training jobs."
    assert result["confidence"] == "high"
    assert result["open_questions"] == ["Does the repo also expose a web dashboard?"]
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
    assert saved["parsed_result"]["capabilities"] == ["model training orchestration"]
    assert saved["parsed_result"]["external_surfaces"] == ["command line arguments"]


def test_basic_info_analyzer_rejects_semantically_invalid_payload(tmp_path):
    class _InvalidPayloadLLMClient(_TrackedLLMClient):
        def chat(self, messages, **kwargs):
            super().chat(messages, **kwargs)
            return _Response(
                json.dumps(
                    {
                        "description": "   ",
                        "target_application": ["training"],
                        "target_user": ["researcher"],
                        "capabilities": ["   "],
                        "interfaces": ["CLI"],
                        "deployment_style": ["self-hosted"],
                        "operator_inputs": ["training config"],
                        "external_surfaces": ["command line arguments"],
                        "evidence_summary": "",
                        "confidence": "unknown",
                        "open_questions": [""],
                    }
                )
            )

    storage_manager = ProfileStorageManager(base_dir=tmp_path, profile_type="software")
    analyzer = BasicInfoAnalyzer(llm_client=_InvalidPayloadLLMClient())

    result = analyzer.analyze(
        repo_path=tmp_path / "repo",
        repo_info={"readme_content": "demo", "config_files": []},
        repo_name="repo",
        version="abc123",
        storage_manager=storage_manager,
    )

    assert "description" not in result
    assert result["llm_calls"] == 1
    assert result["llm_usage"]["input_tokens"] == 12
    assert not (tmp_path / "repo" / "abc123" / "conversations" / "basic_info" / "basic_info.json").exists()


def test_basic_info_analyzer_allows_empty_evidence_backed_optional_lists(tmp_path):
    class _OptionalEmptyListsLLMClient(_TrackedLLMClient):
        def chat(self, messages, **kwargs):
            super().chat(messages, **kwargs)
            return _Response(
                json.dumps(
                    {
                        "description": "demo",
                        "target_application": ["training"],
                        "target_user": ["researcher"],
                        "capabilities": ["model training orchestration"],
                        "interfaces": [],
                        "deployment_style": [],
                        "operator_inputs": [],
                        "external_surfaces": [],
                        "evidence_summary": "README documents a training workflow but does not confirm external interfaces.",
                        "confidence": "medium",
                        "open_questions": [],
                    }
                )
            )

    analyzer = BasicInfoAnalyzer(llm_client=_OptionalEmptyListsLLMClient())

    result = analyzer.analyze(
        repo_path=tmp_path / "repo",
        repo_info={"readme_content": "demo", "config_files": []},
        repo_name="repo",
        version="abc123",
    )

    assert result["interfaces"] == []
    assert result["deployment_style"] == []
    assert result["operator_inputs"] == []
    assert result["external_surfaces"] == []
    assert result["confidence"] == "medium"


def test_basic_info_prompt_allows_empty_evidence_backed_optional_lists():
    assert "return [] rather than guessing." in BASIC_INFO_PROMPT
    assert "`interfaces`, `deployment_style`, `operator_inputs`, `external_surfaces`, or `open_questions`" in BASIC_INFO_PROMPT
    assert "## 5. Interfaces (interfaces)" in BASIC_INFO_PROMPT
    assert "## 6. Deployment style (deployment_style)" in BASIC_INFO_PROMPT
    assert "## 7. Operator inputs (operator_inputs)" in BASIC_INFO_PROMPT
    assert "## 8. External surfaces (external_surfaces)" in BASIC_INFO_PROMPT
    assert "## 11. Open questions (open_questions)" in BASIC_INFO_PROMPT
