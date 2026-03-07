import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from profiler.software.analyzer import SoftwareProfiler
from profiler.software.models import SoftwareProfile
from profiler.software.module_analyzer import ModuleAnalyzer as AgentModuleAnalyzer
from profiler.software.module_analyzer.base import run_agent_analysis
from profiler.software.module_analyzer.skill import SkillModuleAnalyzer
from profiler.software import analyzer as analyzer_module


class StubStorageManager:
    def __init__(self, *, final_result=None, checkpoints=None, conversations=None):
        self.final_result = final_result
        self.checkpoints = checkpoints or {}
        self.conversations = conversations or {}
        self.saved_checkpoints = {}
        self.saved_results = {}
        self.saved_conversations = {}

    def load_final_result(self, filename, *path_parts):
        return self.final_result

    def load_checkpoint(self, checkpoint_name, *path_parts):
        return self.checkpoints.get(checkpoint_name)

    def save_checkpoint(self, checkpoint_name, data, *path_parts):
        self.saved_checkpoints[checkpoint_name] = data

    def save_final_result(self, filename, content, *path_parts):
        self.saved_results[filename] = json.loads(content)

    def load_conversation(self, conversation_type, *path_parts):
        return self.conversations.get(conversation_type)

    def save_conversation(self, conversation_type, data, *path_parts, file_identifier=None):
        self.saved_conversations[conversation_type] = data


def _stub_profiler(storage_manager):
    profiler = SoftwareProfiler.__new__(SoftwareProfiler)
    profiler.storage_manager = storage_manager
    profiler.output_dir = None
    profiler._save_config_to_output_dir = lambda: None
    return profiler


def _stub_git(monkeypatch, commit="abc123"):
    monkeypatch.setattr(analyzer_module, "has_uncommitted_changes", lambda _repo: False)
    monkeypatch.setattr(analyzer_module, "get_git_commit", lambda _repo: commit)
    monkeypatch.setattr(analyzer_module, "get_git_restore_target", lambda _repo: commit)
    monkeypatch.setattr(analyzer_module, "checkout_commit", lambda _repo, _target: True)
    monkeypatch.setattr(analyzer_module, "restore_git_position", lambda _repo, _target: True)


def test_generate_profile_loads_cached_final_result(tmp_path, monkeypatch):
    repo_dir = tmp_path / "demo"
    repo_dir.mkdir()
    _stub_git(monkeypatch)

    cached_profile = {
        "basic_info": {"name": "demo", "version": "abc123", "description": "cached"},
        "repo_info": {"files": ["app.py"]},
        "modules": [],
    }
    profiler = _stub_profiler(StubStorageManager(final_result=json.dumps(cached_profile)))
    profiler._generate_profile_full = lambda *args, **kwargs: pytest.fail("full analysis should not run")

    profile = profiler.generate_profile(str(repo_dir))

    assert isinstance(profile, SoftwareProfile)
    assert profile.description == "cached"


def test_generate_profile_force_regenerate_bypasses_cached_final_result(tmp_path, monkeypatch):
    repo_dir = tmp_path / "demo"
    repo_dir.mkdir()
    _stub_git(monkeypatch)

    cached_profile = {
        "basic_info": {"name": "demo", "version": "abc123", "description": "cached"},
        "repo_info": {"files": ["app.py"]},
        "modules": [],
    }
    profiler = _stub_profiler(StubStorageManager(final_result=json.dumps(cached_profile)))

    regenerated = SoftwareProfile(name="demo", version="abc123", description="regenerated")
    profiler._generate_profile_full = lambda *args, **kwargs: regenerated

    profile = profiler.generate_profile(str(repo_dir), force_regenerate=True)

    assert profile is regenerated


def test_generate_profile_full_reuses_saved_checkpoints():
    checkpoints = {
        "repo_info": {
            "files": ["app.py"],
            "repo_analysis": None,
        },
        "basic_info": {
            "description": "from-checkpoint",
            "target_application": ["inference"],
            "target_user": ["developer"],
        },
        "modules": {
            "modules": [{"name": "api", "files": ["app.py"]}],
        },
    }
    storage_manager = StubStorageManager(checkpoints=checkpoints)
    profiler = _stub_profiler(storage_manager)

    def _unexpected(*args, **kwargs):
        raise AssertionError("checkpointed analysis should not rerun")

    profiler.repo_collector = type("RepoCollector", (), {"collect": _unexpected})()
    profiler.basic_info_analyzer = type("BasicInfoAnalyzer", (), {"analyze": _unexpected})()
    profiler.module_analyzer = type("ModuleAnalyzer", (), {"analyze": _unexpected})()

    profile = profiler._generate_profile_full(Path("/tmp/demo"), "demo", "abc123")

    assert profile.description == "from-checkpoint"
    assert profile.repo_info == {"files": ["app.py"], "repo_analysis": None}


def test_generate_profile_full_reruns_incomplete_basic_info_checkpoint():
    checkpoints = {
        "repo_info": {
            "files": ["app.py"],
            "repo_analysis": None,
        },
        "basic_info": {
            "llm_calls": 1,
            "llm_usage": {"calls_total": 1, "input_tokens": 5, "output_tokens": 6},
        },
        "modules": {
            "modules": [{"name": "api", "files": ["app.py"]}],
        },
    }
    storage_manager = StubStorageManager(checkpoints=checkpoints)
    profiler = _stub_profiler(storage_manager)

    profiler.repo_collector = type("RepoCollector", (), {"collect": lambda *_args, **_kwargs: pytest.fail("repo collection should not rerun")})()
    profiler.module_analyzer = type("ModuleAnalyzer", (), {"analyze": lambda *_args, **_kwargs: pytest.fail("module analysis should not rerun")})()

    basic_info_calls = []

    class RecordingBasicInfoAnalyzer:
        def analyze(self, *_args, **_kwargs):
            basic_info_calls.append(True)
            return {
                "description": "fresh description",
                "target_application": ["training"],
                "target_user": ["researcher"],
                "llm_calls": 1,
                "llm_usage": {
                    "source": "llm_client",
                    "requested_model": "deepseek-chat",
                    "selected_model": "deepseek-chat",
                    "selected_models": ["deepseek-chat"],
                    "calls_total": 1,
                    "calls_with_selected_model_usage": 1,
                    "calls_with_top_level_usage_fallback": 0,
                    "calls_missing_selected_model_usage": 0,
                    "calls_missing_usage": 0,
                    "input_tokens": 10,
                    "output_tokens": 20,
                    "cache_read_input_tokens": 0,
                    "cache_creation_input_tokens": 0,
                    "cost_usd": 0.0,
                    "request_cost_usd": 0.0,
                },
            }

    profiler.basic_info_analyzer = RecordingBasicInfoAnalyzer()

    profile = profiler._generate_profile_full(Path("/tmp/demo"), "demo", "abc123")

    assert basic_info_calls == [True]
    assert profile.description == "fresh description"
    assert storage_manager.saved_checkpoints["basic_info"]["description"] == "fresh description"


def test_generate_profile_full_does_not_persist_incomplete_basic_info_result():
    storage_manager = StubStorageManager(
        checkpoints={
            "repo_info": {
                "files": ["app.py"],
                "repo_analysis": None,
            }
        }
    )
    profiler = _stub_profiler(storage_manager)
    profiler.basic_info_analyzer = type(
        "BasicInfoAnalyzer",
        (),
        {
            "analyze": lambda _self, *_args, **_kwargs: {
                "llm_calls": 1,
                "llm_usage": {
                    "source": "llm_client",
                    "requested_model": "deepseek-chat",
                    "selected_model": "deepseek-chat",
                    "selected_models": ["deepseek-chat"],
                    "calls_total": 1,
                    "calls_with_selected_model_usage": 1,
                    "calls_with_top_level_usage_fallback": 0,
                    "calls_missing_selected_model_usage": 0,
                    "calls_missing_usage": 0,
                    "input_tokens": 7,
                    "output_tokens": 8,
                    "cache_read_input_tokens": 0,
                    "cache_creation_input_tokens": 0,
                    "cost_usd": 0.0,
                    "request_cost_usd": 0.0,
                },
            }
        },
    )()
    profiler.module_analyzer = type(
        "SkillModuleAnalyzer",
        (),
        {"analyze": lambda _self, **_kwargs: {"modules": [], "llm_calls": 0}},
    )()

    profile = profiler._generate_profile_full(Path("/tmp/demo"), "demo", "abc123")

    assert profile.description == ""
    assert "basic_info" not in storage_manager.saved_checkpoints
    assert profile.metadata["llm_calls"] == 1
    assert profile.metadata["llm_usage_summary"]["calls_total"] == 1
    assert profile.metadata["llm_usage_summary"]["input_tokens"] == 7


def test_force_regenerate_rebuilds_repo_analyzer_cache(monkeypatch):
    storage_manager = StubStorageManager()
    profiler = _stub_profiler(storage_manager)
    profiler.repo_analyzer_config = {"languages": ["python"], "rebuild_cache": False}
    profiler.repo_collector = type("RepoCollector", (), {"collect": lambda _self, _repo_path: {"files": ["app.py"]}})()
    profiler.basic_info_analyzer = type(
        "BasicInfoAnalyzer",
        (),
        {"analyze": lambda _self, *_args, **_kwargs: {"description": "", "target_application": [], "target_user": []}},
    )()
    profiler.module_analyzer = type(
        "SkillModuleAnalyzer",
        (),
        {"analyze": lambda _self, **_kwargs: {"modules": [], "llm_calls": 0}},
    )()
    profiler._extract_data_flow_patterns = lambda *_args, **_kwargs: []
    profiler._extract_project_level_features = lambda *_args, **_kwargs: {}

    captured = {}

    class RecordingRepoAnalyzer:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        def get_info(self):
            return None

    monkeypatch.setattr(analyzer_module, "RepoAnalyzer", RecordingRepoAnalyzer)

    profiler._generate_profile_full(Path("/tmp/demo"), "demo", "abc123", force_regenerate=True)

    assert captured["rebuild_cache"] is True


def test_force_regenerate_disables_agent_conversation_resume(monkeypatch):
    storage_manager = StubStorageManager()
    profiler = _stub_profiler(storage_manager)
    profiler.repo_analyzer_config = {"languages": ["python"], "rebuild_cache": False}
    profiler.repo_collector = type("RepoCollector", (), {"collect": lambda _self, _repo_path: {"files": ["app.py"]}})()
    profiler.basic_info_analyzer = type(
        "BasicInfoAnalyzer",
        (),
        {"analyze": lambda _self, *_args, **_kwargs: {"description": "", "target_application": [], "target_user": []}},
    )()
    profiler._extract_data_flow_patterns = lambda *_args, **_kwargs: []
    profiler._extract_project_level_features = lambda *_args, **_kwargs: {}

    class RecordingRepoAnalyzer:
        def __init__(self, **kwargs):
            pass

        def get_info(self):
            return None

    class RecordingModuleAnalyzer(AgentModuleAnalyzer):
        def __init__(self):
            super().__init__(llm_client=None, max_iterations=1)
            self.calls = []

        def analyze(self, **kwargs):
            self.calls.append(kwargs)
            return {"modules": [], "llm_calls": 0}

    monkeypatch.setattr(analyzer_module, "RepoAnalyzer", RecordingRepoAnalyzer)
    profiler.module_analyzer = RecordingModuleAnalyzer()

    profiler._generate_profile_full(Path("/tmp/demo"), "demo", "abc123", force_regenerate=True)

    assert profiler.module_analyzer.calls
    assert profiler.module_analyzer.calls[0]["resume_from_conversation"] is False


def test_force_regenerate_propagates_to_skill_module_analyzer(monkeypatch):
    storage_manager = StubStorageManager()
    profiler = _stub_profiler(storage_manager)
    profiler.repo_analyzer_config = {"languages": ["python"], "rebuild_cache": False}
    profiler.repo_collector = type("RepoCollector", (), {"collect": lambda _self, _repo_path: {"files": ["app.py"]}})()
    profiler.basic_info_analyzer = type(
        "BasicInfoAnalyzer",
        (),
        {"analyze": lambda _self, *_args, **_kwargs: {"description": "", "target_application": [], "target_user": []}},
    )()
    profiler._extract_data_flow_patterns = lambda *_args, **_kwargs: []
    profiler._extract_project_level_features = lambda *_args, **_kwargs: {}

    class RecordingRepoAnalyzer:
        def __init__(self, **kwargs):
            pass

        def get_info(self):
            return None

    class RecordingSkillModuleAnalyzer(SkillModuleAnalyzer):
        def __init__(self):
            super().__init__(llm_client=None)
            self.calls = []
            self.taxonomy = {"coarse": {"fine": {}}}

        def analyze(self, **kwargs):
            self.calls.append(kwargs)
            return {"modules": [], "llm_calls": 0}

    monkeypatch.setattr(analyzer_module, "RepoAnalyzer", RecordingRepoAnalyzer)
    profiler.module_analyzer = RecordingSkillModuleAnalyzer()

    profiler._generate_profile_full(Path("/tmp/demo"), "demo", "abc123", force_regenerate=True)

    assert profiler.module_analyzer.calls
    assert profiler.module_analyzer.calls[0]["force_regenerate"] is True


def test_generate_profile_full_persists_llm_usage_metadata():
    storage_manager = StubStorageManager(
        checkpoints={
            "repo_info": {
                "files": ["app.py"],
                "repo_analysis": None,
            }
        }
    )
    profiler = _stub_profiler(storage_manager)
    profiler.basic_info_analyzer = type(
        "BasicInfoAnalyzer",
        (),
        {
            "analyze": lambda _self, *_args, **_kwargs: {
                "description": "demo",
                "target_application": ["training"],
                "target_user": ["researcher"],
                "llm_calls": 1,
                "llm_usage": {
                    "source": "llm_client",
                    "requested_model": "deepseek-chat",
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
                    "cache_creation_input_tokens": 0,
                    "cost_usd": 0.0,
                    "request_cost_usd": 0.0,
                },
            }
        },
    )()
    profiler.module_analyzer = type(
        "SkillModuleAnalyzer",
        (),
        {
            "analyze": lambda _self, **_kwargs: {
                "modules": [],
                "llm_calls": 1,
                "llm_usage": {
                    "source": "claude_cli",
                    "requested_model": None,
                    "calls_total": 1,
                    "selected_model": "deepseek-chat",
                    "selected_model_found": True,
                    "selected_model_reason": "single_available_model",
                    "available_models": ["deepseek-chat"],
                    "selected_model_usage": {
                        "model": "deepseek-chat",
                        "selection_reason": "single_available_model",
                        "input_tokens": 3,
                        "output_tokens": 4,
                        "cache_read_input_tokens": 5,
                        "cache_creation_input_tokens": 0,
                        "web_search_requests": 0,
                        "cost_usd": 0.0,
                        "context_window": 0,
                    },
                    "top_level_usage": {
                        "input_tokens": 3,
                        "output_tokens": 4,
                        "cache_read_input_tokens": 5,
                        "cache_creation_input_tokens": 0,
                    },
                    "total_cost_usd": 0.0,
                    "is_error": False,
                    "subtype": "success",
                },
                "claude_cli_record_path": "/tmp/claude_cli_invocation.json",
            }
        },
    )()

    profile = profiler._generate_profile_full(Path("/tmp/demo"), "demo", "abc123")

    assert profile.metadata["llm_calls"] == 2
    assert profile.metadata["llm_usage_summary"]["source"] == "llm_usage"
    assert "provider" not in profile.metadata["llm_usage_summary"]
    assert profile.metadata["llm_usage_summary"]["calls_total"] == 2
    assert profile.metadata["llm_usage_summary"]["input_tokens"] == 13
    assert profile.metadata["llm_usage_summary"]["output_tokens"] == 24
    saved = storage_manager.saved_results["software_profile.json"]
    assert saved["metadata"]["llm_calls"] == 2
    assert saved["metadata"]["module_analysis_record_path"] == "/tmp/claude_cli_invocation.json"


def test_generate_profile_full_normalizes_missing_basic_info_usage_before_merge():
    storage_manager = StubStorageManager(
        checkpoints={
            "repo_info": {
                "files": ["app.py"],
                "repo_analysis": None,
            }
        }
    )
    profiler = _stub_profiler(storage_manager)
    profiler.llm_client = type(
        "LLMClientStub",
        (),
        {
            "config": type("Config", (), {"model": "deepseek-chat", "provider": "deepseek"})(),
        },
    )()
    profiler.basic_info_analyzer = type(
        "BasicInfoAnalyzer",
        (),
        {
            "analyze": lambda _self, *_args, **_kwargs: {
                "description": "demo",
                "target_application": ["training"],
                "target_user": ["researcher"],
                "llm_calls": 1,
            }
        },
    )()

    class RecordingAgentModuleAnalyzer(AgentModuleAnalyzer):
        def __init__(self):
            super().__init__(llm_client=None, max_iterations=2)

        def analyze(self, **_kwargs):
            return {
                "modules": [],
                "llm_calls": 1,
                "llm_usage": {
                    "source": "llm_client",
                    "provider": "deepseek",
                    "requested_model": "deepseek-chat",
                    "selected_model": "deepseek-chat",
                    "selected_models": ["deepseek-chat"],
                    "calls_total": 1,
                    "calls_with_selected_model_usage": 1,
                    "calls_with_top_level_usage_fallback": 0,
                    "calls_missing_selected_model_usage": 0,
                    "calls_missing_usage": 0,
                    "input_tokens": 3,
                    "output_tokens": 4,
                    "cache_read_input_tokens": 0,
                    "cache_creation_input_tokens": 0,
                    "cost_usd": 0.0,
                    "request_cost_usd": 0.0,
                },
            }

    profiler.module_analyzer = RecordingAgentModuleAnalyzer()

    profile = profiler._generate_profile_full(Path("/tmp/demo"), "demo", "abc123")

    basic_info_usage = profile.metadata["llm_usage_by_stage"]["basic_info"]
    total_usage = profile.metadata["llm_usage_summary"]
    assert basic_info_usage["source"] == "llm_client"
    assert basic_info_usage["provider"] == "deepseek"
    assert basic_info_usage["requested_model"] == "deepseek-chat"
    assert basic_info_usage["calls_total"] == 1
    assert basic_info_usage["calls_missing_usage"] == 1
    assert total_usage["source"] == "llm_usage"
    assert total_usage["provider"] == "deepseek"
    assert total_usage["requested_model"] == "deepseek-chat"
    assert total_usage["selected_model"] == "deepseek-chat"
    assert total_usage["calls_total"] == 2
    assert total_usage["input_tokens"] == 3
    assert total_usage["output_tokens"] == 4


def test_generate_profile_full_tracks_agent_module_usage_metadata():
    storage_manager = StubStorageManager(
        checkpoints={
            "repo_info": {
                "files": ["app.py"],
                "repo_analysis": None,
            }
        }
    )
    profiler = _stub_profiler(storage_manager)

    class _LLMClientStub:
        def __init__(self):
            self.config = type("Config", (), {"model": "deepseek-chat", "provider": "deepseek"})()

        def usage_history_snapshot(self):
            return 0

        def aggregate_usage_since(self, snapshot):
            return {
                "source": "llm_client",
                "provider": "deepseek",
                "requested_model": "deepseek-chat",
                "selected_model": "deepseek-chat",
                "selected_models": ["deepseek-chat"],
                "calls_total": 2,
                "calls_with_selected_model_usage": 2,
                "calls_with_top_level_usage_fallback": 0,
                "calls_missing_selected_model_usage": 0,
                "calls_missing_usage": 0,
                "input_tokens": 21,
                "output_tokens": 34,
                "cache_read_input_tokens": 0,
                "cache_creation_input_tokens": 0,
                "cost_usd": 0.0,
                "request_cost_usd": 0.0,
            }

    profiler.llm_client = _LLMClientStub()
    profiler.basic_info_analyzer = type(
        "BasicInfoAnalyzer",
        (),
        {
            "analyze": lambda _self, *_args, **_kwargs: {
                "description": "demo",
                "target_application": ["training"],
                "target_user": ["researcher"],
                "llm_calls": 1,
                "llm_usage": {
                    "source": "llm_client",
                    "provider": "deepseek",
                    "requested_model": "deepseek-chat",
                    "selected_model": "deepseek-chat",
                    "selected_models": ["deepseek-chat"],
                    "calls_total": 1,
                    "calls_with_selected_model_usage": 1,
                    "calls_with_top_level_usage_fallback": 0,
                    "calls_missing_selected_model_usage": 0,
                    "calls_missing_usage": 0,
                    "input_tokens": 10,
                    "output_tokens": 20,
                    "cache_read_input_tokens": 0,
                    "cache_creation_input_tokens": 0,
                    "cost_usd": 0.0,
                    "request_cost_usd": 0.0,
                },
            }
        },
    )()
    class RecordingAgentModuleAnalyzer(AgentModuleAnalyzer):
        def __init__(self):
            super().__init__(llm_client=None, max_iterations=2)

        def analyze(self, **_kwargs):
            return {"modules": [], "llm_calls": 2}

    profiler.module_analyzer = RecordingAgentModuleAnalyzer()

    profile = profiler._generate_profile_full(Path("/tmp/demo"), "demo", "abc123")

    assert profile.metadata["llm_calls"] == 3
    assert profile.metadata["llm_usage_by_stage"]["module_analysis"]["calls_total"] == 2
    assert profile.metadata["llm_usage_by_stage"]["module_analysis"]["input_tokens"] == 21
    assert profile.metadata["llm_usage_summary"]["calls_total"] == 3
    assert profile.metadata["llm_usage_summary"]["input_tokens"] == 31
    assert storage_manager.saved_checkpoints["modules"]["llm_usage"]["calls_total"] == 2


def test_generate_profile_full_normalizes_resumed_agent_module_usage_source():
    storage_manager = StubStorageManager(
        checkpoints={
            "repo_info": {
                "files": ["app.py"],
                "repo_analysis": None,
            }
        },
        conversations={
            "module_analysis": {
                "conversation_name": "module_analysis",
                "llm_calls": 2,
                "llm_usage": {
                    "source": "claude_cli",
                    "provider": "deepseek",
                    "requested_model": "deepseek-chat",
                    "selected_model": "deepseek-chat",
                    "selected_models": ["deepseek-chat"],
                    "calls_total": 2,
                    "calls_with_selected_model_usage": 2,
                    "calls_with_top_level_usage_fallback": 0,
                    "calls_missing_selected_model_usage": 0,
                    "calls_missing_usage": 0,
                    "input_tokens": 21,
                    "output_tokens": 34,
                    "cache_read_input_tokens": 0,
                    "cache_creation_input_tokens": 0,
                    "cost_usd": 0.0,
                    "request_cost_usd": 0.0,
                },
            }
        },
    )
    profiler = _stub_profiler(storage_manager)

    class _LLMClientStub:
        def __init__(self):
            self.config = type("Config", (), {"model": "deepseek-chat", "provider": "deepseek"})()

        def usage_history_snapshot(self):
            return 0

        def aggregate_usage_since(self, snapshot):
            return {
                "source": "llm_client",
                "provider": "deepseek",
                "requested_model": "deepseek-chat",
                "selected_model": "deepseek-chat",
                "selected_models": ["deepseek-chat"],
                "calls_total": 1,
                "calls_with_selected_model_usage": 1,
                "calls_with_top_level_usage_fallback": 0,
                "calls_missing_selected_model_usage": 0,
                "calls_missing_usage": 0,
                "input_tokens": 8,
                "output_tokens": 13,
                "cache_read_input_tokens": 0,
                "cache_creation_input_tokens": 0,
                "cost_usd": 0.0,
                "request_cost_usd": 0.0,
            }

    profiler.llm_client = _LLMClientStub()
    profiler.basic_info_analyzer = type(
        "BasicInfoAnalyzer",
        (),
        {
            "analyze": lambda _self, *_args, **_kwargs: {
                "description": "demo",
                "target_application": ["training"],
                "target_user": ["researcher"],
                "llm_calls": 1,
                "llm_usage": {
                    "source": "llm_client",
                    "provider": "deepseek",
                    "requested_model": "deepseek-chat",
                    "selected_model": "deepseek-chat",
                    "selected_models": ["deepseek-chat"],
                    "calls_total": 1,
                    "calls_with_selected_model_usage": 1,
                    "calls_with_top_level_usage_fallback": 0,
                    "calls_missing_selected_model_usage": 0,
                    "calls_missing_usage": 0,
                    "input_tokens": 10,
                    "output_tokens": 20,
                    "cache_read_input_tokens": 0,
                    "cache_creation_input_tokens": 0,
                    "cost_usd": 0.0,
                    "request_cost_usd": 0.0,
                },
            }
        },
    )()

    class RecordingAgentModuleAnalyzer(AgentModuleAnalyzer):
        def __init__(self):
            super().__init__(llm_client=None, max_iterations=3)
            self.calls = []

        def analyze(self, **kwargs):
            self.calls.append(kwargs)
            return {"modules": [{"name": "api", "files": ["app.py"]}], "llm_calls": 3}

    profiler.module_analyzer = RecordingAgentModuleAnalyzer()

    profile = profiler._generate_profile_full(Path("/tmp/demo"), "demo", "abc123")

    assert profiler.module_analyzer.calls[0]["resume_from_conversation"] is True
    assert profile.metadata["llm_usage_by_stage"]["module_analysis"]["calls_total"] == 3
    assert profile.metadata["llm_usage_by_stage"]["module_analysis"]["source"] == "llm_client"
    assert profile.metadata["llm_usage_by_stage"]["module_analysis"]["provider"] == "deepseek"
    assert profile.metadata["llm_usage_by_stage"]["module_analysis"]["input_tokens"] == 29
    assert profile.metadata["llm_usage_by_stage"]["module_analysis"]["output_tokens"] == 47
    assert profile.metadata["llm_usage_summary"]["calls_total"] == 4
    assert profile.metadata["llm_usage_summary"]["input_tokens"] == 39
    assert profile.metadata["llm_usage_summary"]["output_tokens"] == 67
    assert storage_manager.saved_checkpoints["modules"]["llm_usage"]["calls_total"] == 3
    assert storage_manager.saved_checkpoints["modules"]["llm_usage"]["source"] == "llm_client"
    assert storage_manager.saved_checkpoints["modules"]["llm_usage"]["provider"] == "deepseek"


def test_run_agent_analysis_normalizes_resumed_conversation_usage_source(monkeypatch):
    storage_manager = StubStorageManager(
        conversations={
            "module_analysis": {
                "conversation_name": "module_analysis",
                "messages": [{"role": "system", "content": "existing"}],
                "llm_calls": 2,
                "llm_usage": {
                    "source": "claude_cli",
                    "provider": "deepseek",
                    "requested_model": "deepseek-chat",
                    "selected_model": "deepseek-chat",
                    "selected_models": ["deepseek-chat"],
                    "calls_total": 2,
                    "calls_with_selected_model_usage": 2,
                    "calls_with_top_level_usage_fallback": 0,
                    "calls_missing_selected_model_usage": 0,
                    "calls_missing_usage": 0,
                    "input_tokens": 21,
                    "output_tokens": 34,
                    "cache_read_input_tokens": 0,
                    "cache_creation_input_tokens": 0,
                    "cost_usd": 0.0,
                    "request_cost_usd": 0.0,
                },
            }
        }
    )
    monkeypatch.setattr(
        "scanner.agent.utils.make_serializable",
        lambda messages: messages,
    )

    class _LLMClient:
        def __init__(self):
            self.config = SimpleNamespace(model="deepseek-chat", provider="deepseek")

        def usage_history_snapshot(self):
            return 0

        def aggregate_usage_since(self, snapshot):
            assert snapshot == 0
            return {
                "source": "llm_client",
                "provider": "deepseek",
                "requested_model": "deepseek-chat",
                "selected_model": "deepseek-chat",
                "selected_models": ["deepseek-chat"],
                "calls_total": 1,
                "calls_with_selected_model_usage": 1,
                "calls_with_top_level_usage_fallback": 0,
                "calls_missing_selected_model_usage": 0,
                "calls_missing_usage": 0,
                "input_tokens": 8,
                "output_tokens": 13,
                "cache_read_input_tokens": 0,
                "cache_creation_input_tokens": 0,
                "cost_usd": 0.0,
                "request_cost_usd": 0.0,
            }

        def chat(self, messages, tools=None, tool_choice=None):
            assert messages
            assert tools == []
            assert tool_choice == "auto"
            return SimpleNamespace(
                content='{"modules": []}',
                tool_calls=None,
            )

    is_complete, result, llm_calls, _messages = run_agent_analysis(
        llm_client=_LLMClient(),
        system_prompt="system",
        initial_message="initial",
        tools=[],
        toolkit=SimpleNamespace(execute_tool=lambda *_args, **_kwargs: None),
        max_iterations=3,
        storage_manager=storage_manager,
        conversation_name="module_analysis",
        path_parts=("demo", "abc123"),
        resume_from_saved=True,
    )

    assert is_complete is True
    assert result == {"modules": []}
    assert llm_calls == 3
    saved_usage = storage_manager.saved_conversations["module_analysis"]["llm_usage"]
    assert saved_usage["source"] == "llm_client"
    assert saved_usage["provider"] == "deepseek"
    assert saved_usage["calls_total"] == 3
    assert saved_usage["input_tokens"] == 29
    assert saved_usage["output_tokens"] == 47
