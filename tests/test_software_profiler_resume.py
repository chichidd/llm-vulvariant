import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from profiler import fingerprint as fingerprint_module
from profiler.software.analyzer import SoftwareProfiler
from profiler.software.models import SoftwareProfile
from profiler.software.module_analyzer import ModuleAnalyzer as AgentModuleAnalyzer
from profiler.software.module_analyzer.base import run_agent_analysis
from profiler.software.module_analyzer.skill import SkillModuleAnalyzer
from profiler.software import analyzer as analyzer_module


class StubStorageManager:
    def __init__(
        self,
        *,
        final_result=None,
        final_results=None,
        checkpoints=None,
        conversations=None,
    ):
        self.final_result = final_result
        self.final_results = final_results or {}
        self.checkpoints = checkpoints or {}
        self.conversations = conversations or {}
        self.saved_checkpoints = {}
        self.saved_results = {}
        self.saved_conversations = {}

    def load_final_result(self, filename, *path_parts):
        if filename in self.final_results:
            return self.final_results[filename]
        if filename == "software_profile.json":
            return self.final_result
        return None

    def load_checkpoint(self, checkpoint_name, *path_parts):
        return self.checkpoints.get(checkpoint_name)

    def save_checkpoint(self, checkpoint_name, data, *path_parts):
        self.saved_checkpoints[checkpoint_name] = data

    def save_final_result(self, filename, content, *path_parts):
        self.saved_results[filename] = json.loads(content)

    def load_conversation(self, conversation_type, *path_parts, file_identifier=None):
        if file_identifier is not None:
            return self.conversations.get((conversation_type, file_identifier))
        return self.conversations.get(conversation_type)

    def save_conversation(self, conversation_type, data, *path_parts, file_identifier=None):
        if file_identifier is not None:
            self.saved_conversations[(conversation_type, file_identifier)] = data
        self.saved_conversations[conversation_type] = data

    def clear_profile_state(self, *path_parts):
        del path_parts
        self.checkpoints = {}
        self.conversations = {}
        self.final_result = None
        self.final_results.pop("software_profile.json", None)

    def _get_profile_dir(self, *path_parts):
        profile_dir = Path("/tmp/stub-profile-storage")
        for part in path_parts:
            if part:
                profile_dir = profile_dir / part
        return profile_dir


def _stub_profiler(storage_manager):
    profiler = SoftwareProfiler.__new__(SoftwareProfiler)
    profiler.storage_manager = storage_manager
    profiler.output_dir = None
    profiler._save_config_to_output_dir = lambda: None
    profiler._detection_rules = {}
    profiler.repo_analyzer_config = {}
    profiler.module_analyzer_config = {}
    profiler.file_extensions = []
    profiler.exclude_dirs = []
    profiler.llm_client = None
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
        "basic_info": {
            "name": "demo",
            "version": "abc123",
            "description": "cached",
            "capabilities": ["serve inference traffic"],
            "interfaces": ["HTTP API"],
            "deployment_style": ["containerized service"],
            "operator_inputs": ["model configuration"],
            "external_surfaces": ["REST endpoints"],
            "evidence_summary": "Cached README summary references an HTTP API server.",
            "confidence": "high",
            "open_questions": ["Does it support gRPC?"],
        },
        "repo_info": {"files": ["app.py"]},
        "modules": [{"name": "api", "files": ["app.py"]}],
        "metadata": {"profile_fingerprint": {"hash": "expected"}},
    }
    profiler = _stub_profiler(StubStorageManager(final_result=json.dumps(cached_profile)))
    profiler._build_profile_fingerprint = lambda: {"hash": "expected"}
    profiler._generate_profile_full = lambda *args, **kwargs: pytest.fail("full analysis should not run")

    profile = profiler.generate_profile(str(repo_dir))

    assert isinstance(profile, SoftwareProfile)
    assert profile.description == "cached"
    assert profile.capabilities == ["serve inference traffic"]
    assert profile.external_surfaces == ["REST endpoints"]


def test_generate_profile_rejects_cached_final_result_with_empty_modules(tmp_path, monkeypatch):
    repo_dir = tmp_path / "demo"
    repo_dir.mkdir()
    _stub_git(monkeypatch)

    cached_profile = {
        "basic_info": {"name": "demo", "version": "abc123", "description": "cached"},
        "repo_info": {"files": ["app.py"]},
        "modules": [],
        "metadata": {"profile_fingerprint": {"hash": "expected"}},
    }
    profiler = _stub_profiler(StubStorageManager(final_result=json.dumps(cached_profile)))
    profiler._build_profile_fingerprint = lambda: {"hash": "expected"}

    regenerated = SoftwareProfile(name="demo", version="abc123", description="regenerated")
    profiler._generate_profile_full = lambda *args, **kwargs: regenerated

    profile = profiler.generate_profile(str(repo_dir))

    assert profile is regenerated


def test_generate_profile_force_regenerate_bypasses_cached_final_result(tmp_path, monkeypatch):
    repo_dir = tmp_path / "demo"
    repo_dir.mkdir()
    _stub_git(monkeypatch)

    cached_profile = {
        "basic_info": {"name": "demo", "version": "abc123", "description": "cached"},
        "repo_info": {"files": ["app.py"]},
        "modules": [{"name": "api", "files": ["app.py"]}],
        "metadata": {"profile_fingerprint": {"hash": "expected"}},
    }
    profiler = _stub_profiler(StubStorageManager(final_result=json.dumps(cached_profile)))
    profiler._build_profile_fingerprint = lambda: {"hash": "expected"}

    regenerated = SoftwareProfile(name="demo", version="abc123", description="regenerated")
    profiler._generate_profile_full = lambda *args, **kwargs: regenerated

    profile = profiler.generate_profile(str(repo_dir), force_regenerate=True)

    assert profile is regenerated


def test_generate_profile_regenerates_when_cached_fingerprint_is_stale(tmp_path, monkeypatch):
    repo_dir = tmp_path / "demo"
    repo_dir.mkdir()
    _stub_git(monkeypatch)

    cached_profile = {
        "basic_info": {"name": "demo", "version": "abc123", "description": "cached"},
        "repo_info": {"files": ["app.py"]},
        "modules": [{"name": "api", "files": ["app.py"]}],
        "metadata": {"profile_fingerprint": {"hash": "stale"}},
    }
    profiler = _stub_profiler(StubStorageManager(final_result=json.dumps(cached_profile)))
    profiler._build_profile_fingerprint = lambda: {"hash": "expected"}

    regenerated = SoftwareProfile(name="demo", version="abc123", description="regenerated")
    profiler._generate_profile_full = lambda *args, **kwargs: regenerated

    profile = profiler.generate_profile(str(repo_dir))

    assert profile is regenerated


def test_generate_profile_stale_final_result_forces_full_regeneration(tmp_path, monkeypatch):
    repo_dir = tmp_path / "demo"
    repo_dir.mkdir()
    _stub_git(monkeypatch)

    cached_profile = {
        "basic_info": {"name": "demo", "version": "abc123", "description": "cached"},
        "repo_info": {"files": ["app.py"]},
        "modules": [{"name": "api", "files": ["app.py"]}],
        "metadata": {"profile_fingerprint": {"hash": "stale"}},
    }
    profiler = _stub_profiler(StubStorageManager(final_result=json.dumps(cached_profile)))
    profiler._build_profile_fingerprint = lambda: {"hash": "expected"}

    captured = {}

    def _record_generate(*args, **kwargs):
        captured["force_regenerate"] = kwargs["force_regenerate"]
        return SoftwareProfile(name="demo", version="abc123", description="regenerated")

    profiler._generate_profile_full = _record_generate

    profile = profiler.generate_profile(str(repo_dir))

    assert captured["force_regenerate"] is True
    assert profile.description == "regenerated"


def test_generate_profile_missing_resume_state_forces_full_regeneration(tmp_path, monkeypatch):
    repo_dir = tmp_path / "demo"
    repo_dir.mkdir()
    _stub_git(monkeypatch)

    checkpoints = {
        "repo_info": {"files": ["app.py"], "repo_analysis": None},
        "basic_info": {
            "description": "stale",
            "target_application": ["old"],
            "target_user": ["old"],
            "capabilities": ["old capability"],
            "interfaces": ["old interface"],
            "deployment_style": ["old deployment"],
            "operator_inputs": ["old input"],
            "external_surfaces": ["old surface"],
            "evidence_summary": "old summary",
            "confidence": "low",
            "open_questions": ["old question"],
        },
        "modules": {"modules": [{"name": "api", "files": ["app.py"]}]},
    }
    profiler = _stub_profiler(StubStorageManager(checkpoints=checkpoints))
    profiler._build_profile_fingerprint = lambda: {"hash": "expected"}

    captured = {}

    def _record_generate(*args, **kwargs):
        captured["force_regenerate"] = kwargs["force_regenerate"]
        return SoftwareProfile(name="demo", version="abc123", description="regenerated")

    profiler._generate_profile_full = _record_generate

    profile = profiler.generate_profile(str(repo_dir))

    assert captured["force_regenerate"] is True
    assert profile.description == "regenerated"


def test_generate_profile_matching_resume_state_allows_checkpoint_reuse(tmp_path, monkeypatch):
    repo_dir = tmp_path / "demo"
    repo_dir.mkdir()
    _stub_git(monkeypatch)

    checkpoints = {
        "repo_info": {"files": ["app.py"], "repo_analysis": None},
        "basic_info": {
            "description": "from-checkpoint",
            "target_application": ["inference"],
            "target_user": ["developer"],
            "capabilities": ["serve inference traffic"],
            "interfaces": ["HTTP API"],
            "deployment_style": ["containerized service"],
            "operator_inputs": ["model configuration"],
            "external_surfaces": ["REST endpoints"],
            "evidence_summary": "README references a deployed API service.",
            "confidence": "high",
            "open_questions": ["Does it offer background workers?"],
        },
        "modules": {"modules": [{"name": "api", "files": ["app.py"]}]},
    }
    storage_manager = StubStorageManager(
        checkpoints=checkpoints,
        final_results={
            "software_profile_resume_state.json": json.dumps(
                {"profile_fingerprint": {"hash": "expected"}},
                ensure_ascii=False,
            ),
        },
    )
    profiler = _stub_profiler(storage_manager)
    profiler._build_profile_fingerprint = lambda: {"hash": "expected"}

    captured = {}

    def _record_generate(*args, **kwargs):
        captured["force_regenerate"] = kwargs["force_regenerate"]
        return SoftwareProfile(name="demo", version="abc123", description="regenerated")

    profiler._generate_profile_full = _record_generate

    profile = profiler.generate_profile(str(repo_dir))

    assert captured["force_regenerate"] is False
    assert profile.description == "regenerated"


def test_failed_full_regeneration_persists_resume_state_for_retry(tmp_path, monkeypatch):
    repo_dir = tmp_path / "demo"
    repo_dir.mkdir()
    _stub_git(monkeypatch)

    class TrackingStorageManager(StubStorageManager):
        def save_final_result(self, filename, content, *path_parts):
            super().save_final_result(filename, content, *path_parts)
            self.final_results[filename] = content

    storage_manager = TrackingStorageManager(
        checkpoints={
            "repo_info": {"files": ["stale.py"], "repo_analysis": None},
        },
        conversations={
            ("module_analysis", "module_analysis"): {
                "conversation_name": "module_analysis",
                "messages": [{"role": "user", "content": "stale"}],
            },
        },
        final_results={
            "software_profile_resume_state.json": json.dumps(
                {"profile_fingerprint": {"hash": "stale"}},
                ensure_ascii=False,
            ),
        },
    )
    profiler = _stub_profiler(storage_manager)
    profiler._build_profile_fingerprint = lambda: {"hash": "expected"}

    attempts = []

    def _generate(*args, **kwargs):
        attempts.append(kwargs["force_regenerate"])
        if len(attempts) == 1:
            assert storage_manager.checkpoints == {}
            assert storage_manager.conversations == {}
            storage_manager.checkpoints["repo_info"] = {"files": ["fresh.py"], "repo_analysis": None}
            raise RuntimeError("generation failed")
        return SoftwareProfile(name="demo", version="abc123", description="regenerated")

    profiler._generate_profile_full = _generate

    with pytest.raises(RuntimeError, match="generation failed"):
        profiler.generate_profile(str(repo_dir))

    assert storage_manager.saved_results["software_profile_resume_state.json"]["profile_fingerprint"]["hash"] == "expected"
    profile = profiler.generate_profile(str(repo_dir))

    assert attempts == [True, False]
    assert profile.description == "regenerated"


def test_generate_profile_rejects_dirty_worktree_without_cached_final_result(tmp_path, monkeypatch):
    repo_dir = tmp_path / "demo"
    repo_dir.mkdir()

    monkeypatch.setattr(analyzer_module, "has_uncommitted_changes", lambda _repo: True)
    monkeypatch.setattr(analyzer_module, "get_git_commit", lambda _repo: "abc123")
    monkeypatch.setattr(analyzer_module, "get_git_restore_target", lambda _repo: "master")
    monkeypatch.setattr(analyzer_module, "checkout_commit", lambda *_args, **_kwargs: pytest.fail("should not checkout"))
    monkeypatch.setattr(analyzer_module, "restore_git_position", lambda *_args, **_kwargs: True)

    profiler = _stub_profiler(StubStorageManager())
    profiler._build_profile_fingerprint = lambda: {"hash": "expected"}

    with pytest.raises(RuntimeError, match="has local changes; please clean/stash before profiling"):
        profiler.generate_profile(str(repo_dir))


def test_generate_profile_raises_when_restore_after_success_fails(tmp_path, monkeypatch):
    repo_dir = tmp_path / "demo"
    repo_dir.mkdir()

    monkeypatch.setattr(analyzer_module, "has_uncommitted_changes", lambda _repo: False)
    monkeypatch.setattr(analyzer_module, "get_git_commit", lambda _repo: "abc123")
    monkeypatch.setattr(analyzer_module, "get_git_restore_target", lambda _repo: "master")
    monkeypatch.setattr(analyzer_module, "checkout_commit", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(analyzer_module, "restore_git_position", lambda *_args, **_kwargs: False)

    profiler = _stub_profiler(StubStorageManager())
    profiler._build_profile_fingerprint = lambda: {"hash": "expected"}
    profiler._generate_profile_full = lambda *args, **kwargs: SoftwareProfile(
        name="demo",
        version="abc123",
        description="generated",
    )

    with pytest.raises(RuntimeError, match="Failed to restore repository to original position"):
        profiler.generate_profile(str(repo_dir), target_version="deadbeef")


def test_generate_profile_rejects_dirty_worktree_before_loading_matching_cache(tmp_path, monkeypatch):
    repo_dir = tmp_path / "demo"
    repo_dir.mkdir()

    monkeypatch.setattr(analyzer_module, "get_git_commit", lambda _repo: "abc123")
    monkeypatch.setattr(analyzer_module, "get_git_restore_target", lambda _repo: "abc123")
    monkeypatch.setattr(analyzer_module, "has_uncommitted_changes", lambda _repo: True)

    cached_profile = {
        "basic_info": {"name": "demo", "version": "abc123", "description": "cached"},
        "repo_info": {"files": ["app.py"]},
        "modules": [{"name": "api", "files": ["app.py"]}],
        "metadata": {"profile_fingerprint": {"hash": "expected"}},
    }
    profiler = _stub_profiler(StubStorageManager(final_result=json.dumps(cached_profile)))
    profiler._build_profile_fingerprint = lambda: {"hash": "expected"}
    profiler._load_cached_profile_if_compatible = (
        lambda *args, **kwargs: pytest.fail("dirty worktree should fail before loading cached profile")
    )
    profiler._generate_profile_full = lambda *args, **kwargs: pytest.fail("dirty worktree should fail before regeneration")

    with pytest.raises(RuntimeError, match="has local changes; please clean/stash before profiling"):
        profiler.generate_profile(str(repo_dir), target_version="abc123")


def test_generate_profile_refuses_checkout_without_restore_target(tmp_path, monkeypatch):
    repo_dir = tmp_path / "demo"
    repo_dir.mkdir()

    monkeypatch.setattr(analyzer_module, "has_uncommitted_changes", lambda _repo: False)
    monkeypatch.setattr(analyzer_module, "get_git_commit", lambda _repo: "abc123")
    monkeypatch.setattr(analyzer_module, "get_git_restore_target", lambda _repo: None)

    checkout_calls = []
    monkeypatch.setattr(
        analyzer_module,
        "checkout_commit",
        lambda _repo, _target: checkout_calls.append(_target) or True,
    )

    profiler = _stub_profiler(StubStorageManager())
    profiler._generate_profile_full = lambda *args, **kwargs: pytest.fail("full analysis should not run")

    with pytest.raises(RuntimeError, match="Unable to resolve original git position"):
        profiler.generate_profile(str(repo_dir), target_version="deadbeef")

    assert checkout_calls == []


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


def test_generate_profile_full_reanalyzes_empty_modules_checkpoint():
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
            "modules": [],
        },
    }
    storage_manager = StubStorageManager(checkpoints=checkpoints)
    profiler = _stub_profiler(storage_manager)

    profiler.repo_collector = type("RepoCollector", (), {"collect": lambda *_args, **_kwargs: pytest.fail("repo collection should not rerun")})()
    profiler.basic_info_analyzer = type("BasicInfoAnalyzer", (), {"analyze": lambda *_args, **_kwargs: pytest.fail("basic info should not rerun")})()

    module_calls = []

    class RecordingModuleAnalyzer:
        def analyze(self, **kwargs):
            module_calls.append(kwargs)
            return {"modules": [{"name": "api", "files": ["app.py"]}], "llm_calls": 1}

    profiler.module_analyzer = RecordingModuleAnalyzer()

    profile = profiler._generate_profile_full(Path("/tmp/demo"), "demo", "abc123")

    assert module_calls == [{
        "repo_info": {"files": ["app.py"], "repo_analysis": None},
        "repo_path": Path("/tmp/demo"),
        "storage_manager": storage_manager,
        "repo_name": "demo",
        "version": "abc123",
    }]
    assert profile.modules == [{"name": "api", "files": ["app.py"]}]
    assert storage_manager.saved_checkpoints["modules"]["modules"] == [{"name": "api", "files": ["app.py"]}]


def test_generate_profile_full_raises_when_module_analysis_returns_no_modules():
    storage_manager = StubStorageManager(
        checkpoints={
            "repo_info": {
                "files": ["app.py"],
                "repo_analysis": None,
            },
            "basic_info": {
                "description": "from-checkpoint",
                "target_application": ["inference"],
                "target_user": ["developer"],
            },
        }
    )
    profiler = _stub_profiler(storage_manager)
    profiler.repo_collector = type("RepoCollector", (), {"collect": lambda *_args, **_kwargs: pytest.fail("repo collection should not rerun")})()
    profiler.basic_info_analyzer = type("BasicInfoAnalyzer", (), {"analyze": lambda *_args, **_kwargs: pytest.fail("basic info should not rerun")})()
    profiler.module_analyzer = type(
        "SkillModuleAnalyzer",
        (),
        {"analyze": lambda _self, **_kwargs: {"modules": [], "llm_calls": 0}},
    )()

    with pytest.raises(RuntimeError, match="Module analysis did not produce a valid result"):
        profiler._generate_profile_full(Path("/tmp/demo"), "demo", "abc123")


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
                "capabilities": ["train models"],
                "interfaces": ["CLI"],
                "deployment_style": ["self-hosted"],
                "operator_inputs": ["training config"],
                "external_surfaces": ["CLI arguments"],
                "evidence_summary": "README references a CLI workflow for launching training jobs.",
                "confidence": "high",
                "open_questions": ["Does the repo also expose an API?"],
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
    assert profile.capabilities == ["train models"]
    assert profile.interfaces == ["CLI"]
    assert profile.deployment_style == ["self-hosted"]
    assert profile.operator_inputs == ["training config"]
    assert profile.external_surfaces == ["CLI arguments"]
    assert profile.evidence_summary == "README references a CLI workflow for launching training jobs."
    assert profile.confidence == "high"
    assert profile.open_questions == ["Does the repo also expose an API?"]
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
        {"analyze": lambda _self, **_kwargs: {"modules": [{"name": "api", "files": ["app.py"]}], "llm_calls": 0}},
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
        {"analyze": lambda _self, **_kwargs: {"modules": [{"name": "api", "files": ["app.py"]}], "llm_calls": 0}},
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


def test_build_profile_fingerprint_changes_when_repo_analyzer_config_changes():
    profiler = _stub_profiler(StubStorageManager())
    profiler._detection_rules = {"data_sources": {"http": ["requests"]}}
    profiler.module_analyzer_config = {"analyzer_type": "skill"}
    profiler.file_extensions = [".py"]
    profiler.exclude_dirs = ["node_modules"]

    profiler.repo_analyzer_config = {"languages": ["python"]}
    fingerprint = profiler._build_profile_fingerprint()

    profiler.repo_analyzer_config = {"languages": ["python", "cpp"]}
    updated_fingerprint = profiler._build_profile_fingerprint()

    assert fingerprint["repo_analyzer_config_hash"] != updated_fingerprint["repo_analyzer_config_hash"]
    assert fingerprint["hash"] != updated_fingerprint["hash"]


def test_build_profile_fingerprint_changes_when_llm_base_url_changes():
    profiler = _stub_profiler(StubStorageManager())
    profiler._detection_rules = {"data_sources": {"http": ["requests"]}}
    profiler.repo_analyzer_config = {"languages": ["python"]}
    profiler.module_analyzer_config = {"analyzer_type": "skill"}
    profiler.file_extensions = [".py"]
    profiler.exclude_dirs = ["node_modules"]
    profiler.llm_client = SimpleNamespace(
        config=SimpleNamespace(
            provider="deepseek",
            model="deepseek-chat",
            base_url="https://primary.example/v1",
            temperature=0.1,
            top_p=0.9,
            max_tokens=4096,
            enable_thinking=True,
        )
    )

    fingerprint = profiler._build_profile_fingerprint()

    profiler.llm_client = SimpleNamespace(
        config=SimpleNamespace(
            provider="deepseek",
            model="deepseek-chat",
            base_url="https://secondary.example/v1",
            temperature=0.1,
            top_p=0.9,
            max_tokens=4096,
            enable_thinking=True,
        )
    )
    updated_fingerprint = profiler._build_profile_fingerprint()

    assert fingerprint["inputs_hash"] != updated_fingerprint["inputs_hash"]
    assert fingerprint["hash"] != updated_fingerprint["hash"]


def test_build_profile_fingerprint_hashes_external_analyzers():
    profiler = _stub_profiler(StubStorageManager())
    profiler._detection_rules = {"data_sources": {"http": ["requests"]}}
    profiler.repo_analyzer_config = {"languages": ["python"]}
    profiler.module_analyzer_config = {"analyzer_type": "skill"}
    profiler.file_extensions = [".py"]
    profiler.exclude_dirs = ["node_modules"]

    fingerprint = profiler._build_profile_fingerprint()

    assert fingerprint["source_hashes"]["codeql_native.py"]
    assert fingerprint["source_hashes"]["ai_infra_taxonomy.py"]
    assert fingerprint["source_hashes"]["scan_repo.py"]


def test_build_profile_fingerprint_changes_when_repo_state_changes(tmp_path):
    repo_dir = tmp_path / "demo"
    repo_dir.mkdir()
    source_file = repo_dir / "app.py"
    source_file.write_text("print('first')\n", encoding="utf-8")

    profiler = _stub_profiler(StubStorageManager())
    profiler._detection_rules = {"data_sources": {"http": ["requests"]}}
    profiler.repo_analyzer_config = {"languages": ["python"]}
    profiler.module_analyzer_config = {"analyzer_type": "skill"}
    profiler.file_extensions = [".py"]
    profiler.exclude_dirs = ["node_modules"]
    profiler._current_fingerprint_repo_path = repo_dir
    profiler._current_fingerprint_repo_version = "abc123"

    fingerprint = profiler._build_profile_fingerprint()

    source_file.write_text("print('second')\n", encoding="utf-8")
    updated_fingerprint = profiler._build_profile_fingerprint()

    assert fingerprint["inputs_hash"] == updated_fingerprint["inputs_hash"]
    assert fingerprint["repo_state_hash"] != updated_fingerprint["repo_state_hash"]
    assert fingerprint["hash"] != updated_fingerprint["hash"]


def test_build_profile_fingerprint_ignores_non_profiled_files(tmp_path):
    repo_dir = tmp_path / "demo"
    repo_dir.mkdir()
    (repo_dir / "app.py").write_text("print('same')\n", encoding="utf-8")
    ignored_file = repo_dir / "scan.log"
    ignored_file.write_text("first\n", encoding="utf-8")

    profiler = _stub_profiler(StubStorageManager())
    profiler._detection_rules = {"data_sources": {"http": ["requests"]}}
    profiler.repo_analyzer_config = {"languages": ["python"]}
    profiler.module_analyzer_config = {"analyzer_type": "skill"}
    profiler.file_extensions = [".py"]
    profiler.exclude_dirs = ["node_modules"]
    profiler.readme_files = ["README.md"]
    profiler.dependency_files = ["pyproject.toml"]
    profiler._current_fingerprint_repo_path = repo_dir
    profiler._current_fingerprint_repo_version = "abc123"

    fingerprint = profiler._build_profile_fingerprint()

    ignored_file.write_text("second\n", encoding="utf-8")
    updated_fingerprint = profiler._build_profile_fingerprint()

    assert fingerprint["repo_state_hash"] == updated_fingerprint["repo_state_hash"]
    assert fingerprint["hash"] == updated_fingerprint["hash"]


def test_build_profile_fingerprint_inputs_hash_changes_when_repo_file_scope_changes():
    profiler = _stub_profiler(StubStorageManager())
    profiler._detection_rules = {"data_sources": {"http": ["requests"]}}
    profiler.repo_analyzer_config = {"languages": ["python"]}
    profiler.module_analyzer_config = {"analyzer_type": "skill"}
    profiler.file_extensions = [".py"]
    profiler.exclude_dirs = ["node_modules"]
    profiler.readme_files = ["README.md"]
    profiler.dependency_files = ["pyproject.toml"]
    profiler._current_fingerprint_repo_path = None
    profiler._current_fingerprint_repo_version = "abc123"

    fingerprint = profiler._build_profile_fingerprint()

    profiler.readme_files = ["README.txt"]
    updated_fingerprint = profiler._build_profile_fingerprint()

    assert fingerprint["inputs_hash"] != updated_fingerprint["inputs_hash"]
    assert fingerprint["hash"] != updated_fingerprint["hash"]


def test_build_profile_fingerprint_ignores_nested_module_excluded_paths(tmp_path):
    repo_dir = tmp_path / "demo"
    generated_dir = repo_dir / "services" / "foo" / "generated"
    generated_dir.mkdir(parents=True)
    (repo_dir / "app.py").write_text("print('same')\n", encoding="utf-8")
    generated_file = generated_dir / "auto.py"
    generated_file.write_text("print('first')\n", encoding="utf-8")

    profiler = _stub_profiler(StubStorageManager())
    profiler._detection_rules = {"data_sources": {"http": ["requests"]}}
    profiler.repo_analyzer_config = {"languages": ["python"]}
    profiler.module_analyzer_config = {
        "analyzer_type": "skill",
        "excluded_folders": ["services/*/generated"],
    }
    profiler.file_extensions = [".py"]
    profiler.exclude_dirs = ["node_modules"]
    profiler.readme_files = ["README.md"]
    profiler.dependency_files = ["pyproject.toml"]
    profiler._current_fingerprint_repo_path = repo_dir
    profiler._current_fingerprint_repo_version = "abc123"

    fingerprint = profiler._build_profile_fingerprint()

    generated_file.write_text("print('second')\n", encoding="utf-8")
    updated_fingerprint = profiler._build_profile_fingerprint()

    assert fingerprint["repo_state_hash"] == updated_fingerprint["repo_state_hash"]
    assert fingerprint["hash"] == updated_fingerprint["hash"]


def test_build_profile_fingerprint_changes_when_repo_version_changes(tmp_path):
    repo_dir = tmp_path / "demo"
    repo_dir.mkdir()
    (repo_dir / "app.py").write_text("print('same')\n", encoding="utf-8")

    profiler = _stub_profiler(StubStorageManager())
    profiler._detection_rules = {"data_sources": {"http": ["requests"]}}
    profiler.repo_analyzer_config = {"languages": ["python"]}
    profiler.module_analyzer_config = {"analyzer_type": "skill"}
    profiler.file_extensions = [".py"]
    profiler.exclude_dirs = ["node_modules"]
    profiler._current_fingerprint_repo_path = repo_dir
    profiler._current_fingerprint_repo_version = "abc123"

    fingerprint = profiler._build_profile_fingerprint()

    profiler._current_fingerprint_repo_version = "def456"
    updated_fingerprint = profiler._build_profile_fingerprint()

    assert fingerprint["repo_state_hash"] == updated_fingerprint["repo_state_hash"]
    assert fingerprint["hash"] != updated_fingerprint["hash"]


def test_build_profile_fingerprint_tolerates_unreadable_repo_files(tmp_path, monkeypatch):
    repo_dir = tmp_path / "demo"
    repo_dir.mkdir()
    unreadable_file = repo_dir / "app.py"
    unreadable_file.write_text("print('same')\n", encoding="utf-8")

    profiler = _stub_profiler(StubStorageManager())
    profiler._detection_rules = {"data_sources": {"http": ["requests"]}}
    profiler.repo_analyzer_config = {"languages": ["python"]}
    profiler.module_analyzer_config = {"analyzer_type": "skill"}
    profiler.file_extensions = [".py"]
    profiler.exclude_dirs = ["node_modules"]
    profiler.readme_files = ["README.md"]
    profiler.dependency_files = ["pyproject.toml"]
    profiler._current_fingerprint_repo_path = repo_dir
    profiler._current_fingerprint_repo_version = "abc123"

    original_read_bytes = Path.read_bytes

    def _raise_for_repo_file(path: Path) -> bytes:
        if path == unreadable_file:
            raise PermissionError("permission denied")
        return original_read_bytes(path)

    monkeypatch.setattr(fingerprint_module.Path, "read_bytes", _raise_for_repo_file)

    fingerprint = profiler._build_profile_fingerprint()

    assert fingerprint["repo_state_file_count"] == 1
    assert fingerprint["repo_state_hash"]


def test_generate_profile_full_accepts_completed_skill_analysis_with_empty_modules(monkeypatch):
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

    class EmptySkillModuleAnalyzer(SkillModuleAnalyzer):
        def __init__(self):
            super().__init__(llm_client=None)
            self.taxonomy = {"coarse": {"fine": {}}}

        def analyze(self, **kwargs):
            return {"modules": [], "llm_calls": 0, "analysis_completed": True}

    monkeypatch.setattr(analyzer_module, "RepoAnalyzer", RecordingRepoAnalyzer)
    profiler.module_analyzer = EmptySkillModuleAnalyzer()

    profile = profiler._generate_profile_full(Path("/tmp/demo"), "demo", "abc123", force_regenerate=False)

    assert profile.modules == []


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
            return {"modules": [{"name": "api", "files": ["app.py"]}], "llm_calls": 0}

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
            return {"modules": [{"name": "api", "files": ["app.py"]}], "llm_calls": 0}

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
                "modules": [{"name": "api", "files": ["app.py"]}],
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
                "module_analysis_record_path": "/tmp/claude_cli_invocation.json",
                "module_analysis_mode": "claude_cli",
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
    assert saved["metadata"]["module_analysis_mode"] == "claude_cli"
    assert saved["metadata"]["profile_repo_path"] == str(Path("/tmp/demo").resolve())


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
                "modules": [{"name": "api", "files": ["app.py"]}],
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
            return {"modules": [{"name": "api", "files": ["app.py"]}], "llm_calls": 2}

    profiler.module_analyzer = RecordingAgentModuleAnalyzer()

    profile = profiler._generate_profile_full(Path("/tmp/demo"), "demo", "abc123")

    assert profile.metadata["llm_calls"] == 3
    assert profile.metadata["llm_usage_by_stage"]["module_analysis"]["calls_total"] == 2
    assert profile.metadata["llm_usage_by_stage"]["module_analysis"]["input_tokens"] == 21
    assert profile.metadata["llm_usage_summary"]["calls_total"] == 3
    assert profile.metadata["llm_usage_summary"]["input_tokens"] == 31
    assert storage_manager.saved_checkpoints["modules"]["modules"] == [{"name": "api", "files": ["app.py"]}]


def test_generate_profile_full_normalizes_resumed_agent_module_usage_source():
    storage_manager = StubStorageManager(
        checkpoints={
            "repo_info": {
                "files": ["app.py"],
                "repo_analysis": None,
            }
        },
        conversations={
            ("module_analysis", "module_analysis"): {
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
            ("module_analysis", "module_analysis"): {
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


def test_run_agent_analysis_ignores_failed_saved_conversation(monkeypatch):
    storage_manager = StubStorageManager(
        conversations={
            ("module_analysis", "module_analysis"): {
                "conversation_name": "module_analysis",
                "status": "failed",
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
                content='{"modules": [{"name": "fresh", "files": ["app.py"]}]}',
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
    assert result == {"modules": [{"name": "fresh", "files": ["app.py"]}]}
    assert llm_calls == 1


def test_run_agent_analysis_treats_empty_tool_calls_as_final_content(monkeypatch):
    storage_manager = StubStorageManager()
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
            return {"source": "llm_client", "calls_total": 1}

        def chat(self, messages, tools=None, tool_choice=None):
            assert messages
            assert tools == []
            assert tool_choice == "auto"
            return SimpleNamespace(
                content='{"modules": []}',
                tool_calls=[],
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
        resume_from_saved=False,
    )

    assert is_complete is True
    assert result == {"modules": []}
    assert llm_calls == 1


def test_load_prior_agent_module_usage_summary_loads_named_module_analysis_conversation():
    class _StorageManager:
        def __init__(self):
            self.calls = []

        def load_conversation(self, conversation_type, *path_parts, file_identifier=None):
            self.calls.append((conversation_type, path_parts, file_identifier))
            if file_identifier == "module_analysis":
                return {
                    "conversation_name": "module_analysis",
                    "llm_calls": 2,
                    "llm_usage": {
                        "source": "llm_client",
                        "provider": "deepseek",
                        "requested_model": "deepseek-chat",
                        "selected_model": "deepseek-chat",
                        "selected_models": ["deepseek-chat"],
                        "calls_total": 2,
                        "input_tokens": 11,
                        "output_tokens": 13,
                    },
                }
            return {
                "conversation_name": "other",
                "llm_calls": 9,
                "llm_usage": {"calls_total": 9},
            }

    profiler = SoftwareProfiler.__new__(SoftwareProfiler)
    profiler.storage_manager = _StorageManager()
    profiler.llm_client = SimpleNamespace(
        config=SimpleNamespace(model="deepseek-chat", provider="deepseek")
    )

    usage_summary, llm_calls = profiler._load_prior_agent_module_usage_summary(
        path_parts=("demo", "abc123"),
        previous_modules_checkpoint=None,
    )

    assert llm_calls == 2
    assert usage_summary["calls_total"] == 2
    assert profiler.storage_manager.calls == [
        ("module_analysis", ("demo", "abc123"), "module_analysis")
    ]
