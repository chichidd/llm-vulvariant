import json
from pathlib import Path

import pytest

from profiler.software.analyzer import SoftwareProfiler
from profiler.software.models import SoftwareProfile
from profiler.software.module_analyzer import ModuleAnalyzer as AgentModuleAnalyzer
from profiler.software.module_analyzer.skill import SkillModuleAnalyzer
from profiler.software import analyzer as analyzer_module


class StubStorageManager:
    def __init__(self, *, final_result=None, checkpoints=None):
        self.final_result = final_result
        self.checkpoints = checkpoints or {}
        self.saved_checkpoints = {}
        self.saved_results = {}

    def load_final_result(self, filename, *path_parts):
        return self.final_result

    def load_checkpoint(self, checkpoint_name, *path_parts):
        return self.checkpoints.get(checkpoint_name)

    def save_checkpoint(self, checkpoint_name, data, *path_parts):
        self.saved_checkpoints[checkpoint_name] = data

    def save_final_result(self, filename, content, *path_parts):
        self.saved_results[filename] = json.loads(content)


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
