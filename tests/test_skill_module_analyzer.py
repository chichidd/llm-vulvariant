import json
from pathlib import Path
from types import SimpleNamespace

from profiler.software.module_analyzer.skill import SkillModuleAnalyzer as SkillModuleAnalyzer



def test_skill_attach_dependencies_ignores_module_level_entries():
    analyzer = SkillModuleAnalyzer()
    modules = [
        {
            "name": "module.a",
            "category": "module",
            "description": "",
            "files": ["src/a.py"],
            "key_functions": [],
            "dependencies": [],
        }
    ]
    repo_info = {
        "repo_analysis": {
            "functions": [
                {"file": "src/a.py", "name": "<module>"},
                {"file": "src/a.py", "name": "run"},
            ],
            "call_graph_edges": [],
        }
    }

    enriched = analyzer._attach_key_functions_and_dependencies(modules, repo_info, Path("/tmp/repo"))

    assert enriched[0]["key_functions"] == ["run"]


class _StorageManagerStub:
    def __init__(self, checkpoint_dir: Path):
        self._checkpoint_dir = checkpoint_dir
        self.saved = {}

    def get_checkpoint_dir(self, *path_parts):
        self._checkpoint_dir.mkdir(parents=True, exist_ok=True)
        return self._checkpoint_dir

    def save_checkpoint(self, checkpoint_name, data, *path_parts):
        self.saved[checkpoint_name] = data


def test_skill_analyze_force_regenerate_cleans_existing_outputs(tmp_path):
    analyzer = SkillModuleAnalyzer()
    analyzer.taxonomy = {"coarse": {"fine": {}}}

    checkpoint_dir = tmp_path / "checkpoints"
    output_dir = checkpoint_dir / "skill_module_modeler"
    output_dir.mkdir(parents=True)
    stale_file = output_dir / "stale.json"
    stale_file.write_text("stale", encoding="utf-8")

    def _run(repo_path, actual_output_dir, repo_name):
        assert actual_output_dir == output_dir
        assert not stale_file.exists()
        (actual_output_dir / "module_map.json").write_text("{}", encoding="utf-8")
        (actual_output_dir / "file_index.json").write_text("{}", encoding="utf-8")
        (actual_output_dir / "module_profile.json").write_text('{"modules": []}', encoding="utf-8")
        return True, {"selected_model_usage": {"output_tokens": 9}}, actual_output_dir / "claude_cli_invocation.json"

    analyzer._run_claude_analysis = _run
    storage_manager = _StorageManagerStub(checkpoint_dir)

    result = analyzer.analyze(
        repo_info={"files": []},
        repo_path=tmp_path / "repo",
        storage_manager=storage_manager,
        repo_name="demo",
        version="abc123",
        force_regenerate=True,
    )

    assert result["modules"] == []
    assert result["llm_calls"] == 1
    assert result["llm_usage"]["selected_model_usage"]["output_tokens"] == 9
    assert result["claude_cli_record_path"].endswith("claude_cli_invocation.json")


def test_run_claude_analysis_persists_json_output(monkeypatch, tmp_path):
    analyzer = SkillModuleAnalyzer()
    output_dir = tmp_path / "out"

    class _Result:
        returncode = 0
        stdout = (
            '{"type":"result","subtype":"success","result":"done","modelUsage":{'
            '"claude-sonnet-4-5":{"inputTokens":100,"outputTokens":200,"costUSD":1.0},'
            '"deepseek-chat":{"inputTokens":12,"outputTokens":34,"costUSD":0.1}}}'
        )
        stderr = ""

    def _fake_run(*args, **kwargs):
        return _Result()

    monkeypatch.setattr("utils.claude_cli.subprocess.run", _fake_run)

    success, llm_usage, record_path = analyzer._run_claude_analysis(
        repo_path=tmp_path / "repo",
        output_dir=output_dir,
        repo_name="demo",
    )

    assert success is True
    assert llm_usage["selected_model_usage"]["input_tokens"] == 100
    assert llm_usage["selected_model_usage"]["output_tokens"] == 200
    assert llm_usage["selected_model"] == "claude-sonnet-4-5"
    assert llm_usage["selected_model_reason"] == "highest_usage_score"
    assert record_path.exists()


def test_run_claude_analysis_accepts_non_json_stdout_on_zero_exit(monkeypatch, tmp_path):
    analyzer = SkillModuleAnalyzer()
    output_dir = tmp_path / "out"

    class _Result:
        returncode = 0
        stdout = "analysis completed"
        stderr = ""

    def _fake_run(*args, **kwargs):
        return _Result()

    monkeypatch.setattr("utils.claude_cli.subprocess.run", _fake_run)

    success, llm_usage, record_path = analyzer._run_claude_analysis(
        repo_path=tmp_path / "repo",
        output_dir=output_dir,
        repo_name="demo",
    )

    assert success is True
    assert llm_usage["selected_model_usage"] is None
    assert llm_usage["selected_model"] is None
    assert record_path.exists()


def test_run_claude_analysis_falls_back_when_json_output_flag_is_unsupported(monkeypatch, tmp_path):
    analyzer = SkillModuleAnalyzer()
    output_dir = tmp_path / "out"
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

    success, llm_usage, record_path = analyzer._run_claude_analysis(
        repo_path=tmp_path / "repo",
        output_dir=output_dir,
        repo_name="demo",
    )

    assert success is True
    assert llm_usage["selected_model_usage"] is None
    assert llm_usage["calls_total"] == 1
    assert record_path.exists()
    assert len(commands) == 2
    assert "--output-format" in commands[0]
    assert "--output-format" not in commands[1]
    saved_record = json.loads(record_path.read_text(encoding="utf-8"))
    assert saved_record["output_format"] == "text"
    assert saved_record["fallback_from_json_output"] is True
    assert saved_record["prior_attempts"][0]["output_format"] == "json"


def test_skill_analyze_preserves_zero_llm_calls_for_pre_spawn_failures(tmp_path):
    analyzer = SkillModuleAnalyzer()
    analyzer.taxonomy = {"coarse": {"fine": {}}}

    checkpoint_dir = tmp_path / "checkpoints"
    storage_manager = _StorageManagerStub(checkpoint_dir)

    def _run(repo_path, actual_output_dir, repo_name):
        return False, {"calls_total": 0, "selected_model_usage": None, "top_level_usage": None}, actual_output_dir / "claude_cli_invocation.json"

    analyzer._run_claude_analysis = _run

    result = analyzer.analyze(
        repo_info={"files": []},
        repo_path=tmp_path / "repo",
        storage_manager=storage_manager,
        repo_name="demo",
        version="abc123",
    )

    assert result["modules"] == []
    assert result["llm_calls"] == 0


def test_infer_llm_call_count_preserves_explicit_zero():
    assert SkillModuleAnalyzer._infer_llm_call_count({"calls_total": 0, "selected_model": "deepseek-chat"}) == 0


def test_count_claude_attempts_counts_real_llm_requests_only():
    assert SkillModuleAnalyzer._count_claude_attempts(
        SimpleNamespace(returncode=None, timed_out=False, prior_attempts=[], error_type="OSError")
    ) == 0
    assert SkillModuleAnalyzer._count_claude_attempts(
        SimpleNamespace(returncode=None, timed_out=False, prior_attempts=[{"returncode": 2}], error_type="FileNotFoundError")
    ) == 0
    assert SkillModuleAnalyzer._count_claude_attempts(
        SimpleNamespace(returncode=None, timed_out=True, prior_attempts=[], error_type="TimeoutExpired")
    ) == 1
    assert SkillModuleAnalyzer._count_claude_attempts(
        SimpleNamespace(
            returncode=0,
            timed_out=False,
            prior_attempts=[{"returncode": 2}],
            usage_summary={},
        )
    ) == 1
