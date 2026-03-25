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
    for file_name, payload in (
        ("module_map.json", {}),
        ("file_index.json", {}),
        ("module_profile.json", {"modules": []}),
    ):
        (output_dir / file_name).parent.mkdir(parents=True, exist_ok=True)
        (output_dir / file_name).write_text(json.dumps(payload), encoding="utf-8")

    def _fake_run_claude_cli(**kwargs):
        record_path = kwargs["record_path"]
        record_path.write_text("{}", encoding="utf-8")
        return SimpleNamespace(
            returncode=0,
            stdout="",
            stderr="",
            parsed_output={
                "result": "done",
                "modelUsage": {
                    "claude-sonnet-4-5": {"inputTokens": 100, "outputTokens": 200, "costUSD": 1.0},
                    "deepseek-chat": {"inputTokens": 12, "outputTokens": 34, "costUSD": 0.1},
                },
            },
            usage_summary={
                "selected_model_usage": {
                    "input_tokens": 100,
                    "output_tokens": 200,
                },
                "selected_model": "claude-sonnet-4-5",
                "selected_model_reason": "highest_usage_score",
            },
            record_path=record_path,
            parse_error=None,
            error_type=None,
            error_message=None,
            timed_out=False,
            output_format="json",
            fallback_from_json_output=False,
            fallback_reason=None,
            prior_attempts=[],
        )

    monkeypatch.setattr("profiler.software.module_analyzer.skill.run_claude_cli", _fake_run_claude_cli)

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


def test_run_claude_analysis_rejects_zero_exit_without_required_artifacts(monkeypatch, tmp_path):
    analyzer = SkillModuleAnalyzer()
    output_dir = tmp_path / "out"

    def _fake_run_claude_cli(**kwargs):
        record_path = kwargs["record_path"]
        record_path.write_text("{}", encoding="utf-8")
        return SimpleNamespace(
            returncode=0,
            stdout="analysis completed",
            stderr="",
            parsed_output=None,
            usage_summary={},
            record_path=record_path,
            parse_error=None,
            error_type=None,
            error_message=None,
            timed_out=False,
            output_format="text",
            fallback_from_json_output=False,
            fallback_reason=None,
            prior_attempts=[],
        )

    monkeypatch.setattr("profiler.software.module_analyzer.skill.run_claude_cli", _fake_run_claude_cli)

    success, llm_usage, record_path = analyzer._run_claude_analysis(
        repo_path=tmp_path / "repo",
        output_dir=output_dir,
        repo_name="demo",
    )

    assert success is False
    assert llm_usage.get("selected_model_usage") is None
    assert llm_usage.get("selected_model") is None
    assert record_path.exists()


def test_run_claude_analysis_falls_back_when_json_output_flag_is_unsupported(monkeypatch, tmp_path):
    analyzer = SkillModuleAnalyzer()
    output_dir = tmp_path / "out"

    def _fake_run_claude_cli(**kwargs):
        record_path = kwargs["record_path"]
        record_path.write_text(
            json.dumps(
                {
                    "output_format": "text",
                    "fallback_from_json_output": True,
                    "prior_attempts": [{"output_format": "json", "returncode": 2}],
                }
            ),
            encoding="utf-8",
        )
        return SimpleNamespace(
            returncode=0,
            stdout="analysis completed",
            stderr="",
            parsed_output=None,
            usage_summary={},
            record_path=record_path,
            parse_error=None,
            error_type=None,
            error_message=None,
            timed_out=False,
            output_format="text",
            fallback_from_json_output=True,
            fallback_reason="unsupported json output",
            prior_attempts=[{"output_format": "json", "returncode": 2}],
        )

    monkeypatch.setattr("profiler.software.module_analyzer.skill.run_claude_cli", _fake_run_claude_cli)

    success, llm_usage, record_path = analyzer._run_claude_analysis(
        repo_path=tmp_path / "repo",
        output_dir=output_dir,
        repo_name="demo",
    )

    assert success is False
    assert llm_usage.get("selected_model_usage") is None
    assert llm_usage["calls_total"] == 1
    assert record_path.exists()
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


def test_skill_analyze_validation_mode_runs_direct_scan_script(monkeypatch, tmp_path):
    analyzer = SkillModuleAnalyzer(
        llm_client=SimpleNamespace(
            config=SimpleNamespace(provider="deepseek", model="deepseek-chat"),
        ),
        excluded_folders=["vendor"],
        code_extensions=[".py"],
        validation_mode=True,
        validation_temperature=0.0,
        validation_max_workers=1,
    )
    analyzer.taxonomy = {"coarse": {"fine": {}}}

    checkpoint_dir = tmp_path / "checkpoints"
    storage_manager = _StorageManagerStub(checkpoint_dir)
    script_path = tmp_path / "scan_repo.py"
    script_path.write_text("# stub\n", encoding="utf-8")
    monkeypatch.setattr(analyzer, "_resolve_scan_script_path", lambda: script_path)

    commands = []

    class _Result:
        returncode = 0
        stdout = "validation complete"
        stderr = ""

    def _fake_run(cmd, **kwargs):
        commands.append((cmd, kwargs))
        out_dir = Path(cmd[cmd.index("--out") + 1])
        file_list_path = Path(cmd[cmd.index("--file-list") + 1])
        file_list = json.loads(file_list_path.read_text(encoding="utf-8"))
        assert file_list == ["src/app.py"]
        (out_dir / "signals.json").write_text(
            json.dumps(
                {
                    "analysis_mode": "validation_script",
                    "llm_usage_summary": {
                        "source": "llm_client",
                        "provider": "deepseek",
                        "requested_model": "deepseek-chat",
                        "selected_model": "deepseek-chat",
                        "calls_total": 1,
                        "sessions_total": 1,
                        "input_tokens": 11,
                        "output_tokens": 7,
                    },
                }
            ),
            encoding="utf-8",
        )
        (out_dir / "module_map.json").write_text("{}", encoding="utf-8")
        (out_dir / "file_index.json").write_text(
            json.dumps(
                {
                    "src/app.py": "coarse.fine",
                    "vendor/lib.py": "coarse.fine",
                }
            ),
            encoding="utf-8",
        )
        (out_dir / "module_profile.json").write_text(
            json.dumps(
                {
                    "modules": [
                        {
                            "name": "coarse.fine",
                            "category": "coarse",
                            "files": ["src/app.py", "vendor/lib.py", "docs/readme.md"],
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        return _Result()

    monkeypatch.setattr("profiler.software.module_analyzer.skill.subprocess.run", _fake_run)

    result = analyzer.analyze(
        repo_info={"files": ["src/app.py", "vendor/lib.py", "docs/readme.md"]},
        repo_path=tmp_path / "repo",
        storage_manager=storage_manager,
        repo_name="demo",
        version="abc123",
    )

    assert len(result["modules"]) == 1
    assert result["modules"][0]["name"] == "coarse.fine"
    assert result["llm_calls"] == 1
    assert result["module_analysis_mode"] == "validation_script"
    assert result["module_analysis_record_path"].endswith("module_analysis_invocation.json")
    assert result["claude_cli_record_path"].endswith("module_analysis_invocation.json")
    assert result["modules"][0]["files"] == ["src/app.py"]
    cmd, kwargs = commands[0]
    assert cmd[1] == str(script_path)
    assert cmd[cmd.index("--analysis-mode") + 1] == "validation_script"
    assert cmd[cmd.index("--llm-temperature") + 1] == "0.0"
    assert cmd[cmd.index("--max-workers") + 1] == "1"
    assert "--require-llm" in cmd
    assert "--file-list" in cmd
    assert cmd[cmd.index("--exclude") + 1] == "vendor"
    assert cmd[cmd.index("--llm-provider") + 1] == "deepseek"
    assert cmd[cmd.index("--llm-model") + 1] == "deepseek-chat"
    record_path = Path(result["module_analysis_record_path"])
    assert record_path.exists()
    record = json.loads(record_path.read_text(encoding="utf-8"))
    assert record["analysis_mode"] == "validation_script"
    assert kwargs["cwd"]
