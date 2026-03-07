import json

from scanner.checker.skill_checker import SkillExploitabilityChecker


class _TestableChecker(SkillExploitabilityChecker):
    def _skill_exists(self):
        return True


def _checker():
    return _TestableChecker(timeout=1)


def test_infer_verdict_prefers_longer_tokens_first():
    checker = _checker()

    text = "This appears NOT_EXPLOITABLE, even if EXPLOITABLE appears in examples."
    assert checker._infer_verdict_from_text(text) == "NOT_EXPLOITABLE"


def test_parse_claude_result_from_markdown_json_block():
    checker = _checker()
    output = {
        "result": "```json\n{\"verdict\":\"EXPLOITABLE\",\"confidence\":\"high\"}\n```"
    }

    parsed = checker._parse_claude_result(output)

    assert parsed is not None
    assert parsed["verdict"] == "EXPLOITABLE"
    assert parsed["confidence"] == "high"


def test_parse_claude_result_fallback_to_inferred_verdict_and_confidence():
    checker = _checker()
    output = {
        "result": "Analysis: CONDITIONALLY_EXPLOITABLE with medium confidence. JSON omitted."
    }

    parsed = checker._parse_claude_result(output)

    assert parsed is not None
    assert parsed["verdict"] == "CONDITIONALLY_EXPLOITABLE"
    assert parsed["confidence"] == "medium"


def test_build_prompt_includes_output_json_path(tmp_path):
    checker = _checker()
    result_json_path = tmp_path / "analysis_output.json"

    prompt = checker._build_prompt(
        vuln={"file_path": "x.py", "vulnerability_type": "x", "evidence": "line", "description": "desc"},
        repo_path=tmp_path,
        result_json_path=result_json_path,
    )

    assert f"RESULT_JSON_PATH: {result_json_path.resolve()}" in prompt
    assert "write the same final JSON object to that path" in prompt
    assert "return JSON only on stdout" in prompt


def test_analyze_single_vuln_falls_back_to_output_file(monkeypatch, tmp_path):
    checker = _checker()
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()

    def fake_run_claude(prompt, record_path=None):
        (evidence_dir / "analysis_output.json").write_text(
            json.dumps({"verdict": "NOT_EXPLOITABLE", "confidence": "high"}),
            encoding="utf-8",
        )
        return False, None, {
            "selected_model": "deepseek-chat",
            "selected_model_usage": {"input_tokens": 10, "output_tokens": 20},
        }

    monkeypatch.setattr(checker, "_run_claude", fake_run_claude)

    result = checker._analyze_single_vuln(
        vuln={"file_path": "x.py", "vulnerability_type": "x"},
        finding_id="vuln_000",
        repo_path=tmp_path,
        evidence_dir=evidence_dir,
    )

    assert result["verdict"] == "NOT_EXPLOITABLE"
    assert result["confidence"] == "high"
    assert result["finding_id"] == "vuln_000"
    assert result["llm_usage"]["selected_model_usage"]["output_tokens"] == 20
    assert result["claude_cli_record_path"].endswith("claude_cli_invocation.json")


def test_analyze_single_vuln_ignores_stale_output_file(monkeypatch, tmp_path):
    checker = _checker()
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()

    # Pre-existing file from an earlier run should be ignored.
    (evidence_dir / "analysis_output.json").write_text(
        json.dumps({"verdict": "EXPLOITABLE", "confidence": "high"}),
        encoding="utf-8",
    )

    monkeypatch.setattr(checker, "_run_claude", lambda prompt, record_path=None: (False, None, {}))

    result = checker._analyze_single_vuln(
        vuln={"file_path": "x.py", "vulnerability_type": "x"},
        finding_id="vuln_000",
        repo_path=tmp_path,
        evidence_dir=evidence_dir,
    )

    assert result["verdict"] == "ERROR"
    assert result.get("error") == "Claude analysis failed"
    assert result["claude_cli_record_path"].endswith("claude_cli_invocation.json")


def test_run_claude_prefers_observed_model_usage_over_hint(monkeypatch, tmp_path):
    checker = _checker()

    class _Result:
        returncode = 0
        stdout = (
            '{"type":"result","subtype":"success","result":"ok","modelUsage":{'
            '"claude-sonnet-4-5":{"inputTokens":100,"outputTokens":200,"costUSD":1.0},'
            '"deepseek-chat":{"inputTokens":12,"outputTokens":34,"costUSD":0.1}}}'
        )
        stderr = ""

    def _fake_run(*args, **kwargs):
        return _Result()

    monkeypatch.setattr("utils.claude_cli.subprocess.run", _fake_run)

    success, payload, llm_usage = checker._run_claude(
        prompt="deepseek-backed run",
        record_path=tmp_path / "claude_cli_invocation.json",
    )

    assert success is True
    assert payload is not None
    assert llm_usage["selected_model"] == "claude-sonnet-4-5"
    assert llm_usage["selected_model_reason"] == "highest_usage_score"
    assert llm_usage["selected_model_usage"]["input_tokens"] == 100
    assert llm_usage["selected_model_usage"]["output_tokens"] == 200
    assert llm_usage["calls_total"] == 1


def test_run_claude_json_output_flag_error_counts_zero_llm_calls(monkeypatch, tmp_path):
    checker = _checker()
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

    success, payload, llm_usage = checker._run_claude(
        prompt="fallback run",
        record_path=tmp_path / "claude_cli_invocation.json",
    )

    assert success is False
    assert payload is None
    assert len(commands) == 1
    assert llm_usage["calls_total"] == 0


def test_run_claude_preserves_zero_calls_for_pre_spawn_failure(monkeypatch, tmp_path):
    checker = _checker()

    def _fake_run(*args, **kwargs):
        raise FileNotFoundError("claude not found")

    monkeypatch.setattr("utils.claude_cli.subprocess.run", _fake_run)

    success, payload, llm_usage = checker._run_claude(
        prompt="missing claude binary",
        record_path=tmp_path / "claude_cli_invocation.json",
    )

    assert success is False
    assert payload is None
    assert llm_usage["calls_total"] == 0


def test_build_docker_verification_from_evidence_confirmed(tmp_path):
    checker = _checker()
    evidence = tmp_path / "evidence"
    evidence.mkdir()

    (evidence / "Dockerfile.exploit").write_text("FROM python:3.11", encoding="utf-8")
    (evidence / "docker_build.log").write_text("writing image sha256:abc", encoding="utf-8")
    (evidence / "execution_output.txt").write_text("... VULNERABILITY_CONFIRMED ...", encoding="utf-8")
    (evidence / "exploit.py").write_text("print('x')", encoding="utf-8")

    dv = checker._build_docker_verification_from_evidence(evidence, commit_hash="abcdef123456")

    assert dv is not None
    assert dv["build_success"] is True
    assert dv["run_success"] is True
    assert dv["exploit_confirmed"] is True
    assert dv["error"] is None
    assert dv["docker_image"].startswith("exploit-test:")


def test_build_docker_verification_incomplete_build(tmp_path):
    checker = _checker()
    evidence = tmp_path / "evidence"
    evidence.mkdir()

    (evidence / "docker_build.log").write_text("some build output but no success marker", encoding="utf-8")

    dv = checker._build_docker_verification_from_evidence(evidence, commit_hash="")

    assert dv is not None
    assert dv["build_success"] is False
    assert dv["run_success"] is False
    assert "did not complete" in (dv["error"] or "")


def test_build_docker_verification_promotes_build_success_if_exec_exists(tmp_path):
    checker = _checker()
    evidence = tmp_path / "evidence"
    evidence.mkdir()

    (evidence / "docker_build.log").write_text("missing final marker", encoding="utf-8")
    (evidence / "execution_output.txt").write_text("PoC started but failed", encoding="utf-8")

    dv = checker._build_docker_verification_from_evidence(evidence, commit_hash="xyz")

    assert dv is not None
    assert dv["build_success"] is True
    assert dv["run_success"] is True
    assert dv["exploit_confirmed"] is False
    assert "did not confirm" in (dv["error"] or "")


def test_recover_docker_verification_upgrades_unknown_to_exploitable(tmp_path):
    checker = _checker()
    evidence = tmp_path / "evidence"
    evidence.mkdir()

    (evidence / "docker_build.log").write_text("writing image sha256:abc", encoding="utf-8")
    (evidence / "execution_output.txt").write_text("VULNERABILITY_CONFIRMED", encoding="utf-8")

    analysis = {"verdict": "UNKNOWN", "confidence": ""}
    recovered = checker._recover_docker_verification(analysis, evidence_dir=evidence, commit_hash="deadbeef")

    assert recovered["verdict"] == "EXPLOITABLE"
    assert recovered["confidence"] in ("high", "")
    assert recovered["docker_verification"]["exploit_confirmed"] is True


def test_update_summary_counts_unknown_as_error():
    checker = _checker()
    result_doc = {
        "results": [
            {"verdict": "EXPLOITABLE"},
            {"verdict": "UNKNOWN"},
            {"verdict": "NOT_EXPLOITABLE"},
        ]
    }

    checker._update_summary(result_doc)

    assert result_doc["summary"]["exploitable"] == 1
    assert result_doc["summary"]["not_exploitable"] == 1
    assert result_doc["summary"]["error"] == 1


def test_check_single_resumes_existing_results_and_processes_remaining(monkeypatch, tmp_path):
    checker = _checker()

    findings_path = tmp_path / "agentic_vuln_findings.json"
    findings_path.write_text(
        json.dumps(
            {
                "vulnerabilities": [
                    {"file_path": "a.py", "vulnerability_type": "x"},
                    {"file_path": "b.py", "vulnerability_type": "y"},
                ]
            }
        ),
        encoding="utf-8",
    )

    output_path = tmp_path / "exploitability.json"
    existing = {
        "metadata": {"started_at": "t", "completed_at": None},
        "summary": {},
        "results": [
            {
                "finding_id": "vuln_000",
                "verdict": "NOT_EXPLOITABLE",
                "original_finding": {"file_path": "a.py"},
            }
        ],
    }
    output_path.write_text(json.dumps(existing), encoding="utf-8")

    calls = []

    def fake_analyze_single_vuln(**kwargs):
        calls.append(kwargs["finding_id"])
        return {
            "finding_id": kwargs["finding_id"],
            "verdict": "EXPLOITABLE",
            "original_finding": kwargs["vuln"],
        }

    monkeypatch.setattr(checker, "_analyze_single_vuln", fake_analyze_single_vuln)

    result = checker.check_single(
        findings_path=findings_path,
        repo_path=tmp_path,
        output_path=output_path,
    )

    saved = json.loads(output_path.read_text(encoding="utf-8"))
    assert result["status"] == "success"
    assert calls == ["vuln_001"]
    assert len(saved["results"]) == 2
    assert saved["summary"]["exploitable"] == 1
    assert saved["summary"]["not_exploitable"] == 1


def test_check_single_writes_run_metadata(monkeypatch, tmp_path):
    checker = _checker()

    findings_path = tmp_path / "agentic_vuln_findings.json"
    findings_path.write_text(
        json.dumps(
            {"vulnerabilities": [{"file_path": "x.py", "vulnerability_type": "x"}]}
        ),
        encoding="utf-8",
    )
    output_path = tmp_path / "exploitability.json"
    runtime_dir = tmp_path / "claude-runtime" / "run-1"

    def fake_analyze_single_vuln(**kwargs):
        return {
            "finding_id": kwargs["finding_id"],
            "verdict": "NOT_EXPLOITABLE",
            "original_finding": kwargs["vuln"],
        }

    monkeypatch.setattr(checker, "_analyze_single_vuln", fake_analyze_single_vuln)

    result = checker.check_single(
        findings_path=findings_path,
        repo_path=tmp_path,
        output_path=output_path,
        run_id="run-1",
        claude_config_dir=runtime_dir,
    )

    saved = json.loads(output_path.read_text(encoding="utf-8"))
    assert result["status"] == "success"
    assert saved["metadata"]["run_id"] == "run-1"
    assert saved["metadata"]["claude_runtime_dir"] == str(runtime_dir)


def test_init_or_load_results_preserves_retried_usage_summary(tmp_path):
    checker = _checker()
    output_path = tmp_path / "exploitability.json"
    existing = {
        "metadata": {
            "started_at": "t",
            "completed_at": None,
            "llm_usage_retried_attempts_summary": {
                "selected_model": "deepseek-chat",
                "selected_models": ["deepseek-chat"],
                "calls_total": 1,
                "calls_with_selected_model_usage": 1,
                "calls_with_top_level_usage_fallback": 0,
                "calls_missing_selected_model_usage": 0,
                "calls_missing_usage": 0,
                "input_tokens": 2,
                "output_tokens": 3,
                "cache_read_input_tokens": 4,
                "cache_creation_input_tokens": 5,
                "cost_usd": 0.1,
            },
        },
        "summary": {},
        "results": [
            {
                "finding_id": "vuln_000",
                "verdict": "NOT_EXPLOITABLE",
                "llm_usage": {
                    "selected_model_usage": {
                        "model": "deepseek-chat",
                        "input_tokens": 10,
                        "output_tokens": 20,
                        "cache_read_input_tokens": 30,
                        "cache_creation_input_tokens": 40,
                        "cost_usd": 0.5,
                    },
                },
            },
            {
                "finding_id": "vuln_001",
                "verdict": "ERROR",
                "llm_usage": {
                    "selected_model_usage": {
                        "model": "deepseek-chat",
                        "input_tokens": 1,
                        "output_tokens": 2,
                        "cache_read_input_tokens": 3,
                        "cache_creation_input_tokens": 4,
                        "cost_usd": 0.25,
                    },
                },
            },
        ],
    }
    output_path.write_text(json.dumps(existing), encoding="utf-8")

    loaded = checker._init_or_load_results(
        output_path=output_path,
        findings_path=tmp_path / "findings.json",
        repo_path=tmp_path,
        software_profile_path=None,
        total_vulns=2,
    )

    assert len(loaded["results"]) == 1
    retried = loaded["metadata"]["llm_usage_retried_attempts_summary"]
    assert retried["calls_total"] == 2
    assert retried["input_tokens"] == 3
    assert retried["output_tokens"] == 5

    total = loaded["metadata"]["llm_usage_summary"]
    assert total["calls_total"] == 3
    assert total["input_tokens"] == 13
    assert total["output_tokens"] == 25


def test_update_summary_aggregates_llm_usage():
    checker = _checker()
    result_doc = {
        "metadata": {
            "llm_usage_retried_attempts_summary": {
                "selected_model": "deepseek-chat",
                "selected_models": ["deepseek-chat"],
                "calls_total": 1,
                "calls_with_selected_model_usage": 1,
                "calls_with_top_level_usage_fallback": 0,
                "calls_missing_selected_model_usage": 0,
                "calls_missing_usage": 0,
                "input_tokens": 100,
                "output_tokens": 200,
                "cache_read_input_tokens": 300,
                "cache_creation_input_tokens": 400,
                "cost_usd": 1.5,
            },
        },
        "results": [
            {
                "verdict": "EXPLOITABLE",
                "llm_usage": {
                    "selected_model": "deepseek-chat",
                    "selected_model_usage": {
                        "input_tokens": 11,
                        "output_tokens": 22,
                        "cache_read_input_tokens": 33,
                        "cache_creation_input_tokens": 44,
                        "cost_usd": 0.5,
                    },
                },
            },
            {
                "verdict": "NOT_EXPLOITABLE",
                "llm_usage": {
                    "selected_model": "deepseek-chat",
                    "selected_model_usage": {
                        "input_tokens": 1,
                        "output_tokens": 2,
                        "cache_read_input_tokens": 3,
                        "cache_creation_input_tokens": 4,
                        "cost_usd": 0.25,
                    },
                },
            },
        ],
    }

    checker._update_summary(result_doc)

    usage_summary = result_doc["metadata"]["llm_usage_summary"]
    assert usage_summary["calls_with_selected_model_usage"] == 3
    assert usage_summary["input_tokens"] == 112
    assert usage_summary["output_tokens"] == 224
    assert usage_summary["cost_usd"] == 2.25


def test_update_summary_ignores_zero_call_llm_usage():
    checker = _checker()
    result_doc = {
        "metadata": {
            "llm_usage_retried_attempts_summary": {
                "selected_model": None,
                "selected_models": [],
                "calls_total": 0,
                "calls_with_selected_model_usage": 0,
                "calls_with_top_level_usage_fallback": 0,
                "calls_missing_selected_model_usage": 0,
                "calls_missing_usage": 0,
                "input_tokens": 0,
                "output_tokens": 0,
                "cache_read_input_tokens": 0,
                "cache_creation_input_tokens": 0,
                "cost_usd": 0.0,
                "request_cost_usd": 0.0,
            },
        },
        "results": [
            {
                "verdict": "ERROR",
                "llm_usage": {
                    "source": "claude_cli",
                    "calls_total": 0,
                    "selected_model_usage": None,
                    "top_level_usage": None,
                },
            },
            {
                "verdict": "EXPLOITABLE",
                "llm_usage": {
                    "source": "claude_cli",
                    "calls_total": 1,
                    "selected_model": "deepseek-chat",
                    "selected_model_usage": {
                        "model": "deepseek-chat",
                        "input_tokens": 11,
                        "output_tokens": 22,
                        "cache_read_input_tokens": 33,
                        "cache_creation_input_tokens": 44,
                        "cost_usd": 0.5,
                    },
                },
            },
        ],
    }

    checker._update_summary(result_doc)

    usage_summary = result_doc["metadata"]["llm_usage_summary"]
    assert usage_summary["calls_total"] == 1
    assert usage_summary["calls_with_selected_model_usage"] == 1
    assert usage_summary["calls_missing_usage"] == 0
    assert usage_summary["input_tokens"] == 11
    assert usage_summary["output_tokens"] == 22


def test_init_or_load_results_ignores_zero_call_retried_results(tmp_path):
    checker = _checker()
    output_path = tmp_path / "exploitability.json"
    existing = {
        "metadata": {
            "started_at": "t",
            "completed_at": None,
            "llm_usage_retried_attempts_summary": {
                "selected_model": None,
                "selected_models": [],
                "calls_total": 0,
                "calls_with_selected_model_usage": 0,
                "calls_with_top_level_usage_fallback": 0,
                "calls_missing_selected_model_usage": 0,
                "calls_missing_usage": 0,
                "input_tokens": 0,
                "output_tokens": 0,
                "cache_read_input_tokens": 0,
                "cache_creation_input_tokens": 0,
                "cost_usd": 0.0,
                "request_cost_usd": 0.0,
            },
        },
        "summary": {},
        "results": [
            {
                "finding_id": "vuln_000",
                "verdict": "ERROR",
                "llm_usage": {
                    "source": "claude_cli",
                    "calls_total": 0,
                    "selected_model_usage": None,
                    "top_level_usage": None,
                },
            },
            {
                "finding_id": "vuln_001",
                "verdict": "NOT_EXPLOITABLE",
                "llm_usage": {
                    "source": "claude_cli",
                    "calls_total": 1,
                    "selected_model_usage": {
                        "model": "deepseek-chat",
                        "input_tokens": 3,
                        "output_tokens": 4,
                        "cache_read_input_tokens": 0,
                        "cache_creation_input_tokens": 0,
                        "cost_usd": 0.1,
                    },
                },
            },
        ],
    }
    output_path.write_text(json.dumps(existing), encoding="utf-8")

    loaded = checker._init_or_load_results(
        output_path=output_path,
        findings_path=tmp_path / "findings.json",
        repo_path=tmp_path,
        software_profile_path=None,
        total_vulns=2,
    )

    assert len(loaded["results"]) == 1
    retried = loaded["metadata"]["llm_usage_retried_attempts_summary"]
    assert retried["calls_total"] == 0
    total = loaded["metadata"]["llm_usage_summary"]
    assert total["calls_total"] == 1
    assert total["input_tokens"] == 3
    assert total["output_tokens"] == 4
