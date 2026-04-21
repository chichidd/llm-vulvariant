import json
import re
from pathlib import Path

from scanner.checker.threat_model_guardrails import (
    apply_threat_model_guardrails,
    extract_threat_model_facts,
)
from scanner.checker.skill_checker import (
    SkillExploitabilityChecker,
    compute_findings_signature,
    get_exploitability_output_state,
    get_exploitability_output_state_for_findings,
    order_findings_stably,
)


class _TestableChecker(SkillExploitabilityChecker):
    def _skill_exists(self):
        return True


def _checker():
    return _TestableChecker(timeout=1)


def _findings_context(vulnerabilities):
    current_findings = {
        f"vuln_{idx:03d}": vuln
        for idx, vuln in enumerate(order_findings_stably(vulnerabilities))
    }
    return current_findings, compute_findings_signature(vulnerabilities)


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


def test_parse_claude_result_rejects_free_text_without_json():
    checker = _checker()
    output = {
        "result": "Analysis: CONDITIONALLY_EXPLOITABLE with medium confidence. JSON omitted."
    }

    parsed = checker._parse_claude_result(output)

    assert parsed is None


def test_parse_claude_result_treats_schema_only_output_as_parse_failure():
    checker = _checker()
    output = {
        "result": (
            'Schema: {"verdict":"EXPLOITABLE|CONDITIONALLY_EXPLOITABLE|LIBRARY_RISK|NOT_EXPLOITABLE",'
            '"confidence":"high|medium|low"}'
        )
    }

    parsed = checker._parse_claude_result(output)

    assert parsed is None


def test_parse_claude_result_accepts_schema_compliant_prefix():
    checker = _checker()
    output = {
        "result": 'Schema-compliant: {"verdict":"NOT_EXPLOITABLE","confidence":"high"}'
    }

    parsed = checker._parse_claude_result(output)

    assert parsed is not None
    assert parsed["verdict"] == "NOT_EXPLOITABLE"
    assert parsed["confidence"] == "high"


def test_parse_claude_result_accepts_schema_prefixed_final_json():
    checker = _checker()
    output = {
        "result": 'Schema: {"verdict":"NOT_EXPLOITABLE","confidence":"high"}'
    }

    parsed = checker._parse_claude_result(output)

    assert parsed is not None
    assert parsed["verdict"] == "NOT_EXPLOITABLE"
    assert parsed["confidence"] == "high"


def test_parse_claude_result_accepts_output_schema_prefixed_final_json():
    checker = _checker()
    output = {
        "result": 'Output schema: {"verdict":"NOT_EXPLOITABLE","confidence":"high"}'
    }

    parsed = checker._parse_claude_result(output)

    assert parsed is not None
    assert parsed["verdict"] == "NOT_EXPLOITABLE"
    assert parsed["confidence"] == "high"


def test_parse_claude_result_normalizes_separator_variants_in_json_payload():
    checker = _checker()

    cases = [
        ("NOT EXPLOITABLE", "NOT_EXPLOITABLE"),
        ("Library Risk", "LIBRARY_RISK"),
        ("conditionally-exploitable", "CONDITIONALLY_EXPLOITABLE"),
    ]
    for raw_verdict, normalized_verdict in cases:
        parsed = checker._parse_claude_result(
            {"result": json.dumps({"verdict": raw_verdict, "confidence": "high"})}
        )

        assert parsed is not None
        assert parsed["verdict"] == normalized_verdict
        assert parsed["confidence"] == "high"


def test_parse_claude_result_ignores_non_analysis_json_prefix():
    checker = _checker()
    output = {
        "result": 'intro {"note":"tmp"} Actual answer: EXPLOITABLE with high confidence.'
    }

    parsed = checker._parse_claude_result(output)

    assert parsed is None


def test_parse_claude_result_rejects_invalid_confidence_values():
    checker = _checker()
    output = {
        "result": '{"verdict":"EXPLOITABLE","confidence":"very_high"}'
    }

    parsed = checker._parse_claude_result(output)

    assert parsed is None


def test_parse_claude_result_skips_schema_echo_before_actual_analysis():
    checker = _checker()
    output = {
        "result": (
            'Schema: {"verdict":"EXPLOITABLE|CONDITIONALLY_EXPLOITABLE|LIBRARY_RISK|NOT_EXPLOITABLE",'
            '"confidence":"high|medium|low"}\n'
            'Final: {"verdict":"NOT_EXPLOITABLE","confidence":"medium"}'
        )
    }

    parsed = checker._parse_claude_result(output)

    assert parsed is not None
    assert parsed["verdict"] == "NOT_EXPLOITABLE"
    assert parsed["confidence"] == "medium"


def test_parse_claude_result_keeps_final_json_after_schema_echo_without_final_prefix():
    checker = _checker()
    output = {
        "result": (
            'Schema: {"verdict":"EXPLOITABLE|CONDITIONALLY_EXPLOITABLE|LIBRARY_RISK|NOT_EXPLOITABLE",'
            '"confidence":"high|medium|low"}\n'
            '{"verdict":"NOT_EXPLOITABLE","confidence":"high"}'
        )
    }

    parsed = checker._parse_claude_result(output)

    assert parsed is not None
    assert parsed["verdict"] == "NOT_EXPLOITABLE"
    assert parsed["confidence"] == "high"


def test_parse_claude_result_skips_inline_example_json_before_text_verdict():
    checker = _checker()
    output = {
        "result": (
            'Example format: {"verdict":"EXPLOITABLE","confidence":"high"}\n'
            "Actual verdict: NOT_EXPLOITABLE with medium confidence."
        )
    }

    parsed = checker._parse_claude_result(output)

    assert parsed is None


def test_parse_claude_result_keeps_final_json_with_format_prefix():
    checker = _checker()
    output = {
        "result": (
            'JSON format:\n'
            '{"verdict":"NOT_EXPLOITABLE","confidence":"high",'
            '"sink_analysis":{"confirmed":false,"sink_type":"cmd","protection_status":"full"}}'
        )
    }

    parsed = checker._parse_claude_result(output)

    assert parsed is not None
    assert parsed["verdict"] == "NOT_EXPLOITABLE"
    assert parsed["confidence"] == "high"
    assert parsed["sink_analysis"]["sink_type"] == "cmd"


def test_parse_claude_result_keeps_structured_json_when_summary_prose_follows():
    checker = _checker()
    output = {
        "result": (
            '{"verdict":"NOT_EXPLOITABLE","confidence":"high",'
            '"sink_analysis":{"confirmed":false,"sink_type":"cmd","protection_status":"full"},'
            '"source_analysis":{"sources_found":[{"type":"api","location":"handler"}],"attack_path":["entry","sink"]},'
            '"attack_scenario":{"description":"validated input blocks exploit","steps":["review flow"],"impact":"none"}}\n'
            "Final verdict: NOT_EXPLOITABLE."
        )
    }

    parsed = checker._parse_claude_result(output)

    assert parsed is not None
    assert parsed["verdict"] == "NOT_EXPLOITABLE"
    assert parsed["confidence"] == "high"
    assert parsed["sink_analysis"]["sink_type"] == "cmd"
    assert parsed["source_analysis"]["attack_path"] == ["entry", "sink"]
    assert parsed["attack_scenario"]["impact"] == "none"


def test_parse_claude_result_keeps_structured_unknown_json():
    checker = _checker()
    output = {
        "result": (
            '{"verdict":"UNKNOWN","confidence":"low",'
            '"sink_analysis":{"confirmed":false,"sink_type":"cmd","protection_status":"partial"},'
            '"source_analysis":{"sources_found":[],"attack_path":[]},'
            '"attack_scenario":{"description":"needs more evidence","steps":[],"impact":"unclear"}}'
        )
    }

    parsed = checker._parse_claude_result(output)

    assert parsed is not None
    assert parsed["verdict"] == "UNKNOWN"
    assert parsed["sink_analysis"]["protection_status"] == "partial"
    assert parsed["attack_scenario"]["impact"] == "unclear"


def test_build_prompt_uses_ny_api_key_when_openai_proxy_env_is_set(monkeypatch, tmp_path):
    checker = _checker()
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("NY_API_KEY", "ny-proxy-key")

    prompt = checker._build_prompt(
        vuln={
            "file_path": "src/app.py",
            "vulnerability_type": "command_injection",
            "evidence": "dangerous",
            "description": "unsafe input",
        },
        repo_path=tmp_path,
    )

    assert "NY_API_KEY" in prompt
    assert "-e DEEPSEEK_API_KEY -e OPENAI_API_KEY -e NY_API_KEY" in prompt
    assert 'DEEPSEEK_API_KEY="<API_KEY>"' not in prompt
    assert 'OPENAI_API_KEY="<API_KEY>"' not in prompt
    assert "ny-proxy-key" not in prompt


def test_build_prompt_requests_structured_evidence_contract(tmp_path):
    checker = _checker()

    prompt = checker._build_prompt(
        vuln={
            "file_path": "src/app.py",
            "vulnerability_type": "command_injection",
            "evidence": "dangerous",
            "description": "unsafe input",
        },
        repo_path=tmp_path,
    )

    assert '"verdict_rationale":"..."' in prompt
    assert '"preconditions":["..."]' in prompt
    assert '"static_evidence":["..."]' in prompt
    assert '"dynamic_plan":["..."]' in prompt
    assert '"docker_verification":{' in prompt
    assert '"open_questions":["..."]' in prompt
    assert "Ground every claim in the provided repository evidence." in prompt
    assert "If evidence is missing, say so explicitly in the relevant field." in prompt


def test_build_prompt_includes_full_finding_context_and_general_verification_contract(tmp_path):
    checker = _checker()
    evidence = "dangerous evidence " + ("A" * 450) + " evidence-tail"
    description = "unsafe description " + ("B" * 250) + " description-tail"

    prompt = checker._build_prompt(
        vuln={
            "file_path": "src/app.py",
            "function_name": "run",
            "line_number": 42,
            "vulnerability_type": "unsafe_deserialization",
            "evidence": evidence,
            "description": description,
            "similarity_to_known": "same source-to-sink pattern as the reference",
            "attack_scenario": "attacker publishes a malicious shared checkpoint",
        },
        repo_path=tmp_path,
    )

    assert "Function: run" in prompt
    assert "Line: 42" in prompt
    assert "evidence-tail" in prompt
    assert "description-tail" in prompt
    assert "Similarity to known: same source-to-sink pattern as the reference" in prompt
    assert "Attack scenario: attacker publishes a malicious shared checkpoint" in prompt
    assert re.search(r"\brq\d+\b", prompt, flags=re.IGNORECASE) is None
    assert "security claim verification contract" in prompt
    assert "attacker-controlled source" in prompt
    assert "trust boundary" in prompt
    assert "sink semantics" in prompt
    assert "protection analysis" in prompt
    assert "security impact" in prompt
    assert "counterevidence" in prompt


def test_build_prompt_handles_missing_evidence_and_description(tmp_path):
    checker = _checker()

    prompt = checker._build_prompt(
        vuln={
            "file_path": "src/a.py",
            "vulnerability_type": "command_injection",
            "evidence": None,
            "description": None,
        },
        repo_path=tmp_path,
    )

    assert "Evidence: " in prompt
    assert "Description: " in prompt


def test_parse_claude_result_promotes_string_evidence_fields_to_single_item_lists():
    checker = _checker()
    output = {
        "result": json.dumps(
            {
                "verdict": "NOT_EXPLOITABLE",
                "confidence": "medium",
                "verdict_rationale": "Input never reaches an executable sink.",
                "preconditions": "Attacker controls the CLI argument.",
                "static_evidence": "cli.py validates the argument before dispatch.",
                "dynamic_plan": "Try to pass shell metacharacters through the CLI wrapper.",
                "open_questions": "Whether another entry point bypasses the wrapper.",
            }
        )
    }

    parsed = checker._parse_claude_result(output)

    assert parsed is not None
    assert parsed["preconditions"] == ["Attacker controls the CLI argument."]
    assert parsed["static_evidence"] == ["cli.py validates the argument before dispatch."]
    assert parsed["dynamic_plan"] == ["Try to pass shell metacharacters through the CLI wrapper."]
    assert parsed["open_questions"] == ["Whether another entry point bypasses the wrapper."]


def test_strip_inline_json_objects_removes_nested_payload_once():
    checker = _checker()
    text = (
        '{"verdict":"NOT_EXPLOITABLE","sink_analysis":{"confirmed":false,"sink_type":"cmd"}} '
        "Final verdict: NOT_EXPLOITABLE."
    )

    stripped = checker._strip_inline_json_objects(text)

    assert stripped == "Final verdict: NOT_EXPLOITABLE."


def test_load_analysis_from_output_path_requires_verdict(tmp_path):
    checker = _checker()
    output_json_path = tmp_path / "analysis_output.json"
    output_json_path.write_text('{"note":"tmp"}', encoding="utf-8")

    parsed = checker._load_analysis_from_output_path(output_json_path)

    assert parsed is None


def test_load_analysis_from_output_path_skips_schema_echo(tmp_path):
    checker = _checker()
    output_json_path = tmp_path / "analysis_output.json"
    output_json_path.write_text(
        (
            '{"verdict":"EXPLOITABLE|CONDITIONALLY_EXPLOITABLE|LIBRARY_RISK|NOT_EXPLOITABLE",'
            '"confidence":"high|medium|low"}\n'
            '{"verdict":"EXPLOITABLE","confidence":"high"}'
        ),
        encoding="utf-8",
    )

    parsed = checker._load_analysis_from_output_path(output_json_path)

    assert parsed is not None
    assert parsed["verdict"] == "EXPLOITABLE"
    assert parsed["confidence"] == "high"


def test_load_analysis_from_output_path_keeps_structured_error_json(tmp_path):
    checker = _checker()
    output_json_path = tmp_path / "analysis_output.json"
    output_json_path.write_text(
        json.dumps(
            {
                "verdict": "ERROR",
                "confidence": "low",
                "sink_analysis": {"confirmed": False, "sink_type": "cmd", "protection_status": "none"},
                "source_analysis": {"sources_found": [], "attack_path": []},
                "attack_scenario": {"description": "tool failed", "steps": [], "impact": "unknown"},
            }
        ),
        encoding="utf-8",
    )

    parsed = checker._load_analysis_from_output_path(output_json_path)

    assert parsed is not None
    assert parsed["verdict"] == "ERROR"
    assert parsed["attack_scenario"]["description"] == "tool failed"


def test_create_error_vuln_result_includes_structured_evidence_fields():
    checker = _checker()

    result = checker._create_error_vuln_result(
        vuln={"file_path": "src/app.py"},
        finding_id="vuln_000",
        error_msg="Claude analysis failed",
    )

    assert result["verdict"] == "ERROR"
    assert result["verdict_rationale"] == "Claude analysis failed"
    assert result["preconditions"] == []
    assert result["static_evidence"] == []
    assert result["dynamic_plan"] == []
    assert result["docker_verification"] is None
    assert result["open_questions"] == []


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


def test_build_prompt_includes_verification_guardrails(tmp_path):
    checker = _checker()

    prompt = checker._build_prompt(
        vuln={"file_path": "x.py", "vulnerability_type": "x", "evidence": "line", "description": "desc"},
        repo_path=tmp_path,
    )

    assert "Do not count simulated, simplified, source-reading, or echo-only PoCs as verified exploitation." in prompt
    assert "If output contains EXPLOIT_FAILED, the verification must not be marked as verified." in prompt
    assert "Treat trusted-local-only config/example/test inputs conservatively" in prompt


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


def test_analyze_single_vuln_falls_back_to_output_file_when_stdout_is_schema_echo(monkeypatch, tmp_path):
    checker = _checker()
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()

    def fake_run_claude(prompt, record_path=None):
        (evidence_dir / "analysis_output.json").write_text(
            json.dumps({"verdict": "NOT_EXPLOITABLE", "confidence": "high"}),
            encoding="utf-8",
        )
        return True, {
            "result": (
                'Schema: {"verdict":"EXPLOITABLE|CONDITIONALLY_EXPLOITABLE|LIBRARY_RISK|NOT_EXPLOITABLE",'
                '"confidence":"high|medium|low"}'
            )
        }, {
            "selected_model": "deepseek-chat",
            "selected_model_usage": {"input_tokens": 11, "output_tokens": 22},
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
    assert result["llm_usage"]["selected_model_usage"]["output_tokens"] == 22


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


def test_analyze_single_vuln_ignores_stale_docker_evidence_from_previous_attempt(monkeypatch, tmp_path):
    checker = _checker()
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()

    (evidence_dir / "docker_build.log").write_text("writing image sha256:abc", encoding="utf-8")
    (evidence_dir / "execution_output.txt").write_text("VULNERABILITY_CONFIRMED", encoding="utf-8")
    (evidence_dir / "exploit.py").write_text("print('stale')", encoding="utf-8")

    monkeypatch.setattr(checker, "_run_claude", lambda prompt, record_path=None: (False, None, {}))

    result = checker._analyze_single_vuln(
        vuln={"file_path": "x.py", "vulnerability_type": "x"},
        finding_id="vuln_000",
        repo_path=tmp_path,
        evidence_dir=evidence_dir,
    )

    assert result["verdict"] == "ERROR"
    assert result.get("error") == "Claude analysis failed"


def test_analyze_single_vuln_fails_closed_when_result_path_prep_fails(monkeypatch, tmp_path):
    checker = _checker()
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    (evidence_dir / "analysis_output.json").write_text(
        json.dumps({"verdict": "EXPLOITABLE", "confidence": "high"}),
        encoding="utf-8",
    )

    claude_calls = []

    def _raise_prepare_error(result_json_path: Path) -> None:
        claude_calls.append(str(result_json_path))
        raise RuntimeError("Failed to prepare result file")

    def _unexpected_run(prompt, record_path=None):
        raise AssertionError("Claude should not run when result path preparation fails")

    monkeypatch.setattr(checker, "_prepare_result_json_path", _raise_prepare_error)
    monkeypatch.setattr(checker, "_run_claude", _unexpected_run)

    result = checker._analyze_single_vuln(
        vuln={"file_path": "x.py", "vulnerability_type": "x"},
        finding_id="vuln_000",
        repo_path=tmp_path,
        evidence_dir=evidence_dir,
    )

    assert claude_calls == [str(evidence_dir / "analysis_output.json")]
    assert result["verdict"] == "ERROR"
    assert "Failed to prepare result file" in result.get("error", "")
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
    assert llm_usage["calls_total"] == 1


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
    assert dv["verification_verdict"] == "VERIFIED_EXPLOITABLE"
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
    assert dv["verification_verdict"] == "VERIFICATION_FAILED"
    assert "did not confirm" in (dv["error"] or "")


def test_build_docker_verification_rejects_failed_marker_even_with_confirmation_token(tmp_path):
    checker = _checker()
    evidence = tmp_path / "evidence"
    evidence.mkdir()

    (evidence / "Dockerfile.exploit").write_text("FROM python:3.11", encoding="utf-8")
    (evidence / "docker_build.log").write_text("writing image sha256:abc", encoding="utf-8")
    (evidence / "execution_output.txt").write_text(
        "VULNERABILITY_CONFIRMED: looked promising\nEXPLOIT_FAILED: command never reached real sink",
        encoding="utf-8",
    )

    dv = checker._build_docker_verification_from_evidence(evidence, commit_hash="deadbeef")

    assert dv is not None
    assert dv["run_success"] is True
    assert dv["exploit_confirmed"] is False
    assert dv["verification_verdict"] == "VERIFICATION_FAILED"
    assert "EXPLOIT_FAILED" in (dv["error"] or "")


def test_build_docker_verification_rejects_simulated_poc_output(tmp_path):
    checker = _checker()
    evidence = tmp_path / "evidence"
    evidence.mkdir()

    (evidence / "Dockerfile.exploit").write_text("FROM python:3.11", encoding="utf-8")
    (evidence / "docker_build.log").write_text("writing image sha256:abc", encoding="utf-8")
    (evidence / "execution_output.txt").write_text(
        "Simulated exploit:\n"
        "Testing with: echo 'VULNERABILITY_CONFIRMED: demo'\n"
        "VULNERABILITY_CONFIRMED: demo",
        encoding="utf-8",
    )

    dv = checker._build_docker_verification_from_evidence(evidence, commit_hash="feedface")

    assert dv is not None
    assert dv["run_success"] is True
    assert dv["exploit_confirmed"] is False
    assert dv["verification_verdict"] == "VERIFICATION_FAILED"
    assert "simulated" in (dv["error"] or "").lower()


def test_build_docker_verification_downgrades_structured_verified_output_with_failure_markers(tmp_path):
    checker = _checker()
    evidence = tmp_path / "evidence"
    evidence.mkdir()

    (evidence / "analysis_output.json").write_text(
        json.dumps(
            {
                "docker_verification": {
                    "verification_verdict": "VERIFIED_EXPLOITABLE",
                    "build_success": True,
                    "run_success": True,
                    "exploit_confirmed": True,
                    "execution_output": "VULNERABILITY_CONFIRMED\nEXPLOIT_FAILED: simulated failure",
                }
            }
        ),
        encoding="utf-8",
    )

    dv = checker._build_docker_verification_from_evidence(evidence, commit_hash="b16b00b5")

    assert dv is not None
    assert dv["exploit_confirmed"] is False
    assert dv["verification_verdict"] == "VERIFICATION_FAILED"
    assert "EXPLOIT_FAILED" in (dv["error"] or "")


def test_build_docker_verification_ignores_placeholder_structured_output_without_real_activity(tmp_path):
    checker = _checker()
    evidence = tmp_path / "evidence"
    evidence.mkdir()

    (evidence / "analysis_output.json").write_text(
        json.dumps(
            {
                "docker_verification": {
                    "enabled": False,
                    "verification_verdict": "VERIFICATION_FAILED",
                }
            }
        ),
        encoding="utf-8",
    )

    dv = checker._build_docker_verification_from_evidence(evidence, commit_hash="deadbeef")

    assert dv is None


def test_build_docker_verification_prefers_real_runtime_evidence_over_stale_structured_verdict(tmp_path):
    checker = _checker()
    evidence = tmp_path / "evidence"
    evidence.mkdir()

    (evidence / "analysis_output.json").write_text(
        json.dumps(
            {
                "docker_verification": {
                    "verification_verdict": "VERIFICATION_FAILED",
                    "build_success": True,
                    "run_success": True,
                    "exploit_confirmed": False,
                }
            }
        ),
        encoding="utf-8",
    )
    (evidence / "docker_build.log").write_text("writing image sha256:abc", encoding="utf-8")
    (evidence / "execution_output.txt").write_text("VULNERABILITY_CONFIRMED", encoding="utf-8")

    dv = checker._build_docker_verification_from_evidence(evidence, commit_hash="deadbeef")

    assert dv is not None
    assert dv["build_success"] is True
    assert dv["run_success"] is True
    assert dv["exploit_confirmed"] is True
    assert dv["verification_verdict"] == "VERIFIED_EXPLOITABLE"


def test_recover_docker_verification_upgrades_retryable_verdict_when_runtime_confirms_exploit(tmp_path):
    checker = _checker()
    evidence = tmp_path / "evidence"
    evidence.mkdir()

    (evidence / "docker_build.log").write_text("writing image sha256:abc", encoding="utf-8")
    (evidence / "execution_output.txt").write_text("VULNERABILITY_CONFIRMED", encoding="utf-8")

    analysis = {
        "verdict": "UNKNOWN",
        "confidence": "",
        "docker_verification": {"verification_verdict": ""},
    }
    recovered = checker._recover_docker_verification(analysis, evidence_dir=evidence, commit_hash="deadbeef")

    assert recovered["verdict"] == "EXPLOITABLE"
    assert recovered["confidence"] == "high"
    assert recovered["docker_verification"]["exploit_confirmed"] is True
    assert recovered["docker_verification"]["verification_verdict"] == "VERIFIED_EXPLOITABLE"


def test_recover_docker_verification_prefers_on_disk_failure_markers_over_stale_claude_success(tmp_path):
    checker = _checker()
    evidence = tmp_path / "evidence"
    evidence.mkdir()

    (evidence / "docker_build.log").write_text("writing image sha256:abc", encoding="utf-8")
    (evidence / "execution_output.txt").write_text(
        "VULNERABILITY_CONFIRMED\nEXPLOIT_FAILED: simulated failure marker from runtime output",
        encoding="utf-8",
    )

    analysis = {
        "verdict": "EXPLOITABLE",
        "confidence": "high",
        "docker_verification": {
            "verification_verdict": "VERIFIED_EXPLOITABLE",
            "build_success": True,
            "run_success": True,
            "exploit_confirmed": True,
            "execution_output": "VULNERABILITY_CONFIRMED",
        },
    }

    recovered = checker._recover_docker_verification(
        analysis,
        evidence_dir=evidence,
        commit_hash="deadbeef",
    )

    assert recovered["docker_verification"]["build_success"] is True
    assert recovered["docker_verification"]["run_success"] is True
    assert recovered["docker_verification"]["exploit_confirmed"] is False
    assert recovered["docker_verification"]["verification_verdict"] == "VERIFICATION_FAILED"
    assert "EXPLOIT_FAILED" in (recovered["docker_verification"]["error"] or "")


def test_recover_docker_verification_prefers_on_disk_success_over_stale_claude_failure(tmp_path):
    checker = _checker()
    evidence = tmp_path / "evidence"
    evidence.mkdir()

    (evidence / "docker_build.log").write_text("writing image sha256:abc", encoding="utf-8")
    (evidence / "execution_output.txt").write_text("VULNERABILITY_CONFIRMED", encoding="utf-8")

    analysis = {
        "verdict": "EXPLOITABLE",
        "confidence": "high",
        "docker_verification": {
            "verification_verdict": "VERIFICATION_FAILED",
            "build_success": True,
            "run_success": True,
            "exploit_confirmed": False,
            "execution_output": "EXPLOIT_FAILED",
            "error": "old failure",
        },
    }

    recovered = checker._recover_docker_verification(
        analysis,
        evidence_dir=evidence,
        commit_hash="deadbeef",
    )

    assert recovered["docker_verification"]["build_success"] is True
    assert recovered["docker_verification"]["run_success"] is True
    assert recovered["docker_verification"]["exploit_confirmed"] is True
    assert recovered["docker_verification"]["verification_verdict"] == "VERIFIED_EXPLOITABLE"
    assert recovered["docker_verification"]["error"] is None


def test_apply_threat_model_guardrails_downgrades_developer_local_scripts():
    checker = _checker()
    analysis = {
        "verdict": "EXPLOITABLE",
        "confidence": "high",
        "verdict_rationale": "Shell injection is possible.",
        "preconditions": ["User runs script with --config malicious.json"],
        "source_analysis": {
            "sources_found": [{"type": "file", "location": "JSON configuration file provided via --config"}],
            "attack_path": ["exp.py parse_args()", "subprocess.Popen()"],
        },
        "attack_scenario": {
            "description": "Attacker supplies a local config file to the script.",
            "steps": ["1. Create malicious config", "2. User runs local script"],
        },
        "docker_verification": {
            "verification_verdict": "VERIFIED_EXPLOITABLE",
            "exploit_confirmed": True,
        },
    }
    vuln = {"file_path": "scripts/benchmark/exp_utils.py"}

    guarded = checker._apply_threat_model_guardrails(analysis, vuln)

    assert guarded["verdict"] == "LIBRARY_RISK"
    assert guarded["confidence"] == "medium"
    assert "Threat-model guardrail" in guarded["verdict_rationale"]
    assert guarded["docker_verification"]["verification_verdict"] == "NOT_VERIFIED"
    assert guarded["docker_verification"]["exploit_confirmed"] is False


def test_apply_threat_model_guardrails_avoids_false_public_hint_matches_inside_filenames():
    checker = _checker()
    analysis = {
        "verdict": "EXPLOITABLE",
        "confidence": "high",
        "source_analysis": {
            "sources_found": [
                {"type": "cli", "location": "args.config (JSON config file path)"},
                {"type": "file", "location": "JSON config file content (args dictionary)"},
            ],
            "attack_path": [
                "exp.py:parse_args()",
                "exp_utils.py:_build_cmd()/_build_eval_cmd()",
                "exp_utils.py:run()",
            ],
        },
        "attack_scenario": {
            "description": "Command injection via malicious JSON configuration file",
            "steps": ["User runs python exp.py --config malicious.json"],
        },
        "docker_verification": {
            "verification_verdict": "NOT_VERIFIED",
            "exploit_confirmed": False,
        },
    }
    vuln = {"file_path": "scripts/benchmark/exp_utils.py"}

    guarded = checker._apply_threat_model_guardrails(analysis, vuln)

    assert guarded["verdict"] == "LIBRARY_RISK"


def test_apply_threat_model_guardrails_does_not_treat_web_ui_identifier_as_public_exposure():
    checker = _checker()
    analysis = {
        "verdict": "EXPLOITABLE",
        "confidence": "high",
        "verdict_rationale": "Unsanitized local config value reaches the shell.",
        "source_analysis": {
            "sources_found": [
                {
                    "type": "file",
                    "location": "web_ui JSON configuration value loaded from developer-local settings",
                }
            ],
            "attack_path": [
                "scripts/web_ui/launcher.py:load_config()",
                "scripts/web_ui/launcher.py:build_command()",
            ],
        },
        "attack_scenario": {
            "description": "Developer edits a local web_ui JSON configuration file before running the script.",
            "steps": [
                "1. Modify local web_ui config",
                "2. Run the developer helper script",
            ],
        },
        "preconditions": ["web_ui configuration file is attacker controlled on the local machine"],
        "docker_verification": {
            "verification_verdict": "VERIFIED_EXPLOITABLE",
            "exploit_confirmed": True,
        },
    }
    vuln = {"file_path": "scripts/web_ui/launcher.py", "vulnerability_type": "command_injection"}

    guarded = checker._apply_threat_model_guardrails(analysis, vuln)

    assert guarded["verdict"] == "LIBRARY_RISK"
    assert guarded["confidence"] == "medium"
    assert "Threat-model guardrail" in guarded["verdict_rationale"]
    assert guarded["docker_verification"]["verification_verdict"] == "NOT_VERIFIED"
    assert guarded["docker_verification"]["exploit_confirmed"] is False


def test_extract_threat_model_facts_normalizes_string_inputs_and_matches_expected_hints():
    analysis = {
        "preconditions": "config file is attacker controlled",
        "source_analysis": {
            "sources_found": [
                {"type": "file", "location": "web_ui JSON configuration value loaded from local settings"}
            ],
            "attack_path": "scripts/helper.py -> subprocess.Popen",
        },
        "attack_scenario": {
            "description": "Developer-local helper script workflow.",
            "steps": "run local script with config",
        },
    }
    vuln = {"file_path": "scripts/helper.py", "vulnerability_type": "command_injection"}

    facts = extract_threat_model_facts(analysis, vuln)

    assert facts.developer_local_path is True
    assert facts.is_script_entrypoint is True
    assert facts.source_types == {"file"}
    assert "config" in facts.local_only_hints
    assert "web_ui" in facts.local_path_traversal_hints
    assert "ui" not in facts.public_exposure_hints


def test_apply_threat_model_guardrails_helper_downgrades_local_script_case():
    analysis = {
        "verdict": "EXPLOITABLE",
        "confidence": "high",
        "verdict_rationale": "Shell injection is possible.",
        "preconditions": ["User runs script with --config malicious.json"],
        "source_analysis": {
            "sources_found": [{"type": "file", "location": "JSON configuration file provided via --config"}],
            "attack_path": ["exp.py parse_args()", "subprocess.Popen()"],
        },
        "attack_scenario": {
            "description": "Attacker supplies a local config file to the script.",
            "steps": ["1. Create malicious config", "2. User runs local script"],
        },
        "docker_verification": {
            "verification_verdict": "VERIFIED_EXPLOITABLE",
            "exploit_confirmed": True,
        },
    }
    vuln = {"file_path": "scripts/benchmark/exp_utils.py"}

    guarded = apply_threat_model_guardrails(analysis, vuln)

    assert guarded["verdict"] == "LIBRARY_RISK"
    assert guarded["confidence"] == "medium"
    assert guarded["docker_verification"]["verification_verdict"] == "NOT_VERIFIED"
    assert guarded["docker_verification"]["exploit_confirmed"] is False


def test_apply_threat_model_guardrails_downgrades_string_preconditions_for_local_script():
    checker = _checker()
    analysis = {
        "verdict": "EXPLOITABLE",
        "confidence": "high",
        "preconditions": "config file is attacker controlled",
        "source_analysis": {
            "sources_found": [],
            "attack_path": [],
        },
        "attack_scenario": {
            "description": "Developer-local helper script workflow.",
            "steps": [],
        },
        "docker_verification": {
            "verification_verdict": "VERIFIED_EXPLOITABLE",
            "exploit_confirmed": True,
        },
    }
    vuln = {"file_path": "scripts/benchmark/helper.py", "vulnerability_type": "command_injection"}

    guarded = checker._apply_threat_model_guardrails(analysis, vuln)

    assert guarded["verdict"] == "LIBRARY_RISK"
    assert guarded["docker_verification"]["verification_verdict"] == "NOT_VERIFIED"
    assert guarded["docker_verification"]["exploit_confirmed"] is False


def test_apply_threat_model_guardrails_normalizes_confidence_before_local_downgrade():
    checker = _checker()
    analysis = {
        "verdict": "EXPLOITABLE",
        "confidence": "High",
        "preconditions": ["User runs script with --config malicious.json"],
        "source_analysis": {
            "sources_found": [{"type": "file", "location": "JSON configuration file provided via --config"}],
            "attack_path": ["exp.py parse_args()", "subprocess.Popen()"],
        },
        "attack_scenario": {
            "description": "Attacker supplies a local config file to the script.",
            "steps": ["1. Create malicious config", "2. User runs local script"],
        },
        "docker_verification": {
            "verification_verdict": "VERIFIED_EXPLOITABLE",
            "exploit_confirmed": True,
        },
    }
    vuln = {"file_path": "scripts/benchmark/exp_utils.py"}

    guarded = checker._apply_threat_model_guardrails(analysis, vuln)
    normalized = checker._normalize_analysis_contract(guarded)

    assert normalized is not None
    assert normalized["verdict"] == "LIBRARY_RISK"
    assert normalized["confidence"] == "medium"


def test_apply_threat_model_guardrails_treats_string_steps_as_single_evidence_items():
    checker = _checker()
    analysis = {
        "verdict": "EXPLOITABLE",
        "confidence": "high",
        "source_analysis": {
            "sources_found": [],
            "attack_path": [],
        },
        "attack_scenario": {
            "description": "Developer-local helper script workflow.",
            "steps": "config file passed into local script",
        },
        "docker_verification": {
            "verification_verdict": "VERIFIED_EXPLOITABLE",
            "exploit_confirmed": True,
        },
    }
    vuln = {"file_path": "scripts/helper.py", "vulnerability_type": "command_injection"}

    guarded = checker._apply_threat_model_guardrails(analysis, vuln)

    assert guarded["verdict"] == "LIBRARY_RISK"
    assert guarded["docker_verification"]["verification_verdict"] == "NOT_VERIFIED"
    assert guarded["docker_verification"]["exploit_confirmed"] is False


def test_apply_threat_model_guardrails_keeps_product_exposed_inputs_exploitable():
    checker = _checker()
    analysis = {
        "verdict": "EXPLOITABLE",
        "confidence": "high",
        "source_analysis": {
            "sources_found": [{"type": "api", "location": "public web API endpoint"}],
            "attack_path": ["route handler", "fetch_webpage()"],
        },
        "attack_scenario": {
            "description": "Attacker sends URL through public API.",
            "steps": ["1. Send request", "2. Server fetches URL"],
        },
        "docker_verification": {
            "verification_verdict": "VERIFIED_EXPLOITABLE",
            "exploit_confirmed": True,
        },
    }
    vuln = {"file_path": "python/packages/autogen-studio/autogenstudio/gallery/tools/fetch_webpage.py"}

    guarded = checker._apply_threat_model_guardrails(analysis, vuln)

    assert guarded["verdict"] == "EXPLOITABLE"
    assert guarded["docker_verification"]["verification_verdict"] == "VERIFIED_EXPLOITABLE"


def test_apply_threat_model_guardrails_keeps_non_local_path_traversal_exploitable_for_cli_inputs():
    checker = _checker()
    analysis = {
        "verdict": "EXPLOITABLE",
        "confidence": "high",
        "source_analysis": {
            "sources_found": [{"type": "cli_argument", "location": "--output_dir argument controlled by the user"}],
            "attack_path": ["src/cli/exporter.py", "path join", "file write"],
        },
        "attack_scenario": {
            "description": "User controls the output_dir argument of the product CLI.",
            "steps": ["Run src/cli/exporter.py --output_dir ../../tmp"],
        },
        "docker_verification": {
            "verification_verdict": "VERIFIED_EXPLOITABLE",
            "exploit_confirmed": True,
        },
    }
    vuln = {"file_path": "src/cli/exporter.py", "vulnerability_type": "path_traversal"}

    guarded = checker._apply_threat_model_guardrails(analysis, vuln)

    assert guarded["verdict"] == "EXPLOITABLE"
    assert guarded["docker_verification"]["verification_verdict"] == "VERIFIED_EXPLOITABLE"
    assert guarded["docker_verification"]["exploit_confirmed"] is True


def test_apply_threat_model_guardrails_keeps_script_artifact_file_inputs_exploitable():
    checker = _checker()
    analysis = {
        "verdict": "EXPLOITABLE",
        "confidence": "high",
        "source_analysis": {
            "sources_found": [{"type": "cli", "location": "cfg.hyps_cache_file parameter"}],
            "attack_path": ["eval script", "pickle.load()"],
        },
        "attack_scenario": {
            "description": "Attacker provides malicious pickle file via hyps_cache_file parameter",
            "steps": ["1. Create malicious pickle", "2. User runs script with hyps_cache_file=malicious.pkl"],
        },
        "docker_verification": {
            "verification_verdict": "VERIFIED_EXPLOITABLE",
            "exploit_confirmed": True,
        },
    }
    vuln = {"file_path": "scripts/asr_language_modeling/ngram_lm/eval_beamsearch_ngram_ctc.py"}

    guarded = checker._apply_threat_model_guardrails(analysis, vuln)

    assert guarded["verdict"] == "EXPLOITABLE"


def test_apply_threat_model_guardrails_keeps_supported_cli_entrypoints_exploitable():
    checker = _checker()
    analysis = {
        "verdict": "EXPLOITABLE",
        "confidence": "high",
        "source_analysis": {
            "sources_found": [{"type": "cli", "location": "user-provided --config path"}],
            "attack_path": ["scripts/deploy.py", "load config", "sink"],
        },
        "attack_scenario": {
            "description": "Attacker supplies a malicious config file to the shipped CLI.",
            "steps": ["run scripts/deploy.py --config bad.json"],
        },
        "preconditions": ["config file is attacker controlled"],
        "docker_verification": {
            "verification_verdict": "VERIFIED_EXPLOITABLE",
            "exploit_confirmed": True,
        },
    }
    vuln = {"file_path": "scripts/deploy.py", "vulnerability_type": "command_injection"}

    guarded = checker._apply_threat_model_guardrails(analysis, vuln)

    assert guarded["verdict"] == "EXPLOITABLE"
    assert guarded["confidence"] == "high"
    assert guarded["docker_verification"]["verification_verdict"] == "VERIFIED_EXPLOITABLE"
    assert guarded["docker_verification"]["exploit_confirmed"] is True


def test_apply_threat_model_guardrails_keeps_nested_supported_cli_entrypoints_exploitable():
    checker = _checker()
    analysis = {
        "verdict": "EXPLOITABLE",
        "confidence": "high",
        "source_analysis": {
            "sources_found": [{"type": "cli", "location": "user-provided --config path"}],
            "attack_path": ["scripts/tools/deploy.py", "load config", "sink"],
        },
        "attack_scenario": {
            "description": "Attacker supplies a malicious config file to the shipped nested CLI.",
            "steps": ["run scripts/tools/deploy.py --config bad.json"],
        },
        "preconditions": ["config file is attacker controlled"],
        "docker_verification": {
            "verification_verdict": "VERIFIED_EXPLOITABLE",
            "exploit_confirmed": True,
        },
    }
    vuln = {"file_path": "scripts/tools/deploy.py", "vulnerability_type": "command_injection"}

    guarded = checker._apply_threat_model_guardrails(analysis, vuln)

    assert guarded["verdict"] == "EXPLOITABLE"
    assert guarded["confidence"] == "high"
    assert guarded["docker_verification"]["verification_verdict"] == "VERIFIED_EXPLOITABLE"
    assert guarded["docker_verification"]["exploit_confirmed"] is True


def test_apply_threat_model_guardrails_downgrades_local_config_path_traversal():
    checker = _checker()
    analysis = {
        "verdict": "EXPLOITABLE",
        "confidence": "high",
        "source_analysis": {
            "sources_found": [{"type": "cli_argument", "location": "cfg['env']['motion_file'] via Hydra configuration"}],
            "attack_path": ["train.py", "Hydra configuration", "motion_file concatenation"],
        },
        "attack_scenario": {
            "description": "Attacker provides local motion_file path via Hydra configuration",
            "steps": ["1. User runs local training config", "2. Script reads arbitrary local file"],
        },
        "docker_verification": {
            "verification_verdict": "VERIFIED_EXPLOITABLE",
            "exploit_confirmed": True,
        },
    }
    vuln = {"file_path": "isaacgymenvs/tasks/humanoid_amp.py", "vulnerability_type": "path_traversal"}

    guarded = checker._apply_threat_model_guardrails(analysis, vuln)

    assert guarded["verdict"] == "LIBRARY_RISK"
    assert guarded["docker_verification"]["verification_verdict"] == "NOT_VERIFIED"
    assert guarded["docker_verification"]["exploit_confirmed"] is False


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
                "original_finding": {"file_path": "a.py", "vulnerability_type": "x"},
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


def test_check_single_resume_retries_stale_error_after_intermediate_save(monkeypatch, tmp_path):
    checker = _checker()

    findings_path = tmp_path / "agentic_vuln_findings.json"
    findings_path.write_text(
        json.dumps(
            {
                "vulnerabilities": [
                    {"file_path": "a.py", "vulnerability_type": "x"},
                    {"file_path": "b.py", "vulnerability_type": "y"},
                    {"file_path": "c.py", "vulnerability_type": "z"},
                ]
            }
        ),
        encoding="utf-8",
    )

    output_path = tmp_path / "exploitability.json"
    existing = {
        "metadata": {
            "started_at": "t",
            "completed_at": None,
            "total_vulnerabilities": 3,
        },
        "summary": {},
        "results": [
            {
                "finding_id": "vuln_000",
                "verdict": "NOT_EXPLOITABLE",
                "original_finding": {"file_path": "a.py", "vulnerability_type": "x"},
            },
            {
                "finding_id": "vuln_002",
                "verdict": "ERROR",
                "original_finding": {"file_path": "c.py", "vulnerability_type": "z"},
            },
        ],
    }
    output_path.write_text(json.dumps(existing), encoding="utf-8")

    calls = []

    def fake_analyze_single_vuln(**kwargs):
        calls.append(kwargs["finding_id"])
        verdict = "EXPLOITABLE" if kwargs["finding_id"] == "vuln_001" else "NOT_EXPLOITABLE"
        return {
            "finding_id": kwargs["finding_id"],
            "verdict": verdict,
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
    assert calls == ["vuln_001", "vuln_002"]
    assert [item["finding_id"] for item in saved["results"]] == [
        "vuln_000",
        "vuln_001",
        "vuln_002",
    ]
    assert saved["results"][2]["verdict"] == "NOT_EXPLOITABLE"


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


def test_check_single_empty_findings_writes_complete_output(tmp_path):
    checker = _checker()

    findings_path = tmp_path / "agentic_vuln_findings.json"
    findings_path.write_text(json.dumps({"vulnerabilities": []}), encoding="utf-8")
    output_path = tmp_path / "exploitability.json"

    result = checker.check_single(
        findings_path=findings_path,
        repo_path=tmp_path,
        output_path=output_path,
    )

    saved = json.loads(output_path.read_text(encoding="utf-8"))
    assert result["status"] == "success"
    assert result["num_analyzed"] == 0
    assert saved["metadata"]["total_vulnerabilities"] == 0
    assert saved["metadata"]["findings_signature"] == compute_findings_signature([])
    assert isinstance(saved["metadata"]["completed_at"], str)
    assert saved["metadata"]["completed_at"]
    assert saved["results"] == []
    assert get_exploitability_output_state(saved) == "complete"


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
    current_findings, findings_signature = _findings_context(
        [
            {"finding_id": "vuln_000"},
            {"finding_id": "vuln_001"},
        ]
    )

    loaded = checker._init_or_load_results(
        output_path=output_path,
        findings_path=tmp_path / "findings.json",
        repo_path=tmp_path,
        software_profile_path=None,
        total_vulns=2,
        current_findings=current_findings,
        findings_signature=findings_signature,
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


def test_init_or_load_results_refreshes_total_vulnerabilities_for_changed_findings(tmp_path):
    checker = _checker()
    output_path = tmp_path / "exploitability.json"
    output_path.write_text(
        json.dumps(
            {
                "metadata": {
                    "started_at": "t",
                    "completed_at": "2026-03-11T00:00:00",
                    "total_vulnerabilities": 1,
                },
                "summary": {},
                "results": [
                    {"finding_id": "vuln_000", "verdict": "NOT_EXPLOITABLE"},
                ],
            }
        ),
        encoding="utf-8",
    )
    current_findings, findings_signature = _findings_context(
        [
            {"file_path": "a.py"},
            {"file_path": "b.py"},
        ]
    )

    loaded = checker._init_or_load_results(
        output_path=output_path,
        findings_path=tmp_path / "findings.json",
        repo_path=tmp_path,
        software_profile_path=None,
        total_vulns=2,
        current_findings=current_findings,
        findings_signature=findings_signature,
    )

    assert loaded["metadata"]["total_vulnerabilities"] == 2
    assert loaded["metadata"]["completed_at"] is None


def test_init_or_load_results_reinitializes_on_corrupt_existing_output(tmp_path):
    checker = _checker()
    output_path = tmp_path / "exploitability.json"
    output_path.write_text("{not-json", encoding="utf-8")
    current_findings, findings_signature = _findings_context([{"file_path": "a.py"}])

    loaded = checker._init_or_load_results(
        output_path=output_path,
        findings_path=tmp_path / "findings.json",
        repo_path=tmp_path,
        software_profile_path=None,
        total_vulns=1,
        current_findings=current_findings,
        findings_signature=findings_signature,
    )

    assert loaded["metadata"]["total_vulnerabilities"] == 1
    assert loaded["metadata"]["completed_at"] is None
    assert loaded["results"] == []


def test_get_exploitability_output_state_for_findings_downgrades_changed_signature(tmp_path):
    findings_path = tmp_path / "findings.json"
    new_findings = [
        {"file_path": "a.py", "vulnerability_type": "cmd"},
        {"file_path": "c.py", "vulnerability_type": "path_traversal"},
    ]
    findings_path.write_text(
        json.dumps({"vulnerabilities": new_findings}),
        encoding="utf-8",
    )

    exploitability_data = {
        "metadata": {
            "completed_at": "2026-03-11T00:00:00",
            "total_vulnerabilities": 2,
            "findings_signature": compute_findings_signature(
                [
                    {"file_path": "a.py", "vulnerability_type": "cmd"},
                    {"file_path": "b.py", "vulnerability_type": "ssrf"},
                ]
            ),
        },
        "summary": {},
        "results": [
            {"finding_id": "vuln_000"},
            {"finding_id": "vuln_001"},
        ],
    }

    assert (
        get_exploitability_output_state_for_findings(exploitability_data, findings_path)
        == "in_progress"
    )


def test_get_exploitability_output_state_for_findings_requires_signature(tmp_path):
    findings_path = tmp_path / "findings.json"
    findings_path.write_text(
        json.dumps({"vulnerabilities": [{"file_path": "a.py"}]}),
        encoding="utf-8",
    )

    exploitability_data = {
        "metadata": {
            "completed_at": "2026-03-11T00:00:00",
            "total_vulnerabilities": 1,
        },
        "summary": {},
        "results": [
            {"finding_id": "vuln_000"},
        ],
    }

    assert (
        get_exploitability_output_state_for_findings(exploitability_data, findings_path)
        == "in_progress"
    )


def test_get_exploitability_output_state_for_findings_preserves_complete_output_without_findings_file(
    tmp_path,
):
    findings_path = tmp_path / "findings.json"

    exploitability_data = {
        "metadata": {
            "completed_at": "2026-03-11T00:00:00",
            "total_vulnerabilities": 1,
            "findings_signature": compute_findings_signature([{"file_path": "a.py"}]),
        },
        "summary": {},
        "results": [
            {"finding_id": "vuln_000"},
        ],
    }

    assert (
        get_exploitability_output_state_for_findings(exploitability_data, findings_path)
        == "complete"
    )


def test_get_exploitability_output_state_for_findings_downgrades_invalid_findings_file(
    tmp_path,
):
    findings_path = tmp_path / "findings.json"

    exploitability_data = {
        "metadata": {
            "completed_at": "2026-03-11T00:00:00",
            "total_vulnerabilities": 1,
            "findings_signature": compute_findings_signature([{"file_path": "a.py"}]),
        },
        "summary": {},
        "results": [
            {"finding_id": "vuln_000"},
        ],
    }

    findings_path.write_text("{bad-json", encoding="utf-8")

    assert (
        get_exploitability_output_state_for_findings(exploitability_data, findings_path)
        == "in_progress"
    )


def test_get_exploitability_output_state_treats_retryable_rows_as_in_progress():
    exploitability_data = {
        "metadata": {
            "completed_at": "2026-03-11T00:00:00",
            "total_vulnerabilities": 1,
        },
        "summary": {},
        "results": [
            {
                "finding_id": "vuln_000",
                "verdict": "ERROR",
            }
        ],
    }

    assert get_exploitability_output_state(exploitability_data) == "in_progress"


def test_init_or_load_results_drops_results_outside_current_findings_scope(tmp_path):
    checker = _checker()
    output_path = tmp_path / "exploitability.json"
    output_path.write_text(
        json.dumps(
            {
                "metadata": {
                    "started_at": "t",
                    "completed_at": None,
                    "total_vulnerabilities": 3,
                },
                "summary": {},
                "results": [
                    {"finding_id": "vuln_000", "verdict": "NOT_EXPLOITABLE"},
                    {"finding_id": "vuln_001", "verdict": "EXPLOITABLE"},
                    {"finding_id": "vuln_002", "verdict": "LIBRARY_RISK"},
                ],
            }
        ),
        encoding="utf-8",
    )
    current_findings, findings_signature = _findings_context(
        [
            {"file_path": "a.py"},
            {"file_path": "b.py"},
        ]
    )

    loaded = checker._init_or_load_results(
        output_path=output_path,
        findings_path=tmp_path / "findings.json",
        repo_path=tmp_path,
        software_profile_path=None,
        total_vulns=2,
        current_findings=current_findings,
        findings_signature=findings_signature,
    )

    assert [item["finding_id"] for item in loaded["results"]] == ["vuln_000", "vuln_001"]
    assert loaded["metadata"]["total_vulnerabilities"] == 2


def test_init_or_load_results_drops_results_for_changed_findings_with_same_count(tmp_path):
    checker = _checker()
    output_path = tmp_path / "exploitability.json"
    old_findings = [
        {"file_path": "a.py", "vulnerability_type": "cmd"},
        {"file_path": "b.py", "vulnerability_type": "ssrf"},
    ]
    new_findings = [
        {"file_path": "a.py", "vulnerability_type": "cmd"},
        {"file_path": "c.py", "vulnerability_type": "path_traversal"},
    ]
    output_path.write_text(
        json.dumps(
            {
                "metadata": {
                    "started_at": "t",
                    "completed_at": "2026-03-11T00:00:00",
                    "total_vulnerabilities": 2,
                    "findings_signature": compute_findings_signature(old_findings),
                },
                "summary": {},
                "results": [
                    {
                        "finding_id": "vuln_000",
                        "verdict": "NOT_EXPLOITABLE",
                        "original_finding": old_findings[0],
                    },
                    {
                        "finding_id": "vuln_001",
                        "verdict": "EXPLOITABLE",
                        "original_finding": old_findings[1],
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    current_findings, findings_signature = _findings_context(new_findings)

    loaded = checker._init_or_load_results(
        output_path=output_path,
        findings_path=tmp_path / "findings.json",
        repo_path=tmp_path,
        software_profile_path=None,
        total_vulns=2,
        current_findings=current_findings,
        findings_signature=findings_signature,
    )

    assert [item["finding_id"] for item in loaded["results"]] == ["vuln_000"]
    assert loaded["metadata"]["findings_signature"] == findings_signature
    assert loaded["metadata"]["completed_at"] is None


def test_init_or_load_results_drops_results_when_finding_gains_new_fields(tmp_path):
    checker = _checker()
    output_path = tmp_path / "exploitability.json"
    old_findings = [
        {"file_path": "a.py", "vulnerability_type": "cmd"},
    ]
    new_findings = [
        {
            "file_path": "a.py",
            "vulnerability_type": "cmd",
            "sink": "os.system",
        },
    ]
    output_path.write_text(
        json.dumps(
            {
                "metadata": {
                    "started_at": "t",
                    "completed_at": "2026-03-11T00:00:00",
                    "total_vulnerabilities": 1,
                    "findings_signature": compute_findings_signature(old_findings),
                },
                "summary": {},
                "results": [
                    {
                        "finding_id": "vuln_000",
                        "verdict": "NOT_EXPLOITABLE",
                        "original_finding": old_findings[0],
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    current_findings, findings_signature = _findings_context(new_findings)

    loaded = checker._init_or_load_results(
        output_path=output_path,
        findings_path=tmp_path / "findings.json",
        repo_path=tmp_path,
        software_profile_path=None,
        total_vulns=1,
        current_findings=current_findings,
        findings_signature=findings_signature,
    )

    assert loaded["results"] == []
    assert loaded["metadata"]["findings_signature"] == findings_signature
    assert loaded["metadata"]["completed_at"] is None


def test_init_or_load_results_keeps_results_when_findings_reorder(tmp_path):
    checker = _checker()
    output_path = tmp_path / "exploitability.json"
    original_findings = [
        {"file_path": "b.py", "vulnerability_type": "ssrf"},
        {"file_path": "a.py", "vulnerability_type": "cmd"},
    ]
    reordered_findings = [
        {"file_path": "a.py", "vulnerability_type": "cmd"},
        {"file_path": "b.py", "vulnerability_type": "ssrf"},
    ]
    current_findings, findings_signature = _findings_context(original_findings)
    output_path.write_text(
        json.dumps(
            {
                "metadata": {
                    "started_at": "t",
                    "completed_at": "2026-03-11T00:00:00",
                    "total_vulnerabilities": 2,
                    "findings_signature": findings_signature,
                },
                "summary": {},
                "results": [
                    {
                        "finding_id": "vuln_000",
                        "verdict": "NOT_EXPLOITABLE",
                        "original_finding": current_findings["vuln_000"],
                    },
                    {
                        "finding_id": "vuln_001",
                        "verdict": "EXPLOITABLE",
                        "original_finding": current_findings["vuln_001"],
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    reordered_current_findings, reordered_signature = _findings_context(reordered_findings)

    loaded = checker._init_or_load_results(
        output_path=output_path,
        findings_path=tmp_path / "findings.json",
        repo_path=tmp_path,
        software_profile_path=None,
        total_vulns=2,
        current_findings=reordered_current_findings,
        findings_signature=reordered_signature,
    )

    assert [item["finding_id"] for item in loaded["results"]] == ["vuln_000", "vuln_001"]
    assert loaded["metadata"]["findings_signature"] == reordered_signature
    assert loaded["metadata"]["completed_at"] == "2026-03-11T00:00:00"


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
    current_findings, findings_signature = _findings_context(
        [
            {"finding_id": "vuln_000"},
            {"finding_id": "vuln_001"},
        ]
    )

    loaded = checker._init_or_load_results(
        output_path=output_path,
        findings_path=tmp_path / "findings.json",
        repo_path=tmp_path,
        software_profile_path=None,
        total_vulns=2,
        current_findings=current_findings,
        findings_signature=findings_signature,
    )

    assert len(loaded["results"]) == 1
    retried = loaded["metadata"]["llm_usage_retried_attempts_summary"]
    assert retried["calls_total"] == 0
    total = loaded["metadata"]["llm_usage_summary"]
    assert total["calls_total"] == 1
    assert total["input_tokens"] == 3
    assert total["output_tokens"] == 4


def test_save_results_merges_newer_on_disk_results_for_retried_entries(tmp_path):
    checker = _checker()
    output_path = tmp_path / "exploitability.json"
    initial = {
        "metadata": {
            "started_at": "t0",
            "completed_at": None,
            "total_vulnerabilities": 3,
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
            "llm_usage_summary": {
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
                "verdict": "NOT_EXPLOITABLE",
            },
            {
                "finding_id": "vuln_001",
                "verdict": "ERROR",
            },
        ],
    }
    output_path.write_text(json.dumps(initial), encoding="utf-8")
    current_findings, findings_signature = _findings_context(
        [
            {"finding_id": "vuln_000"},
            {"finding_id": "vuln_001"},
            {"finding_id": "vuln_002"},
        ]
    )

    loaded = checker._init_or_load_results(
        output_path=output_path,
        findings_path=tmp_path / "findings.json",
        repo_path=tmp_path,
        software_profile_path=None,
        total_vulns=3,
        current_findings=current_findings,
        findings_signature=findings_signature,
    )
    assert [item["finding_id"] for item in loaded["results"]] == ["vuln_000"]

    concurrent = {
        "metadata": {
            **initial["metadata"],
            "completed_at": None,
        },
        "summary": {},
        "results": [
            {
                "finding_id": "vuln_000",
                "verdict": "NOT_EXPLOITABLE",
            },
            {
                "finding_id": "vuln_001",
                "verdict": "EXPLOITABLE",
            },
        ],
    }
    output_path.write_text(json.dumps(concurrent), encoding="utf-8")

    loaded["results"].append(
        {
            "finding_id": "vuln_002",
            "verdict": "LIBRARY_RISK",
        }
    )
    checker._save_results(output_path, loaded)

    saved = json.loads(output_path.read_text(encoding="utf-8"))
    assert [item["finding_id"] for item in saved["results"]] == [
        "vuln_000",
        "vuln_001",
        "vuln_002",
    ]
    assert saved["results"][1]["verdict"] == "EXPLOITABLE"
    assert saved["summary"]["exploitable"] == 1
    assert saved["summary"]["library_risk"] == 1
    assert saved["summary"]["not_exploitable"] == 1


def test_save_results_does_not_restore_stale_retryable_entries_from_disk(tmp_path):
    checker = _checker()
    output_path = tmp_path / "exploitability.json"
    initial = {
        "metadata": {
            "started_at": "t0",
            "completed_at": None,
            "total_vulnerabilities": 3,
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
            "llm_usage_summary": {
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
                "verdict": "NOT_EXPLOITABLE",
            },
            {
                "finding_id": "vuln_002",
                "verdict": "ERROR",
            },
        ],
    }
    output_path.write_text(json.dumps(initial), encoding="utf-8")

    current = {
        "metadata": dict(initial["metadata"]),
        "summary": {},
        "results": [
            {
                "finding_id": "vuln_000",
                "verdict": "NOT_EXPLOITABLE",
            },
            {
                "finding_id": "vuln_001",
                "verdict": "EXPLOITABLE",
            },
        ],
    }

    checker._save_results(output_path, current)

    saved = json.loads(output_path.read_text(encoding="utf-8"))
    assert [item["finding_id"] for item in saved["results"]] == [
        "vuln_000",
        "vuln_001",
    ]
    assert saved["summary"]["exploitable"] == 1
    assert saved["summary"]["not_exploitable"] == 1
    assert saved["summary"]["error"] == 0


def test_save_results_returns_merged_doc_without_mutating_input(tmp_path):
    checker = _checker()
    output_path = tmp_path / "exploitability.json"
    output_path.write_text(
        json.dumps(
            {
                "metadata": {
                    "started_at": "t0",
                    "completed_at": None,
                    "total_vulnerabilities": 2,
                },
                "summary": {},
                "results": [
                    {"finding_id": "vuln_000", "verdict": "NOT_EXPLOITABLE"},
                ],
            }
        ),
        encoding="utf-8",
    )

    current = {
        "metadata": {
            "started_at": "t1",
            "completed_at": None,
            "total_vulnerabilities": 2,
        },
        "summary": {},
        "results": [
            {"finding_id": "vuln_001", "verdict": "EXPLOITABLE"},
        ],
    }

    saved_doc = checker._save_results(output_path, current)

    assert [item["finding_id"] for item in current["results"]] == ["vuln_001"]
    assert [item["finding_id"] for item in saved_doc["results"]] == ["vuln_000", "vuln_001"]
    assert saved_doc["summary"]["exploitable"] == 1
    assert saved_doc["summary"]["not_exploitable"] == 1


def test_save_results_does_not_restore_stale_rows_outside_current_scope(tmp_path):
    checker = _checker()
    output_path = tmp_path / "exploitability.json"
    output_path.write_text(
        json.dumps(
            {
                "metadata": {
                    "started_at": "t0",
                    "completed_at": None,
                    "total_vulnerabilities": 3,
                },
                "summary": {},
                "results": [
                    {"finding_id": "vuln_000", "verdict": "NOT_EXPLOITABLE"},
                    {"finding_id": "vuln_002", "verdict": "EXPLOITABLE"},
                ],
            }
        ),
        encoding="utf-8",
    )

    current = {
        "metadata": {
            "started_at": "t1",
            "completed_at": None,
            "total_vulnerabilities": 2,
        },
        "summary": {},
        "results": [
            {"finding_id": "vuln_000", "verdict": "NOT_EXPLOITABLE"},
        ],
    }

    saved_doc = checker._save_results(output_path, current)

    assert [item["finding_id"] for item in saved_doc["results"]] == ["vuln_000"]


def test_save_results_does_not_restore_stale_rows_for_changed_findings(tmp_path):
    checker = _checker()
    output_path = tmp_path / "exploitability.json"
    old_findings = [
        {"file_path": "a.py", "vulnerability_type": "cmd"},
        {"file_path": "b.py", "vulnerability_type": "ssrf"},
    ]
    new_findings = [
        {"file_path": "a.py", "vulnerability_type": "cmd"},
        {"file_path": "c.py", "vulnerability_type": "path_traversal"},
    ]
    output_path.write_text(
        json.dumps(
            {
                "metadata": {
                    "started_at": "t0",
                    "completed_at": None,
                    "total_vulnerabilities": 2,
                    "findings_signature": compute_findings_signature(old_findings),
                },
                "summary": {},
                "results": [
                    {
                        "finding_id": "vuln_000",
                        "verdict": "NOT_EXPLOITABLE",
                        "original_finding": old_findings[0],
                    },
                    {
                        "finding_id": "vuln_001",
                        "verdict": "EXPLOITABLE",
                        "original_finding": old_findings[1],
                    },
                ],
            }
        ),
        encoding="utf-8",
    )

    current = {
        "metadata": {
            "started_at": "t1",
            "completed_at": None,
            "total_vulnerabilities": 2,
            "findings_signature": compute_findings_signature(new_findings),
        },
        "summary": {},
        "results": [
            {
                "finding_id": "vuln_000",
                "verdict": "NOT_EXPLOITABLE",
                "original_finding": new_findings[0],
            },
        ],
    }
    current_findings, _ = _findings_context(new_findings)

    saved_doc = checker._save_results(
        output_path,
        current,
        current_findings=current_findings,
    )

    assert [item["finding_id"] for item in saved_doc["results"]] == ["vuln_000"]
