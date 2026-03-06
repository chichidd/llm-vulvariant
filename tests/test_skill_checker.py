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

    def fake_run_claude(prompt):
        (evidence_dir / "analysis_output.json").write_text(
            json.dumps({"verdict": "NOT_EXPLOITABLE", "confidence": "high"}),
            encoding="utf-8",
        )
        return False, None

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


def test_analyze_single_vuln_ignores_stale_output_file(monkeypatch, tmp_path):
    checker = _checker()
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()

    # Pre-existing file from an earlier run should be ignored.
    (evidence_dir / "analysis_output.json").write_text(
        json.dumps({"verdict": "EXPLOITABLE", "confidence": "high"}),
        encoding="utf-8",
    )

    monkeypatch.setattr(checker, "_run_claude", lambda prompt: (False, None))

    result = checker._analyze_single_vuln(
        vuln={"file_path": "x.py", "vulnerability_type": "x"},
        finding_id="vuln_000",
        repo_path=tmp_path,
        evidence_dir=evidence_dir,
    )

    assert result["verdict"] == "ERROR"
    assert result.get("error") == "Claude analysis failed"


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
