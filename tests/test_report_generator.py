from scanner.checker.report_generator import ReportGenerator


def _generator():
    return ReportGenerator(
        repo_name="demo",
        commit_hash="abcdef1234567890",
        repo_url="https://github.com/example/demo",
        language="python",
    )


def test_docker_verification_verdict_mapping():
    gen = _generator()

    assert gen._docker_verification_verdict(None) is None
    assert gen._docker_verification_verdict({"verification_verdict": "NOT_VERIFIED"}) == "NOT_VERIFIED"
    assert gen._docker_verification_verdict({"exploit_confirmed": True}) == "VERIFIED_EXPLOITABLE"
    assert gen._docker_verification_verdict({"run_success": True}) == "VERIFICATION_FAILED"
    assert gen._docker_verification_verdict({"build_success": True}) == "PARTIAL_VERIFICATION"
    assert gen._docker_verification_verdict({}) == "GENERATION_FAILED"


def test_extract_and_summarize_finding_verifications():
    gen = _generator()
    data = {
        "results": [
            {"finding_id": "v1", "docker_verification": {"exploit_confirmed": True}},
            {"finding_id": "v2", "docker_verification": {"build_success": True}},
            {"finding_id": "v3", "docker_verification": {"run_success": True}},
            {"finding_id": "v4"},
        ]
    }

    verifications = gen._extract_finding_verifications(data)
    summary = gen._summarize_docker_verifications(verifications)

    assert set(verifications.keys()) == {"v1", "v2", "v3"}
    assert summary["verified_exploitable"] == 1
    assert summary["partial_verification"] == 1
    assert summary["verification_failed"] == 1
    assert summary["generation_failed"] == 0


def test_generate_ghsa_reports_filters_findings_and_embeds_docker_section():
    gen = _generator()
    data = {
        "results": [
            {
                "finding_id": "vuln_001",
                "verdict": "EXPLOITABLE",
                "original_finding": {
                    "file_path": "src/api.py",
                    "vulnerability_type": "command_injection",
                    "description": "desc",
                    "evidence": "evidence",
                    "attack_scenario": "scenario",
                },
                "source_analysis": {"attack_path": ["a", "b"], "sources_found": []},
                "sink_analysis": {"sink_type": "command", "confirmed": True},
                "docker_verification": {
                    "exploit_confirmed": True,
                    "execution_output": "VULNERABILITY_CONFIRMED",
                    "poc_script_path": "/tmp/poc.py",
                },
            },
            {
                "finding_id": "vuln_002",
                "verdict": "NOT_EXPLOITABLE",
                "original_finding": {
                    "file_path": "src/ignore.py",
                    "vulnerability_type": "xss",
                },
            },
        ]
    }

    reports = gen.generate_ghsa_reports(data, cve_id="CVE-2025-0001")

    assert len(reports) == 1
    assert reports[0]["finding_id"] == "vuln_001"
    assert "Docker Verification Evidence" in reports[0]["content"]


def test_generate_ghsa_reports_only_exploitable_filter():
    gen = _generator()
    data = {
        "results": [
            {
                "finding_id": "vuln_001",
                "verdict": "EXPLOITABLE",
                "original_finding": {
                    "file_path": "src/a.py",
                    "vulnerability_type": "command_injection",
                },
            },
            {
                "finding_id": "vuln_002",
                "verdict": "CONDITIONALLY_EXPLOITABLE",
                "original_finding": {
                    "file_path": "src/b.py",
                    "vulnerability_type": "xss",
                },
            },
        ]
    }

    reports = gen.generate_ghsa_reports(data, only_exploitable=True)
    assert [r["finding_id"] for r in reports] == ["vuln_001"]


def test_generate_full_report_contains_docker_summary_and_findings_sections():
    gen = _generator()
    data = {
        "summary": {
            "exploitable": 1,
            "conditionally_exploitable": 0,
            "library_risk": 0,
            "not_exploitable": 0,
        },
        "metadata": {
            "started_at": "2026-01-01T00:00:00",
            "completed_at": "2026-01-01T01:00:00",
            "total_vulnerabilities": 1,
        },
        "results": [
            {
                "finding_id": "vuln_001",
                "verdict": "EXPLOITABLE",
                "source_analysis": {"attack_path": ["entry", "sink"]},
                "original_finding": {
                    "file_path": "src/app.py",
                    "vulnerability_type": "deserialization",
                    "description": "Unsafe load",
                    "evidence": "pickle.loads(user_input)",
                    "attack_scenario": "attacker sends payload",
                    "confidence": "high",
                },
                "docker_verification": {
                    "exploit_confirmed": True,
                    "execution_output": "VULNERABILITY_CONFIRMED",
                },
            }
        ],
    }

    report = gen.generate_full_report(data, cve_id="CVE-2025-0001")

    assert "Docker Verification Results" in report
    assert "Exploitable Vulnerabilities" in report
    assert "Finding 1" in report
    assert "VERIFIED_EXPLOITABLE" in report


def test_generate_full_report_only_exploitable_hides_conditional_sections():
    gen = _generator()
    data = {
        "results": [
            {
                "finding_id": "vuln_001",
                "verdict": "EXPLOITABLE",
                "original_finding": {
                    "file_path": "src/app.py",
                    "vulnerability_type": "deserialization",
                    "description": "Unsafe load",
                    "confidence": "high",
                },
            },
            {
                "finding_id": "vuln_002",
                "verdict": "CONDITIONALLY_EXPLOITABLE",
                "original_finding": {
                    "file_path": "src/extra.py",
                    "vulnerability_type": "ssrf",
                    "description": "Conditional issue",
                    "confidence": "medium",
                },
            },
        ],
    }

    report = gen.generate_full_report(data, only_exploitable=True)
    assert "Report mode: only findings with verdict `EXPLOITABLE`" in report
    assert "Exploitable Vulnerabilities" in report
    assert "Conditionally Exploitable Vulnerabilities" not in report
