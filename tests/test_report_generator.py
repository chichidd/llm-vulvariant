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


def test_generate_full_report_prefers_analysis_confidence_over_original_finding():
    gen = _generator()
    data = {
        "results": [
            {
                "finding_id": "vuln_001",
                "verdict": "EXPLOITABLE",
                "confidence": "medium",
                "original_finding": {
                    "file_path": "src/app.py",
                    "vulnerability_type": "deserialization",
                    "description": "Unsafe load",
                    "confidence": "low",
                },
            }
        ],
    }

    report = gen.generate_full_report(data)

    assert "**Verdict**: EXPLOITABLE | **Confidence**: medium" in report


def test_generate_reports_render_analysis_attack_scenario_payload():
    gen = _generator()
    data = {
        "results": [
            {
                "finding_id": "vuln_001",
                "verdict": "EXPLOITABLE",
                "confidence": "high",
                "attack_scenario": {
                    "description": "Generated exploit path",
                    "steps": ["deliver payload", "reach sink"],
                    "impact": "remote code execution",
                },
                "original_finding": {
                    "file_path": "src/app.py",
                    "vulnerability_type": "deserialization",
                    "description": "Unsafe load",
                    "evidence": "pickle.loads(user_input)",
                },
            }
        ],
    }

    ghsa_report = gen.generate_ghsa_reports(data)[0]["content"]
    full_report = gen.generate_full_report(data)

    assert "Generated exploit path" in ghsa_report
    assert "Steps: deliver payload -> reach sink" in ghsa_report
    assert "Impact: remote code execution" in full_report


def test_generate_reports_render_structured_checker_evidence_sections():
    gen = _generator()
    data = {
        "results": [
            {
                "finding_id": "vuln_001",
                "verdict": "CONDITIONALLY_EXPLOITABLE",
                "confidence": "medium",
                "verdict_rationale": "User input reaches a shell sink, but only after authentication.",
                "preconditions": ["Attacker can authenticate to the admin endpoint."],
                "static_evidence": [
                    "api.py: handle() forwards request.json['cmd'] into subprocess.run(..., shell=True)."
                ],
                "dynamic_plan": [
                    "Start the vulnerable service.",
                    "Send a crafted authenticated request with shell metacharacters.",
                ],
                "open_questions": ["Whether the admin endpoint is exposed in default deployments."],
                "original_finding": {
                    "file_path": "src/app.py",
                    "vulnerability_type": "command_injection",
                    "description": "Unsafe shell invocation",
                    "evidence": "subprocess.run(user_cmd, shell=True)",
                },
            }
        ],
    }

    ghsa_report = gen.generate_ghsa_reports(data)[0]["content"]
    full_report = gen.generate_full_report(data)

    assert "Verdict Rationale" in ghsa_report
    assert "User input reaches a shell sink" in ghsa_report
    assert "Preconditions" in full_report
    assert "Attacker can authenticate to the admin endpoint." in full_report
    assert "Static Evidence" in full_report
    assert "Dynamic Verification Plan" in full_report
    assert "Open Questions" in full_report


def test_generate_ghsa_reports_tolerates_type_drifted_analysis_payloads():
    gen = _generator()
    data = {
        "results": [
            {
                "finding_id": "vuln_001",
                "verdict": "EXPLOITABLE",
                "source_analysis": "bad",
                "remediation": "manual fix",
                "sink_analysis": "sink here",
                "docker_verification": {
                    "verification_verdict": "VERIFIED_EXPLOITABLE",
                    "execution_rounds": ["boom"],
                    "execution_output": "VULNERABILITY_CONFIRMED",
                    "poc_generation": "bad",
                    "evidence_summary": "bad",
                },
                "original_finding": {
                    "file_path": "src/app.py",
                    "vulnerability_type": "command_injection",
                    "description": "Unsafe exec",
                    "evidence": "os.system(user_input)",
                },
            }
        ],
    }

    report = gen.generate_ghsa_reports(data)[0]["content"]

    assert "Docker Verification Evidence" in report
    assert "VULNERABILITY_CONFIRMED" in report
    assert "No specific remediation provided." in report


def test_generate_full_report_tolerates_non_mapping_result_fields():
    gen = _generator()
    data = {
        "results": [
            {
                "finding_id": "vuln_001",
                "verdict": "EXPLOITABLE",
                "source_analysis": "bad",
                "docker_verification": {
                    "verification_verdict": "VERIFIED_EXPLOITABLE",
                    "execution_rounds": ["boom"],
                    "execution_output": "VULNERABILITY_CONFIRMED",
                },
                "original_finding": "bad",
            }
        ],
    }

    report = gen.generate_full_report(data)

    assert "#### Finding 1: Unknown in `unknown`" in report
    assert "**Docker Verification**: VERIFIED_EXPLOITABLE" in report
    assert "VULNERABILITY_CONFIRMED" in report


def test_report_generator_handles_missing_vulnerability_type_fields():
    gen = _generator()
    data = {
        "results": [
            {
                "finding_id": "vuln_001",
                "verdict": "EXPLOITABLE",
                "source_analysis": {"sources_found": ["cli"], "attack_path": ["entry", "sink"]},
                "original_finding": {
                    "file_path": None,
                    "vulnerability_type": None,
                    "description": None,
                    "evidence": None,
                },
            }
        ],
    }

    ghsa_report = gen.generate_ghsa_reports(data)[0]["content"]
    full_report = gen.generate_full_report(data)

    assert "Unknown in unknown" in ghsa_report
    assert "#### Finding 1: Unknown in `unknown`" in full_report
    assert "Security impact dependent on context" in ghsa_report


def test_report_generator_falls_back_to_python_for_unknown_language():
    gen = ReportGenerator(
        repo_name="demo",
        commit_hash="abcdef1234567890",
        repo_url="https://github.com/example/demo",
        language="unknown",
    )

    assert gen.language == "python"
    assert gen._exploit_file == "exploit.py"
