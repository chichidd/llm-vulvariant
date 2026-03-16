from pathlib import Path

import cli.profile_generation as profile_generation


def test_create_profile_llm_client_enables_thinking(monkeypatch) -> None:
    captured = {}

    def fake_create_llm_client(config):
        captured["provider"] = config.provider
        captured["model"] = config.model
        captured["enable_thinking"] = config.enable_thinking
        return object()

    monkeypatch.setattr(profile_generation, "create_llm_client", fake_create_llm_client)

    profile_generation.create_profile_llm_client("deepseek", "deepseek-chat")

    assert captured == {
        "provider": "deepseek",
        "model": "deepseek-chat",
        "enable_thinking": True,
    }


def test_build_vulnerability_entry_includes_call_chain_string() -> None:
    entry = profile_generation.build_vulnerability_entry(
        {
            "repo_name": "demo",
            "commit": "abc123",
            "call_chain": [
                {"file_path": "src/a.py", "function_name": "entry"},
                {"file_path": "src/b.py", "vuln_sink": "eval"},
            ],
            "payload": "payload",
            "cve_id": "CVE-2026-0001",
        }
    )

    assert entry.repo_name == "demo"
    assert entry.commit == "abc123"
    assert entry.call_chain_str == "src/a.py#entry -> src/b.py#eval"
    assert entry.payload == "payload"
    assert entry.cve_id == "CVE-2026-0001"


def test_run_software_profile_generation_passes_expected_arguments(monkeypatch, tmp_path) -> None:
    captured = {}

    class StubProfiler:
        def __init__(self, llm_client, output_dir):
            captured["llm_client"] = llm_client
            captured["output_dir"] = output_dir

        def generate_profile(self, repo_path, force_regenerate, target_version):
            captured["repo_path"] = repo_path
            captured["force_regenerate"] = force_regenerate
            captured["target_version"] = target_version
            return "software-profile"

    monkeypatch.setattr(profile_generation, "SoftwareProfiler", StubProfiler)

    result = profile_generation.run_software_profile_generation(
        repo_path=tmp_path / "repo",
        output_dir=tmp_path / "profiles",
        llm_client="llm",
        force_regenerate=True,
        target_version="abc123",
    )

    assert result == "software-profile"
    assert captured == {
        "llm_client": "llm",
        "output_dir": str(tmp_path / "profiles"),
        "repo_path": str(tmp_path / "repo"),
        "force_regenerate": True,
        "target_version": "abc123",
    }


def test_run_vulnerability_profile_generation_passes_expected_arguments(monkeypatch, tmp_path) -> None:
    captured = {}
    repo_profile = object()
    vuln_entry = profile_generation.build_vulnerability_entry(
        {
            "repo_name": "demo",
            "commit": "abc123",
            "call_chain": [{"file_path": "src/a.py", "function_name": "entry"}],
            "payload": None,
            "cve_id": "CVE-2026-0001",
        }
    )

    class StubProfiler:
        def __init__(self, llm_client, repo_profile, vuln_entry, output_dir):
            captured["llm_client"] = llm_client
            captured["repo_profile"] = repo_profile
            captured["vuln_entry"] = vuln_entry
            captured["output_dir"] = output_dir

        def generate_vulnerability_profile(self, repo_path, save_results=True):
            captured["repo_path"] = repo_path
            captured["save_results"] = save_results
            return "vulnerability-profile"

    monkeypatch.setattr(profile_generation, "VulnerabilityProfiler", StubProfiler)

    result = profile_generation.run_vulnerability_profile_generation(
        repo_path=tmp_path / "repo",
        output_dir=tmp_path / "profiles",
        llm_client="llm",
        repo_profile=repo_profile,
        vuln_entry=vuln_entry,
    )

    assert result == "vulnerability-profile"
    assert captured["llm_client"] == "llm"
    assert captured["repo_profile"] is repo_profile
    assert captured["vuln_entry"] == vuln_entry
    assert captured["output_dir"] == str(tmp_path / "profiles")
    assert captured["repo_path"] == str(Path(tmp_path / "repo"))
    assert captured["save_results"] is True
