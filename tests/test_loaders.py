import json

import config as config_module
from scanner.agent.loaders import load_software_profile, load_vulnerability_profile


def test_load_software_profile_success_and_missing(tmp_path):
    base = tmp_path / "soft"
    profile_dir = base / "repo" / "abc"
    profile_dir.mkdir(parents=True)
    (profile_dir / "software_profile.json").write_text(
        json.dumps({"basic_info": {"name": "repo", "version": "abc"}}),
        encoding="utf-8",
    )

    profile = load_software_profile("repo", "abc", base_dir=base)
    missing = load_software_profile("repo", "def", base_dir=base)

    assert profile is not None
    assert profile.name == "repo"
    assert profile.version == "abc"
    assert missing is None


def test_load_vulnerability_profile_success_and_invalid_json(tmp_path):
    base = tmp_path / "vuln-profiles"
    profile_dir = base / "repo" / "CVE-1"
    profile_dir.mkdir(parents=True)
    (profile_dir / "vulnerability_profile.json").write_text(
        json.dumps({"repo_name": "repo", "cve_id": "CVE-1"}),
        encoding="utf-8",
    )

    profile = load_vulnerability_profile("repo", "CVE-1", base_dir=base)
    assert profile is not None
    assert profile.repo_name == "repo"

    (profile_dir / "vulnerability_profile.json").write_text("{bad-json", encoding="utf-8")
    broken = load_vulnerability_profile("repo", "CVE-1", base_dir=base)
    assert broken is None


def test_loaders_default_base_dir_from_path_config(monkeypatch, tmp_path):
    profile_base = tmp_path / "profiles"
    repo_base = profile_base / "soft"
    repo_profile_dir = repo_base / "repo" / "abc"
    repo_profile_dir.mkdir(parents=True)
    (repo_profile_dir / "software_profile.json").write_text(
        json.dumps({"basic_info": {"name": "repo", "version": "abc"}}),
        encoding="utf-8",
    )

    vuln_base = profile_base / "vuln"
    vuln_profile_dir = vuln_base / "repo" / "CVE-1"
    vuln_profile_dir.mkdir(parents=True)
    (vuln_profile_dir / "vulnerability_profile.json").write_text(
        json.dumps({"repo_name": "repo", "cve_id": "CVE-1"}),
        encoding="utf-8",
    )

    monkeypatch.setitem(config_module._path_config, "profile_base_path", profile_base)

    software_profile = load_software_profile("repo", "abc")
    vuln_profile = load_vulnerability_profile("repo", "CVE-1")

    assert software_profile is not None
    assert software_profile.version == "abc"
    assert vuln_profile is not None
    assert vuln_profile.cve_id == "CVE-1"
