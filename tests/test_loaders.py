import json

from scanner.agent.loaders import load_software_profile, load_vulnerability_profile


def test_load_software_profile_success_and_missing(tmp_path):
    base = tmp_path / "repo-profiles"
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
