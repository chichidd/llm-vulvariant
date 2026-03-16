from argparse import Namespace
from types import SimpleNamespace

import cli.software as cli_software
import cli.vulnerability as cli_vulnerability


def test_software_main_uses_shared_generation_helper(monkeypatch, tmp_path) -> None:
    repo_root = tmp_path / "repos"
    repo_root.mkdir()
    profile_root = tmp_path / "profiles"
    profile_root.mkdir()

    captured = {}

    monkeypatch.setattr(
        cli_software,
        "parse_args",
        lambda: Namespace(
            repo_name="demo",
            llm_provider="deepseek",
            llm_name="deepseek-chat",
            profile_base_path=str(profile_root),
            software_profile_dirname="soft",
            output_dir=None,
            repo_base_path=str(repo_root),
            target_version="abc123",
            force_regenerate=True,
            verbose=False,
        ),
    )
    monkeypatch.setattr(cli_software, "setup_logging", lambda verbose: None)
    monkeypatch.setattr(cli_software, "resolve_profile_dirs", lambda **kwargs: (profile_root / "soft", None))
    monkeypatch.setattr(cli_software, "create_profile_llm_client", lambda provider, model: "llm")
    monkeypatch.setattr(
        cli_software,
        "run_software_profile_generation",
        lambda *, repo_path, output_dir, llm_client, force_regenerate, target_version: captured.update(
            {
                "repo_path": repo_path,
                "output_dir": output_dir,
                "llm_client": llm_client,
                "force_regenerate": force_regenerate,
                "target_version": target_version,
            }
        ),
    )

    assert cli_software.main() == 0
    assert captured == {
        "repo_path": repo_root / "demo",
        "output_dir": profile_root / "soft",
        "llm_client": "llm",
        "force_regenerate": True,
        "target_version": "abc123",
    }


def test_vulnerability_main_uses_shared_generation_helper(monkeypatch, tmp_path) -> None:
    repo_root = tmp_path / "repos"
    (repo_root / "demo").mkdir(parents=True)
    repo_profile_dir = tmp_path / "profiles" / "soft"
    vuln_profile_dir = tmp_path / "profiles" / "vuln"

    captured = {}
    fake_profile = SimpleNamespace(repo_name="demo")

    monkeypatch.setattr(
        cli_vulnerability,
        "parse_args",
        lambda: Namespace(
            vuln_index=4,
            vuln_json=str(tmp_path / "vuln.json"),
            llm_provider="deepseek",
            llm_name="deepseek-chat",
            profile_base_path=str(tmp_path / "profiles"),
            software_profile_dirname="soft",
            vuln_profile_dirname="vuln",
            output_dir=None,
            soft_profile_dir=None,
            repo_base_path=str(repo_root),
            verbose=False,
        ),
    )
    monkeypatch.setattr(cli_vulnerability, "setup_logging", lambda verbose: None)
    monkeypatch.setattr(
        cli_vulnerability,
        "resolve_profile_dirs",
        lambda **kwargs: (repo_profile_dir, vuln_profile_dir),
    )
    monkeypatch.setattr(
        cli_vulnerability,
        "read_vuln_data",
        lambda **kwargs: [
            {
                "repo_name": "demo",
                "commit": "abc123",
                "call_chain": [{"file_path": "src/a.py", "function_name": "entry"}],
                "payload": "payload",
                "cve_id": "CVE-2026-0001",
            }
        ],
    )
    monkeypatch.setattr(cli_vulnerability, "load_software_profile", lambda *args, **kwargs: object())
    monkeypatch.setattr(cli_vulnerability, "create_profile_llm_client", lambda provider, model: "llm")
    monkeypatch.setattr(cli_vulnerability, "display_vulnerability_profile", lambda profile: captured.update({"profile": profile}))
    monkeypatch.setattr(
        cli_vulnerability,
        "run_vulnerability_profile_generation",
        lambda *, repo_path, output_dir, llm_client, repo_profile, vuln_entry: captured.update(
            {
                "repo_path": repo_path,
                "output_dir": output_dir,
                "llm_client": llm_client,
                "repo_profile": repo_profile,
                "vuln_entry": vuln_entry,
            }
        )
        or fake_profile,
    )

    assert cli_vulnerability.main() == 0
    assert captured["repo_path"] == repo_root / "demo"
    assert captured["output_dir"] == vuln_profile_dir
    assert captured["llm_client"] == "llm"
    assert captured["vuln_entry"].repo_name == "demo"
    assert captured["vuln_entry"].commit == "abc123"
    assert captured["vuln_entry"].call_chain_str == "src/a.py#entry"
    assert captured["profile"] is fake_profile


def test_vulnerability_main_returns_error_when_software_profile_is_missing(monkeypatch, tmp_path) -> None:
    repo_root = tmp_path / "repos"
    (repo_root / "demo").mkdir(parents=True)
    repo_profile_dir = tmp_path / "profiles" / "soft"
    vuln_profile_dir = tmp_path / "profiles" / "vuln"

    monkeypatch.setattr(
        cli_vulnerability,
        "parse_args",
        lambda: Namespace(
            vuln_index=1,
            vuln_json=str(tmp_path / "vuln.json"),
            llm_provider="deepseek",
            llm_name="deepseek-chat",
            profile_base_path=str(tmp_path / "profiles"),
            software_profile_dirname="soft",
            vuln_profile_dirname="vuln",
            output_dir=None,
            soft_profile_dir=None,
            repo_base_path=str(repo_root),
            verbose=False,
        ),
    )
    monkeypatch.setattr(cli_vulnerability, "setup_logging", lambda verbose: None)
    monkeypatch.setattr(
        cli_vulnerability,
        "resolve_profile_dirs",
        lambda **kwargs: (repo_profile_dir, vuln_profile_dir),
    )
    monkeypatch.setattr(
        cli_vulnerability,
        "read_vuln_data",
        lambda **kwargs: [
            {
                "repo_name": "demo",
                "commit": "abc123",
                "call_chain": [{"file_path": "src/a.py", "function_name": "entry"}],
                "payload": "payload",
                "cve_id": "CVE-2026-0001",
            }
        ],
    )
    monkeypatch.setattr(cli_vulnerability, "load_software_profile", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        cli_vulnerability,
        "run_vulnerability_profile_generation",
        lambda **kwargs: (_ for _ in ()).throw(AssertionError("should not run without software profile")),
    )

    assert cli_vulnerability.main() == 1
