import json

import pytest

import utils.vuln_utils as vuln_utils


def test_read_vuln_data_resolves_relative_paths_and_allows_missing_payload(tmp_path, monkeypatch):
    repo_root = tmp_path
    repos_dir = repo_root / "data" / "repos" / "demo"
    repos_dir.mkdir(parents=True)
    source_file = repos_dir / "src" / "api.py"
    source_file.parent.mkdir(parents=True, exist_ok=True)
    source_file.write_text("def entry():\n    return 1\n", encoding="utf-8")

    vuln_json = repo_root / "data" / "vuln.json"
    vuln_json.parent.mkdir(parents=True, exist_ok=True)
    vuln_json.write_text(
        json.dumps(
            [
                {
                    "repo_name": "demo",
                    "commit": "deadbeef",
                    "cve_id": "CVE-2026-0001",
                    "call_chain": ["src/api.py#entry", "os.system"],
                }
            ]
        ),
        encoding="utf-8",
    )

    monkeypatch.setitem(vuln_utils._path_config, "repo_root", repo_root)
    monkeypatch.setattr(vuln_utils, "get_git_restore_target", lambda repo_path: "main")
    monkeypatch.setattr(vuln_utils, "get_git_commit", lambda repo_path: "deadbeef")
    monkeypatch.setattr(vuln_utils, "has_uncommitted_changes", lambda repo_path: False)
    monkeypatch.setattr(vuln_utils, "checkout_commit", lambda repo_path, commit: True)
    monkeypatch.setattr(vuln_utils, "restore_git_position", lambda repo_path, restore_target: True)
    monkeypatch.setattr(
        vuln_utils,
        "extract_function_snippet_based_on_name_with_ast",
        lambda code_content, function_name, with_line_numbers=True, line_number_format="standard": "1: def entry():",
    )

    records = vuln_utils.read_vuln_data(
        vuln_json_path="data/vuln.json",
        repo_base_path="data/repos",
    )

    assert len(records) == 1
    assert records[0]["payload"] is None
    assert records[0]["call_chain"][0]["file_path"] == "src/api.py"
    assert records[0]["call_chain"][0]["code_snippet"] == "1: def entry():"


def test_read_vuln_data_refuses_checkout_without_restore_target(tmp_path, monkeypatch):
    repo_root = tmp_path
    repos_dir = repo_root / "data" / "repos" / "demo"
    repos_dir.mkdir(parents=True)
    source_file = repos_dir / "src" / "api.py"
    source_file.parent.mkdir(parents=True, exist_ok=True)
    source_file.write_text("def entry():\n    return 1\n", encoding="utf-8")

    vuln_json = repo_root / "data" / "vuln.json"
    vuln_json.parent.mkdir(parents=True, exist_ok=True)
    vuln_json.write_text(
        json.dumps(
            [
                {
                    "repo_name": "demo",
                    "commit": "deadbeef",
                    "cve_id": "CVE-2026-0001",
                    "call_chain": ["src/api.py#entry"],
                }
            ]
        ),
        encoding="utf-8",
    )

    checkout_calls = []

    monkeypatch.setitem(vuln_utils._path_config, "repo_root", repo_root)
    monkeypatch.setattr(vuln_utils, "get_git_restore_target", lambda repo_path: None)
    monkeypatch.setattr(vuln_utils, "get_git_commit", lambda repo_path: "cafebabe")
    monkeypatch.setattr(vuln_utils, "has_uncommitted_changes", lambda repo_path: False)
    monkeypatch.setattr(
        vuln_utils,
        "checkout_commit",
        lambda repo_path, commit: checkout_calls.append(commit) or True,
    )

    with pytest.raises(RuntimeError, match="Unable to resolve original git position"):
        vuln_utils.read_vuln_data(
            vuln_json_path="data/vuln.json",
            repo_base_path="data/repos",
        )

    assert checkout_calls == []


def test_read_vuln_data_raises_when_restore_fails(tmp_path, monkeypatch):
    repo_root = tmp_path
    repos_dir = repo_root / "data" / "repos" / "demo"
    repos_dir.mkdir(parents=True)
    source_file = repos_dir / "src" / "api.py"
    source_file.parent.mkdir(parents=True, exist_ok=True)
    source_file.write_text("def entry():\n    return 1\n", encoding="utf-8")

    vuln_json = repo_root / "data" / "vuln.json"
    vuln_json.parent.mkdir(parents=True, exist_ok=True)
    vuln_json.write_text(
        json.dumps(
            [
                {
                    "repo_name": "demo",
                    "commit": "deadbeef",
                    "cve_id": "CVE-2026-0001",
                    "call_chain": ["src/api.py#entry"],
                }
            ]
        ),
        encoding="utf-8",
    )

    monkeypatch.setitem(vuln_utils._path_config, "repo_root", repo_root)
    monkeypatch.setattr(vuln_utils, "get_git_restore_target", lambda repo_path: "main")
    monkeypatch.setattr(vuln_utils, "get_git_commit", lambda repo_path: "cafebabe")
    monkeypatch.setattr(vuln_utils, "has_uncommitted_changes", lambda repo_path: False)
    monkeypatch.setattr(vuln_utils, "checkout_commit", lambda repo_path, commit: True)
    monkeypatch.setattr(vuln_utils, "restore_git_position", lambda repo_path, restore_target: False)
    monkeypatch.setattr(
        vuln_utils,
        "extract_function_snippet_based_on_name_with_ast",
        lambda code_content, function_name, with_line_numbers=True, line_number_format="standard": "1: def entry():",
    )

    with pytest.raises(RuntimeError, match="Failed to restore demo to main"):
        vuln_utils.read_vuln_data(
            vuln_json_path="data/vuln.json",
            repo_base_path="data/repos",
        )


def test_read_vuln_data_surfaces_restore_failure_when_body_also_errors(tmp_path, monkeypatch):
    repo_root = tmp_path
    repos_dir = repo_root / "data" / "repos" / "demo"
    repos_dir.mkdir(parents=True)
    source_file = repos_dir / "src" / "api.py"
    source_file.parent.mkdir(parents=True, exist_ok=True)
    source_file.write_text("def entry():\n    return 1\n", encoding="utf-8")

    vuln_json = repo_root / "data" / "vuln.json"
    vuln_json.parent.mkdir(parents=True, exist_ok=True)
    vuln_json.write_text(
        json.dumps(
            [
                {
                    "repo_name": "demo",
                    "commit": "deadbeef",
                    "cve_id": "CVE-2026-0001",
                    "call_chain": ["src/api.py#entry"],
                }
            ]
        ),
        encoding="utf-8",
    )

    monkeypatch.setitem(vuln_utils._path_config, "repo_root", repo_root)
    monkeypatch.setattr(vuln_utils, "get_git_restore_target", lambda repo_path: "main")
    monkeypatch.setattr(vuln_utils, "get_git_commit", lambda repo_path: "cafebabe")
    monkeypatch.setattr(vuln_utils, "has_uncommitted_changes", lambda repo_path: False)
    monkeypatch.setattr(vuln_utils, "checkout_commit", lambda repo_path, commit: True)
    monkeypatch.setattr(vuln_utils, "restore_git_position", lambda repo_path, restore_target: False)
    monkeypatch.setattr(
        vuln_utils,
        "extract_function_snippet_based_on_name_with_ast",
        lambda *args, **kwargs: (_ for _ in ()).throw(ValueError("snippet boom")),
    )

    with pytest.raises(RuntimeError, match="Failed to restore demo to main"):
        vuln_utils.read_vuln_data(
            vuln_json_path="data/vuln.json",
            repo_base_path="data/repos",
        )


def test_read_vuln_data_rejects_call_chain_paths_outside_repo_root(tmp_path, monkeypatch):
    repo_root = tmp_path
    repos_dir = repo_root / "data" / "repos" / "demo"
    repos_dir.mkdir(parents=True)
    escaped_file = repo_root / "data" / "repos" / "secret.py"
    escaped_file.write_text("def secret():\n    return 42\n", encoding="utf-8")

    vuln_json = repo_root / "data" / "vuln.json"
    vuln_json.parent.mkdir(parents=True, exist_ok=True)
    vuln_json.write_text(
        json.dumps(
            [
                {
                    "repo_name": "demo",
                    "commit": "deadbeef",
                    "cve_id": "CVE-2026-0001",
                    "call_chain": ["../secret.py#entry"],
                }
            ]
        ),
        encoding="utf-8",
    )

    monkeypatch.setitem(vuln_utils._path_config, "repo_root", repo_root)
    monkeypatch.setattr(vuln_utils, "get_git_restore_target", lambda repo_path: "main")
    monkeypatch.setattr(vuln_utils, "get_git_commit", lambda repo_path: "deadbeef")
    monkeypatch.setattr(vuln_utils, "has_uncommitted_changes", lambda repo_path: False)
    monkeypatch.setattr(vuln_utils, "checkout_commit", lambda repo_path, commit: True)
    monkeypatch.setattr(vuln_utils, "restore_git_position", lambda repo_path, restore_target: True)
    monkeypatch.setattr(
        vuln_utils,
        "extract_function_snippet_based_on_name_with_ast",
        lambda *args, **kwargs: pytest.fail("escaped paths must not be read"),
    )

    with pytest.raises(RuntimeError, match="escapes repository root"):
        vuln_utils.read_vuln_data(
            vuln_json_path="data/vuln.json",
            repo_base_path="data/repos",
        )
