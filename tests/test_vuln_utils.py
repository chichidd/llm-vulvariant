import json

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
