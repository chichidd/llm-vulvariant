import config as config_module


def test_load_paths_config_resolves_relative_paths_from_project_root(tmp_path):
    config_path = tmp_path / "config" / "paths.yaml"
    config_path.parent.mkdir(parents=True)
    config_path.write_text(
        "\n".join(
            [
                "paths:",
                "  project_root: project-root",
                "  profile_base_path: profiles",
                "  data_base_path: data",
                "  vuln_data_path: data/vuln.json",
                "  repo_base_path: repos",
                "  codeql_db_path: codeql",
                "  embedding_model_path: models",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    loaded = config_module.load_paths_config(config_path)
    project_root = tmp_path / "config" / "project-root"

    assert loaded["project_root"] == project_root
    assert loaded["profile_base_path"] == project_root / "profiles"
    assert loaded["data_base_path"] == project_root / "data"
    assert loaded["vuln_data_path"] == project_root / "data" / "vuln.json"
    assert loaded["repo_base_path"] == project_root / "repos"
    assert loaded["codeql_db_path"] == project_root / "codeql"
    assert loaded["embedding_model_path"] == project_root / "models"


def test_resolve_profile_base_path_anchors_relative_override_to_repo_root(monkeypatch, tmp_path):
    repo_root = tmp_path / "llm-vulvariant"
    repo_root.mkdir()
    monkeypatch.setitem(config_module._path_config, "repo_root", repo_root)

    assert config_module.resolve_profile_base_path("profiles") == repo_root / "profiles"
