import hashlib
from pathlib import Path

import pytest

import config as config_module


def test_load_paths_config_resolves_relative_paths_from_project_root(tmp_path):
    config_path = tmp_path / "config" / "paths.yaml"
    config_path.parent.mkdir(parents=True)
    config_path.write_text(
        "\n".join(
            [
                "paths:",
                "  project_root: project-root",
                "  repo_root: project-root/repo-checkout",
                "  results_base_path: results",
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
    assert loaded["repo_root"] == project_root / "repo-checkout"
    assert loaded["results_base_path"] == project_root / "results"
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


def test_default_paths_are_canonical_and_revision_local():
    loaded = config_module.load_paths_config()
    repo_root = Path(config_module.__file__).resolve().parents[1]
    revision_root = Path(config_module.__file__).resolve().parents[3]

    assert loaded["project_root"] == revision_root
    assert loaded["results_base_path"] == revision_root / "results"
    assert loaded["repo_root"] == repo_root
    assert loaded["profile_base_path"] == revision_root / "evidence" / "profiles"
    assert loaded["vuln_data_path"] == revision_root / "benchmark" / "input" / "vuln.json"
    assert loaded["repo_base_path"] == revision_root / "repos" / "general"
    for name, path in loaded.items():
        if name == "project_root":
            continue
        path.relative_to(revision_root)


def test_load_paths_config_fails_closed_when_missing_or_invalid(tmp_path):
    with pytest.raises(FileNotFoundError, match="Path configuration not found"):
        config_module.load_paths_config(tmp_path / "missing.yaml")

    invalid = tmp_path / "invalid.yaml"
    invalid.write_text("paths: [\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Failed to load path configuration"):
        config_module.load_paths_config(invalid)

    incomplete = tmp_path / "incomplete.yaml"
    incomplete.write_text("paths:\n  project_root: .\n", encoding="utf-8")
    with pytest.raises(ValueError, match="missing required keys"):
        config_module.load_paths_config(incomplete)


@pytest.mark.parametrize("parent_alias", ["~/vuln", "${HOME}/vuln", "$HOME/vuln"])
def test_load_paths_config_rejects_implicit_parent_home_aliases(tmp_path, parent_alias):
    config_path = tmp_path / "paths.yaml"
    config_path.write_text(
        "\n".join(
            [
                "paths:",
                f"  project_root: '{parent_alias}'",
                "  repo_root: repo",
                "  results_base_path: results",
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

    with pytest.raises(ValueError, match="aliases are forbidden"):
        config_module.load_paths_config(config_path)


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("project_root", "/mnt/host"),
        ("project_root", "../../../.."),
        ("profile_base_path", "../../../host-profiles"),
    ],
)
def test_default_paths_cannot_be_rebound_after_registry_freeze(
    tmp_path, monkeypatch, name, value
):
    revision_root = tmp_path / "ccs-revision"
    repo_root = revision_root / "code" / "llm-vulvariant"
    src_dir = repo_root / "src"
    config_dir = repo_root / "config"
    src_dir.mkdir(parents=True)
    config_dir.mkdir(parents=True)
    values = {
        "project_root": "../../..",
        "repo_root": "..",
        "results_base_path": "results",
        "profile_base_path": "evidence/profiles",
        "data_base_path": "benchmark/input",
        "vuln_data_path": "benchmark/input/vuln.json",
        "repo_base_path": "repos/general",
        "codeql_db_path": "results/codeql-dbs",
        "embedding_model_path": "./models",
    }
    values[name] = value
    (config_dir / "paths.yaml").write_text(
        "paths:\n"
        + "".join(f"  {key}: '{path}'\n" for key, path in values.items()),
        encoding="utf-8",
    )
    monkeypatch.setattr(config_module, "__file__", str(src_dir / "config.py"))

    assert config_module.load_paths_config() == config_module._path_config


def test_paths_config_rejects_duplicate_yaml_keys(tmp_path):
    config_path = tmp_path / "paths.yaml"
    config_path.write_text(
        "paths:\n  project_root: .\n  project_root: other\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Duplicate YAML key: project_root"):
        config_module.load_paths_config(config_path)


@pytest.mark.parametrize(
    ("project_root", "profile_base_path", "message"),
    [
        ("/", "profiles", "must not be filesystem root"),
        (".", "../outside", "escapes project_root"),
    ],
)
def test_custom_paths_reject_overwide_root_or_escape(
    tmp_path, project_root, profile_base_path, message
):
    config_path = tmp_path / "paths.yaml"
    config_path.write_text(
        "\n".join(
            [
                "paths:",
                f"  project_root: '{project_root}'",
                "  repo_root: repo",
                "  results_base_path: results",
                f"  profile_base_path: '{profile_base_path}'",
                "  data_base_path: data",
                "  vuln_data_path: data/vuln.json",
                "  repo_base_path: repos",
                "  codeql_db_path: results/codeql-dbs",
                "  embedding_model_path: models",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match=message):
        config_module.load_paths_config(config_path)


def test_scanner_config_fails_closed_on_missing_invalid_or_duplicate(tmp_path):
    with pytest.raises(FileNotFoundError, match="Scanner configuration not found"):
        config_module.load_scanner_config(tmp_path / "missing.yaml")

    invalid = tmp_path / "invalid-scanner.yaml"
    invalid.write_text("module_similarity: [\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Failed to load scanner configuration"):
        config_module.load_scanner_config(invalid)

    duplicate = tmp_path / "duplicate-scanner.yaml"
    duplicate.write_text(
        "module_similarity:\n"
        "  threshold: 0.8\n"
        "  model_name: first\n"
        "  model_name: second\n"
        "  device: cpu\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="Duplicate YAML key: model_name"):
        config_module.load_scanner_config(duplicate)


@pytest.mark.parametrize(
    "threshold",
    ["true", ".nan", ".inf", "-.inf", "-0.0001", "1.0001"],
)
def test_scanner_config_rejects_non_finite_boolean_or_out_of_range_threshold(
    tmp_path, threshold
):
    config_path = tmp_path / "scanner.yaml"
    config_path.write_text(
        "module_similarity:\n"
        f"  threshold: {threshold}\n"
        "  model_name: local-model\n"
        "  device: cpu\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match=r"finite number in \[0, 1\]"):
        config_module.load_scanner_config(config_path)


def test_paths_config_allows_project_local_embedding_model_symlink(tmp_path):
    project_root = tmp_path / "revision"
    repo_root = project_root / "code" / "llm-vulvariant"
    outside_models = tmp_path / "shared-models"
    repo_root.mkdir(parents=True)
    outside_models.mkdir()
    (project_root / "models").symlink_to(
        outside_models,
        target_is_directory=True,
    )
    config_path = tmp_path / "paths.yaml"
    config_path.write_text(
        "paths:\n"
        f"  project_root: '{project_root}'\n"
        f"  repo_root: '{repo_root}'\n"
        "  results_base_path: results\n"
        "  profile_base_path: profiles\n"
        "  data_base_path: data\n"
        "  vuln_data_path: data/vuln.json\n"
        "  repo_base_path: repos\n"
        "  codeql_db_path: results/codeql-dbs\n"
        "  embedding_model_path: models\n",
        encoding="utf-8",
    )

    loaded = config_module.load_paths_config(config_path)

    assert loaded["embedding_model_path"] == project_root / "models"
    assert loaded["embedding_model_path"].is_symlink()
    assert loaded["embedding_model_path"].resolve() == outside_models


def test_paths_config_rejects_skill_symlink_escape(tmp_path):
    project_root = tmp_path / "revision"
    repo_root = project_root / "code" / "llm-vulvariant"
    skills_parent = repo_root / ".claude"
    outside = tmp_path / "outside-skills"
    skills_parent.mkdir(parents=True)
    outside.mkdir()
    (skills_parent / "skills").symlink_to(outside, target_is_directory=True)
    config_path = tmp_path / "paths.yaml"
    config_path.write_text(
        "paths:\n"
        f"  project_root: '{project_root}'\n"
        f"  repo_root: '{repo_root}'\n"
        "  results_base_path: results\n"
        "  profile_base_path: profiles\n"
        "  data_base_path: data\n"
        "  vuln_data_path: data/vuln.json\n"
        "  repo_base_path: repos\n"
        "  codeql_db_path: results/codeql-dbs\n"
        "  embedding_model_path: models\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="escapes project_root: skill_path"):
        config_module.load_paths_config(config_path)


def test_yaml_snapshot_hashes_the_exact_single_read_used_for_parsing():
    raw_bytes = b"module_similarity:\n  threshold: 0.75\n"

    class SingleReadPath:
        def __init__(self):
            self.read_count = 0

        def read_bytes(self):
            self.read_count += 1
            if self.read_count > 1:
                raise AssertionError("configuration was read more than once")
            return raw_bytes

    snapshot_path = SingleReadPath()
    parsed, digest = config_module._load_yaml_snapshot(snapshot_path)

    assert snapshot_path.read_count == 1
    assert parsed == {"module_similarity": {"threshold": 0.75}}
    assert digest == hashlib.sha256(raw_bytes).hexdigest()
