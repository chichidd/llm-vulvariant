"""Tests for the CodeQL query directory setup changes in AgenticToolkit.

Verifies that:
- _init_codeql sets template dir from _path_config and defers actual dir creation.
- _setup_query_dir creates the dir under output_dir and copies yml files.
- _setup_query_dir is idempotent (second call is a no-op).
- _setup_query_dir returns False when memory_manager is missing.
- _ensure_query_pack delegates to _setup_query_dir.
- _run_codeql_query writes the .ql file under output_dir/codeql-queries/<lang>/.
"""

import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from profiler.fingerprint import stable_data_hash

# ---------------------------------------------------------------------------
# Helpers / Fakes
# ---------------------------------------------------------------------------

class FakeCodeQLAnalyzer:
    """Minimal CodeQL analyzer stub."""
    is_available = True

    def run_query(self, database_path, query, output_format="sarif-latest"):
        # Return empty SARIF so downstream extraction works
        return True, {"runs": [{"results": []}]}


class FakeMemoryManager:
    """Minimal memory manager stub that provides an output_dir."""

    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.memory = SimpleNamespace(
            file_status={},
            file_completion_reasons={},
        )
        self._findings = []
        self._issues = []

    def add_finding(self, finding):
        self._findings.append(finding)

    def add_issue(self, issue):
        self._issues.append(issue)


def _make_toolkit(
    tmp_path: Path,
    *,
    with_memory: bool = True,
    with_template_ymls: bool = True,
    language: str = "python",
    languages=None,
):
    """Build an AgenticToolkit wired to temp directories.

    Returns (toolkit, repo_path, output_dir, template_dir).
    """
    repo_path = tmp_path / "fake_repo"
    repo_path.mkdir()
    # Create a dummy .py so language detection won't be needed
    (repo_path / "main.py").write_text("print('hi')\n")
    (repo_path / "main.js").write_text("console.log('hi')\n")

    output_dir = tmp_path / "output"
    output_dir.mkdir()

    resolved_languages = list(languages or [language])
    template_base = tmp_path / "template_root" / ".codeql-queries" / language
    for lang in resolved_languages:
        template_dir = tmp_path / "template_root" / ".codeql-queries" / lang
        template_dir.mkdir(parents=True)
        if with_template_ymls:
            (template_dir / "qlpack.yml").write_text("name: test-pack\n")
            (template_dir / "codeql-pack.lock.yml").write_text("lockfileVersion: 1.0.0\n")

    if with_template_ymls:
        # Keep reference path used by existing tests.
        template_base.mkdir(parents=True, exist_ok=True)

    memory = FakeMemoryManager(output_dir) if with_memory else None

    fake_path_config = {
        "repo_root": tmp_path / "template_root",
        "codeql_db_path": tmp_path / "codeql_dbs",
    }

    with patch("scanner.agent.toolkit._path_config", fake_path_config), \
         patch("scanner.agent.toolkit.CodeQLAnalyzer", FakeCodeQLAnalyzer), \
         patch("scanner.agent.toolkit.detect_repo_languages", return_value=resolved_languages):
        from scanner.agent.toolkit import AgenticToolkit
        tk = AgenticToolkit(
            repo_path=repo_path,
            memory_manager=memory,
            languages=languages,
        )

    return tk, repo_path, output_dir, template_base


def _write_codeql_database_metadata(
    db_dir: Path,
    *,
    source_repo_path: Path,
    sha: str,
    primary_language: str = "python",
) -> None:
    """Write the minimal CodeQL DB identity metadata used by relocation fallback."""
    db_dir.mkdir(parents=True, exist_ok=True)
    (db_dir / "codeql-database.yml").write_text(
        "\n".join(
            [
                "---",
                f"sourceLocationPrefix: {source_repo_path.resolve()}",
                f"primaryLanguage: {primary_language}",
                "creationMetadata:",
                f"  sha: {sha}",
                "",
            ]
        ),
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestInitCodeql:
    """_init_codeql should store the template path and leave query_dir unset."""

    def test_template_dir_points_to_language_subdir(self, tmp_path):
        tk, _, _, template_base = _make_toolkit(tmp_path, language="python")
        assert tk._codeql_query_template_dirs["python"] == template_base

    def test_query_dir_is_none_after_init(self, tmp_path):
        tk, _, _, _ = _make_toolkit(tmp_path)
        assert tk._codeql_query_dirs == {}

    def test_query_dir_ready_is_false_after_init(self, tmp_path):
        tk, _, _, _ = _make_toolkit(tmp_path)
        assert tk._codeql_query_dirs_ready == set()


class TestSetupQueryDir:
    """_setup_query_dir should create dir and copy yml files."""

    def test_creates_query_dir_under_output(self, tmp_path):
        tk, _, output_dir, _ = _make_toolkit(tmp_path)
        result = tk._setup_query_dir()
        assert result is True
        expected = output_dir / "codeql-queries" / "python"
        assert expected.is_dir()
        assert tk._codeql_query_dirs.get("python") == expected

    def test_copies_yml_files(self, tmp_path):
        tk, _, output_dir, _ = _make_toolkit(tmp_path)
        tk._setup_query_dir()
        query_dir = output_dir / "codeql-queries" / "python"
        assert (query_dir / "qlpack.yml").exists()
        assert (query_dir / "codeql-pack.lock.yml").exists()
        # Verify content matches template
        assert (query_dir / "qlpack.yml").read_text() == "name: test-pack\n"

    def test_does_not_overwrite_existing_ymls(self, tmp_path):
        tk, _, output_dir, _ = _make_toolkit(tmp_path)
        # Pre-create with different content
        query_dir = output_dir / "codeql-queries" / "python"
        query_dir.mkdir(parents=True)
        (query_dir / "qlpack.yml").write_text("custom content\n")

        tk._setup_query_dir()
        # Should keep existing content, not overwrite
        assert (query_dir / "qlpack.yml").read_text() == "custom content\n"

    def test_idempotent_second_call(self, tmp_path):
        tk, _, _, _ = _make_toolkit(tmp_path)
        assert tk._setup_query_dir() is True
        first_dir = tk._codeql_query_dirs.get("python")
        # Second call should return True without re-creating
        assert tk._setup_query_dir() is True
        assert tk._codeql_query_dirs.get("python") == first_dir

    def test_returns_false_without_memory_manager(self, tmp_path):
        tk, _, _, _ = _make_toolkit(tmp_path, with_memory=False)
        assert tk._setup_query_dir() is False
        assert tk._codeql_query_dirs == {}

    def test_works_without_template_ymls(self, tmp_path):
        tk, _, output_dir, _ = _make_toolkit(tmp_path, with_template_ymls=False)
        result = tk._setup_query_dir()
        assert result is True
        query_dir = output_dir / "codeql-queries" / "python"
        assert query_dir.is_dir()
        # No yml files should be present (template had none)
        assert not (query_dir / "qlpack.yml").exists()
        assert not (query_dir / "codeql-pack.lock.yml").exists()

    def test_works_for_different_languages(self, tmp_path):
        tk, _, output_dir, _ = _make_toolkit(tmp_path, language="go")
        tk._setup_query_dir()
        expected = output_dir / "codeql-queries" / "go"
        assert expected.is_dir()
        assert tk._codeql_query_dirs.get("go") == expected


class TestEnsureQueryPack:
    """_ensure_query_pack should delegate to _setup_query_dir and check lock file."""

    def test_returns_true_when_lock_file_copied_from_template(self, tmp_path):
        tk, _, _, _ = _make_toolkit(tmp_path)
        # Template has codeql-pack.lock.yml so it should be copied → no install needed
        result = tk._ensure_query_pack()
        assert result is True

    def test_returns_false_without_memory_manager(self, tmp_path):
        tk, _, _, _ = _make_toolkit(tmp_path, with_memory=False)
        result = tk._ensure_query_pack()
        assert result is False

    def test_installs_when_no_lock_file(self, tmp_path):
        """When template has no lock file, _ensure_query_pack should try codeql pack install."""
        tk, _, output_dir, _ = _make_toolkit(tmp_path, with_template_ymls=False)

        # Manually create qlpack.yml so we skip the get_codeql_pack path
        tk._setup_query_dir()
        (tk._codeql_query_dirs["python"] / "qlpack.yml").write_text("name: test\n")

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="")
            result = tk._ensure_query_pack()

        assert result is True
        mock_run.assert_called_once()
        # Verify the install command targets the correct directory
        call_args = mock_run.call_args
        assert str(output_dir / "codeql-queries" / "python") in call_args[0][0][-1]


class TestRunCodeqlQuery:
    """_run_codeql_query should write .ql files under the output query dir."""

    def test_ql_file_saved_to_output_dir(self, tmp_path):
        tk, _, output_dir, _ = _make_toolkit(tmp_path)

        # Create a fake database so path check passes
        db_name = "test-db-python"
        tk._codeql_database_names = {"python": db_name}
        db_dir = tk._codeql_db_base_path / db_name
        db_dir.mkdir(parents=True)

        query_code = "import python\nselect 1"
        result = tk._run_codeql_query(query=query_code, query_name="test_query")

        assert result.success is True
        # Verify .ql file was written under output's codeql-queries dir
        ql_file = output_dir / "codeql-queries" / "python" / "test_query.ql"
        assert ql_file.exists()
        assert ql_file.read_text() == query_code

    def test_query_name_sanitized_in_filename(self, tmp_path):
        tk, _, output_dir, _ = _make_toolkit(tmp_path)
        db_name = "test-db-python"
        tk._codeql_database_names = {"python": db_name}
        (tk._codeql_db_base_path / db_name).mkdir(parents=True)

        result = tk._run_codeql_query(
            query="select 1", query_name="my query/special chars!"
        )
        assert result.success is True
        # Special chars should be replaced with _
        ql_file = output_dir / "codeql-queries" / "python" / "my_query_special_chars_.ql"
        assert ql_file.exists()

    def test_fails_without_database(self, tmp_path):
        tk, _, _, _ = _make_toolkit(tmp_path)
        tk._codeql_database_names = {"python": "nonexistent-db"}
        result = tk._run_codeql_query(query="select 1", query_name="test")
        assert result.success is False
        assert "not found" in result.error.lower()

    def test_fails_without_codeql_analyzer(self, tmp_path):
        tk, _, _, _ = _make_toolkit(tmp_path)
        tk._codeql_analyzer = None
        result = tk._run_codeql_query(query="select 1", query_name="test")
        assert result.success is False
        assert "not available" in result.error.lower()

    def test_run_codeql_query_falls_back_to_profile_generated_database_name(self, tmp_path):
        tk, repo_path, output_dir, _ = _make_toolkit(tmp_path)
        tk._software_profile = SimpleNamespace(version="deadbeef1234")
        tk._codeql_database_names = {"python": "fake_repo-deadbeef-python"}
        repo_path_hash = stable_data_hash(str(repo_path.resolve()))[:12]
        actual_db_name = f"{repo_path.name}-{repo_path_hash}-deadbeef-python"
        _write_codeql_database_metadata(
            tk._codeql_db_base_path / actual_db_name,
            source_repo_path=repo_path.resolve(),
            sha="deadbeef1234",
        )

        captured = {}

        def fake_run_query(database_path, query, output_format="sarif-latest"):
            captured["database_path"] = database_path
            captured["query"] = query
            captured["output_format"] = output_format
            return True, {"runs": [{"results": []}]}

        tk._codeql_analyzer = SimpleNamespace(run_query=fake_run_query)

        result = tk._run_codeql_query(query="import python\nselect 1", query_name="fallback_query")

        assert result.success is True
        assert captured["database_path"].endswith(actual_db_name)
        assert (output_dir / "codeql-queries" / "python" / "fallback_query.ql").exists()

    def test_run_codeql_query_finds_relocated_profile_generated_database(self, tmp_path):
        tk, repo_path, output_dir, _ = _make_toolkit(tmp_path)
        original_repo_path = (tmp_path / "old-root" / repo_path.name).resolve()
        tk._software_profile = SimpleNamespace(
            version="deadbeef1234",
            metadata={"profile_repo_path": str(original_repo_path)},
        )
        tk._codeql_database_names = {"python": "fake_repo-deadbeef-python"}
        old_repo_path_hash = stable_data_hash(str(original_repo_path))[:12]
        actual_db_name = f"{repo_path.name}-{old_repo_path_hash}-deadbeef-python"
        _write_codeql_database_metadata(
            tk._codeql_db_base_path / actual_db_name,
            source_repo_path=original_repo_path,
            sha="deadbeef1234",
        )

        captured = {}

        def fake_run_query(database_path, query, output_format="sarif-latest"):
            captured["database_path"] = database_path
            captured["query"] = query
            captured["output_format"] = output_format
            return True, {"runs": [{"results": []}]}

        tk._codeql_analyzer = SimpleNamespace(run_query=fake_run_query)

        result = tk._run_codeql_query(query="import python\nselect 1", query_name="relocated_query")

        assert result.success is True
        assert captured["database_path"].endswith(actual_db_name)
        assert (output_dir / "codeql-queries" / "python" / "relocated_query.ql").exists()

    def test_run_codeql_query_ignores_current_path_hash_database_when_profile_was_generated_elsewhere(
        self,
        tmp_path,
    ):
        tk, repo_path, output_dir, _ = _make_toolkit(tmp_path)
        original_repo_path = (tmp_path / "old-root" / repo_path.name).resolve()
        tk._software_profile = SimpleNamespace(
            version="deadbeef1234",
            metadata={"profile_repo_path": str(original_repo_path)},
        )
        tk._codeql_database_names = {"python": "fake_repo-deadbeef-python"}

        expected_db_name = (
            f"{repo_path.name}-{stable_data_hash(str(original_repo_path))[:12]}-deadbeef-python"
        )
        current_hash_db_name = (
            f"{repo_path.name}-{stable_data_hash(str(repo_path.resolve()))[:12]}-deadbeef-python"
        )
        _write_codeql_database_metadata(
            tk._codeql_db_base_path / expected_db_name,
            source_repo_path=original_repo_path,
            sha="deadbeef1234",
        )
        _write_codeql_database_metadata(
            tk._codeql_db_base_path / current_hash_db_name,
            source_repo_path=repo_path.resolve(),
            sha="deadbeef1234",
        )

        captured = {}

        def fake_run_query(database_path, query, output_format="sarif-latest"):
            captured["database_path"] = database_path
            captured["query"] = query
            captured["output_format"] = output_format
            return True, {"runs": [{"results": []}]}

        tk._codeql_analyzer = SimpleNamespace(run_query=fake_run_query)

        result = tk._run_codeql_query(
            query="import python\nselect 1",
            query_name="ignore_current_hash_query",
        )

        assert result.success is True
        assert captured["database_path"].endswith(expected_db_name)
        assert not captured["database_path"].endswith(current_hash_db_name)
        assert (output_dir / "codeql-queries" / "python" / "ignore_current_hash_query.ql").exists()

    def test_run_codeql_query_prefers_matching_profile_source_database_over_newer_collision(self, tmp_path):
        tk, repo_path, output_dir, _ = _make_toolkit(tmp_path)
        expected_source_repo_path = (tmp_path / "old-root-a" / repo_path.name).resolve()
        colliding_source_repo_path = (tmp_path / "old-root-b" / repo_path.name).resolve()
        tk._software_profile = SimpleNamespace(
            version="deadbeef1234",
            metadata={"profile_repo_path": str(expected_source_repo_path)},
        )
        tk._codeql_database_names = {"python": "fake_repo-deadbeef-python"}

        expected_repo_path_hash = stable_data_hash(str(expected_source_repo_path))[:12]
        colliding_repo_path_hash = stable_data_hash(str(colliding_source_repo_path))[:12]
        expected_db_name = f"{repo_path.name}-{expected_repo_path_hash}-deadbeef-python"
        colliding_db_name = f"{repo_path.name}-{colliding_repo_path_hash}-deadbeef-python"
        expected_db_dir = tk._codeql_db_base_path / expected_db_name
        colliding_db_dir = tk._codeql_db_base_path / colliding_db_name
        _write_codeql_database_metadata(
            expected_db_dir,
            source_repo_path=expected_source_repo_path,
            sha="deadbeef1234",
        )
        _write_codeql_database_metadata(
            colliding_db_dir,
            source_repo_path=colliding_source_repo_path,
            sha="deadbeef1234",
        )
        os.utime(expected_db_dir, ns=(1, 1))
        os.utime(colliding_db_dir, ns=(2, 2))

        captured = {}

        def fake_run_query(database_path, query, output_format="sarif-latest"):
            captured["database_path"] = database_path
            captured["query"] = query
            captured["output_format"] = output_format
            return True, {"runs": [{"results": []}]}

        tk._codeql_analyzer = SimpleNamespace(run_query=fake_run_query)

        result = tk._run_codeql_query(query="import python\nselect 1", query_name="multi_relocation_query")

        assert result.success is True
        assert captured["database_path"].endswith(expected_db_name)
        assert not captured["database_path"].endswith(colliding_db_name)
        assert (output_dir / "codeql-queries" / "python" / "multi_relocation_query.ql").exists()

    def test_run_codeql_query_rejects_exact_profile_generated_database_with_mismatched_metadata(
        self,
        tmp_path,
    ):
        tk, repo_path, _, _ = _make_toolkit(tmp_path)
        original_repo_path = (tmp_path / "old-root" / repo_path.name).resolve()
        tk._software_profile = SimpleNamespace(
            version="deadbeef1234",
            metadata={"profile_repo_path": str(original_repo_path)},
        )
        tk._codeql_database_names = {"python": "fake_repo-deadbeef-python"}

        exact_db_name = (
            f"{repo_path.name}-{stable_data_hash(str(original_repo_path))[:12]}-deadbeef-python"
        )
        _write_codeql_database_metadata(
            tk._codeql_db_base_path / exact_db_name,
            source_repo_path=repo_path.resolve(),
            sha="deadbeef1234",
        )
        tk._codeql_analyzer = SimpleNamespace(
            run_query=lambda **kwargs: pytest.fail("mismatched exact DB should not run CodeQL"),
        )

        result = tk._run_codeql_query(
            query="import python\nselect 1",
            query_name="mismatched_exact_query",
        )

        assert result.success is False
        assert "CodeQL database not found" in (result.error or "")

    def test_run_codeql_query_rejects_ambiguous_relocated_databases_without_profile_repo_path(
        self,
        tmp_path,
    ):
        tk, repo_path, _, _ = _make_toolkit(tmp_path)
        tk._software_profile = SimpleNamespace(version="deadbeef1234")
        tk._codeql_database_names = {"python": "fake_repo-deadbeef-python"}

        source_repo_path_a = (tmp_path / "old-root-a" / repo_path.name).resolve()
        source_repo_path_b = (tmp_path / "old-root-b" / repo_path.name).resolve()
        db_name_a = (
            f"{repo_path.name}-{stable_data_hash(str(source_repo_path_a))[:12]}-deadbeef-python"
        )
        db_name_b = (
            f"{repo_path.name}-{stable_data_hash(str(source_repo_path_b))[:12]}-deadbeef-python"
        )
        _write_codeql_database_metadata(
            tk._codeql_db_base_path / db_name_a,
            source_repo_path=source_repo_path_a,
            sha="deadbeef1234",
        )
        _write_codeql_database_metadata(
            tk._codeql_db_base_path / db_name_b,
            source_repo_path=source_repo_path_b,
            sha="deadbeef1234",
        )
        tk._codeql_analyzer = SimpleNamespace(
            run_query=lambda **kwargs: pytest.fail("ambiguous fallback should not run CodeQL"),
        )

        result = tk._run_codeql_query(
            query="import python\nselect 1",
            query_name="ambiguous_relocation_query",
        )

        assert result.success is False
        assert "CodeQL database not found" in (result.error or "")

    def test_run_codeql_query_prefers_profile_generated_database_over_legacy_name(self, tmp_path):
        tk, repo_path, output_dir, _ = _make_toolkit(tmp_path)
        tk._software_profile = SimpleNamespace(version="deadbeef1234")
        legacy_db_name = "fake_repo-deadbeef-python"
        hashed_repo_path = stable_data_hash(str(repo_path.resolve()))[:12]
        hashed_db_name = f"{repo_path.name}-{hashed_repo_path}-deadbeef-python"
        tk._codeql_database_names = {"python": legacy_db_name}
        (tk._codeql_db_base_path / legacy_db_name).mkdir(parents=True)
        _write_codeql_database_metadata(
            tk._codeql_db_base_path / hashed_db_name,
            source_repo_path=repo_path.resolve(),
            sha="deadbeef1234",
        )

        captured = {}

        def fake_run_query(database_path, query, output_format="sarif-latest"):
            captured["database_path"] = database_path
            captured["query"] = query
            captured["output_format"] = output_format
            return True, {"runs": [{"results": []}]}

        tk._codeql_analyzer = SimpleNamespace(run_query=fake_run_query)

        result = tk._run_codeql_query(query="import python\nselect 1", query_name="prefer_hashed_query")

        assert result.success is True
        assert captured["database_path"].endswith(hashed_db_name)
        assert not captured["database_path"].endswith(legacy_db_name)
        assert (output_dir / "codeql-queries" / "python" / "prefer_hashed_query.ql").exists()


class TestSetMemoryManagerLate:
    """query dir should work when memory_manager is set after construction."""

    def test_setup_query_dir_after_set_memory_manager(self, tmp_path):
        # Create without memory
        tk, _, _, _ = _make_toolkit(tmp_path, with_memory=False)
        assert tk._setup_query_dir() is False

        # Now set memory manager
        output_dir = tmp_path / "late_output"
        output_dir.mkdir()
        tk.set_memory_manager(FakeMemoryManager(output_dir))

        assert tk._setup_query_dir() is True
        expected = output_dir / "codeql-queries" / "python"
        assert expected.is_dir()
        assert (expected / "qlpack.yml").exists()


class TestMultiLanguageBehavior:
    def test_iter_source_files_uses_all_configured_languages(self, tmp_path):
        tk, repo_path, _, _ = _make_toolkit(
            tmp_path,
            language="python",
            languages=["python", "javascript"],
        )
        files = sorted(
            str(path.relative_to(repo_path))
            for path in tk._iter_source_files(repo_path, recursive=False)
        )
        assert files == ["main.js", "main.py"]

    def test_run_codeql_query_routes_to_matching_language_database(self, tmp_path):
        tk, _, output_dir, _ = _make_toolkit(
            tmp_path,
            language="python",
            languages=["python", "javascript"],
        )

        db_python = "test-db-python"
        db_js = "test-db-javascript"
        (tk._codeql_db_base_path / db_python).mkdir(parents=True)
        (tk._codeql_db_base_path / db_js).mkdir(parents=True)
        tk._codeql_database_names = {
            "python": db_python,
            "javascript": db_js,
        }

        captured = {}

        def fake_run_query(database_path, query, output_format="sarif-latest"):
            captured["database_path"] = database_path
            captured["query"] = query
            captured["output_format"] = output_format
            return True, {"runs": [{"results": []}]}

        tk._codeql_analyzer = SimpleNamespace(run_query=fake_run_query)

        result = tk._run_codeql_query(query="import javascript\nselect 1", query_name="js_query")

        assert result.success is True
        normalized_query_path = captured["query"].replace("\\", "/")
        assert captured["database_path"].endswith(db_js)
        assert "/codeql-queries/javascript/js_query.ql" in normalized_query_path
        assert (output_dir / "codeql-queries" / "javascript" / "js_query.ql").exists()

    def test_switch_memory_manager_rebuilds_query_dir_under_new_output(self, tmp_path):
        tk, _, first_output_dir, _ = _make_toolkit(tmp_path, with_memory=True)
        assert tk._setup_query_dir() is True

        first_query_dir = first_output_dir / "codeql-queries" / "python"
        assert tk._codeql_query_dirs.get("python") == first_query_dir
        assert "python" in tk._codeql_query_dirs_ready

        second_output_dir = tmp_path / "second_output"
        second_output_dir.mkdir()
        tk.set_memory_manager(FakeMemoryManager(second_output_dir))

        assert tk._codeql_query_dirs == {}
        assert tk._codeql_query_dirs_ready == set()

        assert tk._setup_query_dir() is True
        second_query_dir = second_output_dir / "codeql-queries" / "python"
        assert tk._codeql_query_dirs.get("python") == second_query_dir
        assert second_query_dir.is_dir()
