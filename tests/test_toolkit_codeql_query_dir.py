"""Tests for the CodeQL query directory setup changes in AgenticToolkit.

Verifies that:
- _init_codeql sets template dir from _path_config and defers actual dir creation.
- _setup_query_dir creates the dir under output_dir and copies yml files.
- _setup_query_dir is idempotent (second call is a no-op).
- _setup_query_dir returns False when memory_manager is missing.
- _ensure_query_pack delegates to _setup_query_dir.
- _run_codeql_query writes the .ql file under output_dir/codeql-queries/<lang>/.
"""

import json
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from profiler.fingerprint import stable_data_hash
from scanner.agent.memory import AgentMemoryManager

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
        self._add_findings_calls = []
        self._atomic_calls = []
        self._first_touches = []

    def add_finding(self, finding):
        self._findings.append(finding)

    def add_findings(self, findings):
        self._add_findings_calls.append(len(findings))
        self._findings.extend(findings)
        return len(findings)

    def add_findings_with_first_touches(self, findings, file_paths):
        self._add_findings_calls.append(len(findings))
        self._atomic_calls.append((list(findings), list(file_paths)))
        self._findings.extend(findings)
        for file_path in file_paths:
            if file_path not in self._first_touches:
                self._first_touches.append(file_path)
        return len(findings)

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

    def test_record_codeql_findings_filters_low_signal_xml_parsing_from_memory(self, tmp_path):
        tk, _, _, _ = _make_toolkit(tmp_path)
        tk._record_codeql_findings_in_memory(
            "xml_parsing_functions",
            [
                {
                    "file": "a.py",
                    "rule_id": "py/xml-parsing",
                    "message": "XML parsing function: parse",
                    "snippet": "",
                    "start_line": 12,
                },
                {
                    "file": "b.py",
                    "rule_id": "python/xml-parsing",
                    "message": "XML parsing call: parse",
                    "snippet": "",
                    "start_line": 21,
                },
                {
                    "file": "c.py",
                    "rule_id": "xxe",
                    "message": "Potential XXE in XML parser",
                    "snippet": "",
                    "start_line": 33,
                },
                {
                    "file": "d.py",
                    "rule_id": "python/xxe-xml-parsing",
                    "message": "Potential XXE vulnerability: XML parsing call",
                    "snippet": "",
                    "start_line": 44,
                },
            ],
        )

        assert tk._memory_manager._add_findings_calls == [2]
        assert tk._memory_manager._first_touches == ["a.py", "b.py", "c.py", "d.py"]
        assert [
            finding["vulnerability_type"]
            for finding in tk._memory_manager._findings
        ] == ["xxe", "python/xxe-xml-parsing"]
        assert tk._memory_manager._issues == [
            "CodeQL query 'xml_parsing_functions' found 4 potential issues (2 filtered, 2 eligible, 2 new)"
        ]

    def test_run_codeql_query_preserves_raw_results_when_memory_filters(self, tmp_path):
        tk, _, output_dir, _ = _make_toolkit(tmp_path)
        db_name = "test-db-python"
        tk._codeql_database_names = {"python": db_name}
        db_dir = tk._codeql_db_base_path / db_name
        db_dir.mkdir(parents=True)
        tk._codeql_analyzer.run_query = MagicMock(
            return_value=(
                True,
                {
                    "runs": [
                        {
                            "results": [
                                {
                                    "ruleId": "py/xml-parsing",
                                    "message": {"text": "XML parsing function: parse"},
                                    "locations": [
                                        {
                                            "physicalLocation": {
                                                "artifactLocation": {"uri": "a.py"},
                                                "region": {"startLine": 12},
                                            }
                                        }
                                    ],
                                },
                                {
                                    "ruleId": "xxe",
                                    "message": {"text": "Potential XXE in XML parser"},
                                    "locations": [
                                        {
                                            "physicalLocation": {
                                                "artifactLocation": {"uri": "b.py"},
                                                "region": {"startLine": 24},
                                            }
                                        }
                                    ],
                                },
                            ]
                        }
                    ]
                },
            )
        )

        result = tk._run_codeql_query(query="import python\nselect 1", query_name="mixed_query")

        assert result.success is True
        assert [
            finding["vulnerability_type"]
            for finding in tk._memory_manager._findings
        ] == ["xxe"]
        assert tk._memory_manager._first_touches == ["a.py", "b.py"]
        stem = tk._codeql_artifact_stem("mixed_query")
        findings_file = output_dir / "codeql-results" / f"{stem}_findings.json"
        saved = json.loads(findings_file.read_text())
        assert saved["total_findings"] == 2
        assert [finding["rule_id"] for finding in saved["findings"]] == [
            "py/xml-parsing",
            "xxe",
        ]

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
        stem = tk._codeql_artifact_stem("test_query")
        ql_file = output_dir / "codeql-queries" / "python" / f"{stem}.ql"
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
        stem = tk._codeql_artifact_stem("my query/special chars!")
        assert stem.startswith("my_query_special_chars-")
        ql_file = output_dir / "codeql-queries" / "python" / f"{stem}.ql"
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
        stem = tk._codeql_artifact_stem("fallback_query")
        assert (output_dir / "codeql-queries" / "python" / f"{stem}.ql").exists()

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
        stem = tk._codeql_artifact_stem("relocated_query")
        assert (output_dir / "codeql-queries" / "python" / f"{stem}.ql").exists()

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
        stem = tk._codeql_artifact_stem("ignore_current_hash_query")
        assert (output_dir / "codeql-queries" / "python" / f"{stem}.ql").exists()

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
        stem = tk._codeql_artifact_stem("multi_relocation_query")
        assert (output_dir / "codeql-queries" / "python" / f"{stem}.ql").exists()

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
        stem = tk._codeql_artifact_stem("prefer_hashed_query")
        assert (output_dir / "codeql-queries" / "python" / f"{stem}.ql").exists()


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
        stem = tk._codeql_artifact_stem("js_query")
        assert f"/codeql-queries/javascript/{stem}.ql" in normalized_query_path
        assert (output_dir / "codeql-queries" / "javascript" / f"{stem}.ql").exists()

    def test_explicit_query_language_never_falls_back_to_another_database(
        self,
        tmp_path,
    ):
        tk, _, _, _ = _make_toolkit(
            tmp_path,
            language="python",
            languages=["python", "javascript"],
        )
        db_python = "test-db-python"
        (tk._codeql_db_base_path / db_python).mkdir(parents=True)
        tk._codeql_database_names = {"python": db_python}
        tk._codeql_analyzer.run_query = MagicMock()

        result = tk._run_codeql_query(
            query="import javascript\nselect 1",
            query_name="missing_js_database",
        )

        assert result.success is False
        assert "language 'javascript'" in result.error
        tk._codeql_analyzer.run_query.assert_not_called()

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


def test_frozen_global_schedule_groups_codeql_output_once_per_file(tmp_path):
    tk, repo_path, output_dir, _ = _make_toolkit(tmp_path)
    for relative_path in ("a.py", "b.py", "unscheduled.py"):
        (repo_path / relative_path).write_text("pass\n", encoding="utf-8")
    tk.set_file_enumeration_order(["b.py", "a.py"])
    tk.set_active_file_window(["b.py", "a.py"], cursor=0)

    findings = [
        {
            "file": "unscheduled.py",
            "start_line": 1,
            "rule_id": "outside",
            "message": "outside",
        },
        {
            "file": "a.py",
            "start_line": 2,
            "rule_id": "a-rule",
            "message": "a-message",
        },
        *[
            {
                "file": "b.py",
                "start_line": index + 1,
                "rule_id": f"b-rule-{index}",
                "message": f"b-message-{index}",
            }
            for index in range(7)
        ],
    ]

    summary = tk._format_codeql_summary("demo", findings)
    assert "Found **8** potential issue(s)" in summary
    assert summary.index("### b.py") < summary.index("### a.py")
    assert summary.count("### b.py") == 1
    assert summary.count("### a.py") == 1
    assert "unscheduled.py" not in summary
    assert all(f"b-message-{index}" in summary for index in range(7))

    results_dir = output_dir / "codeql-results"
    results_dir.mkdir(parents=True, exist_ok=True)
    stem = tk._codeql_artifact_stem("demo")
    (results_dir / f"{stem}_findings.json").write_text(
        json.dumps({"findings": findings}),
        encoding="utf-8",
    )
    result = tk._read_codeql_results("demo")
    assert result.success is True
    payload = json.loads(result.content)
    assert [row["file"] for row in payload["files"]] == ["b.py", "a.py"]
    assert [row["finding_count"] for row in payload["files"]] == [7, 1]
    assert "unscheduled.py" not in result.content
    assert result.content.count('"b.py"') == 1
    assert result.content.count('"a.py"') == 1


def test_colliding_query_slugs_keep_distinct_codeql_artifacts(tmp_path):
    tk, _, output_dir, _ = _make_toolkit(tmp_path)
    db_name = "test-db-python"
    tk._codeql_database_names = {"python": db_name}
    (tk._codeql_db_base_path / db_name).mkdir(parents=True)

    first = tk._run_codeql_query("import python\nselect 1", "a/b")
    second = tk._run_codeql_query("import python\nselect 2", "a?b")

    assert first.success is True
    assert second.success is True
    first_stem = tk._codeql_artifact_stem("a/b")
    second_stem = tk._codeql_artifact_stem("a?b")
    assert first_stem != second_stem
    results_dir = output_dir / "codeql-results"
    first_payload = json.loads(
        (results_dir / f"{first_stem}_findings.json").read_text(encoding="utf-8")
    )
    second_payload = json.loads(
        (results_dir / f"{second_stem}_findings.json").read_text(encoding="utf-8")
    )
    assert first_payload["query_name"] == "a/b"
    assert second_payload["query_name"] == "a?b"
    assert tk._read_codeql_results("a/b").success is True
    assert tk._read_codeql_results("a?b").success is True



def test_codeql_actual_manager_save_failure_rolls_back_findings_and_touches(
    tmp_path
):
    memory_output = tmp_path / "memory"
    manager = AgentMemoryManager(output_dir=memory_output)
    manager.initialize(
        target_repo="repo",
        target_commit="a" * 40,
        cve_id="CVE-2026-7000",
        module_priorities={"api": 1},
        file_to_module={"a.py": "api", "b.py": "api"},
    )
    before_disk = manager.memory_file.read_bytes()
    toolkit_root = tmp_path / "toolkit"
    toolkit_root.mkdir()
    toolkit, _, _, _ = _make_toolkit(toolkit_root)
    toolkit._memory_manager = manager

    def fail_save():
        raise RuntimeError("injected CodeQL save failure")

    manager.save = fail_save
    with pytest.raises(RuntimeError, match="injected CodeQL save failure"):
        toolkit._record_codeql_findings_in_memory(
            "atomic-query",
            [
                {
                    "file": "a.py",
                    "rule_id": "py/xml-parsing",
                    "message": "low signal but still a visible touch",
                    "snippet": "",
                    "start_line": 1,
                },
                {
                    "file": "b.py",
                    "rule_id": "python/command-injection",
                    "message": "eligible finding",
                    "snippet": "sink(user_input)",
                    "start_line": 2,
                },
            ],
        )

    assert manager.memory.findings == []
    assert manager.memory.coverage_first_touches == []
    assert manager.memory_file.read_bytes() == before_disk
    reloaded = AgentMemoryManager(output_dir=memory_output)
    assert reloaded.initialize(
        target_repo="repo",
        target_commit="a" * 40,
        cve_id="CVE-2026-7000",
        module_priorities={"api": 1},
        file_to_module={"a.py": "api", "b.py": "api"},
    ) is True
    assert reloaded.memory.findings == []
    assert reloaded.memory.coverage_first_touches == []
