import json
from types import SimpleNamespace

import pytest

import cli.batch_scanner_cache as batch_scanner_cache
from cli.batch_scanner import (
    _cached_vulnerability_profile_matches_current_inputs,
    _ensure_software_profile,
    _ensure_vulnerability_profile,
)
from cli.profile_generation import build_vulnerability_entry
from profiler import SoftwareProfiler
from profiler.fingerprint import build_vulnerability_profile_fingerprint
from profiler.vulnerability.analyzer import EXTRACTION_TEMPERATURE


def _build_cached_software_profile_fingerprint(
    repo_profiles_dir,
    *,
    repo_path=None,
    repo_version=None,
):
    profiler = SoftwareProfiler(output_dir=str(repo_profiles_dir))
    profiler._current_fingerprint_repo_path = repo_path  # pylint: disable=protected-access
    profiler._current_fingerprint_repo_version = repo_version  # pylint: disable=protected-access
    return profiler._build_profile_fingerprint()  # pylint: disable=protected-access


def _materialized_call_chain(file_path: str = "src/app.py", function_name: str = "entry"):
    return [
        {
            "file_path": file_path,
            "function_name": function_name,
            "file_content": "def entry():\n    return 'cached'\n",
            "code_snippet": "1: def entry():\n2:     return 'cached'",
        }
    ]


def test_loads_cached_software_profile_from_disk_when_repo_is_missing(monkeypatch, tmp_path):
    repo_name = "demo"
    commit_hash = "abc123"
    repo_profiles_dir = tmp_path / "profiles"
    profile_dir = repo_profiles_dir / repo_name / commit_hash
    profile_dir.mkdir(parents=True)
    source_repo_dir = tmp_path / "source-state"
    source_repo_dir.mkdir()
    (source_repo_dir / "app.py").write_text("print('cached')\n", encoding="utf-8")
    fingerprint = _build_cached_software_profile_fingerprint(
        repo_profiles_dir,
        repo_path=source_repo_dir,
        repo_version=commit_hash,
    )
    (profile_dir / "software_profile.json").write_text(
        json.dumps(
            {
                "basic_info": {"name": repo_name, "version": commit_hash, "description": "cached"},
                "repo_info": {},
                "modules": [],
                "metadata": {"profile_fingerprint": fingerprint},
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        "cli.batch_scanner.run_software_profile_generation",
        lambda **kwargs: pytest.fail("cached-only mode should not regenerate software profiles"),
    )

    cache = {}
    profile = _ensure_software_profile(
        repo_name=repo_name,
        commit_hash=commit_hash,
        repos_root=tmp_path / "missing-repos",
        repo_profiles_dir=repo_profiles_dir,
        llm_client=None,
        force_regenerate=False,
        cache=cache,
        regenerated_keys=set(),
    )

    assert getattr(profile, "description", None) == "cached"
    assert getattr(cache[(repo_name, commit_hash)], "description", None) == "cached"


def test_missing_repo_cached_software_profile_returns_none_when_fingerprint_is_stale(
    monkeypatch,
    tmp_path,
):
    repo_name = "demo"
    commit_hash = "abc123"
    repo_profiles_dir = tmp_path / "profiles"
    profile_dir = repo_profiles_dir / repo_name / commit_hash
    profile_dir.mkdir(parents=True)
    (profile_dir / "software_profile.json").write_text(
        json.dumps(
            {
                "basic_info": {"name": repo_name, "version": commit_hash, "description": "stale"},
                "repo_info": {},
                "modules": [],
                "metadata": {"profile_fingerprint": {"hash": "stale", "inputs_hash": "stale"}},
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        "cli.batch_scanner.run_software_profile_generation",
        lambda **kwargs: pytest.fail("missing repo should not attempt regeneration"),
    )

    profile = _ensure_software_profile(
        repo_name=repo_name,
        commit_hash=commit_hash,
        repos_root=tmp_path / "missing-repos",
        repo_profiles_dir=repo_profiles_dir,
        llm_client=None,
        force_regenerate=False,
        cache={},
        regenerated_keys=set(),
    )

    assert profile is None


def test_loads_cached_vulnerability_profile_from_disk_when_repo_is_missing(monkeypatch, tmp_path):
    repo_name = "demo"
    commit_hash = "abc123"
    cve_id = "CVE-2026-0001"
    vuln_json_path = tmp_path / "vuln.json"
    vuln_json_path.write_text(
        json.dumps(
            [
                {
                    "repo_name": repo_name,
                    "commit": commit_hash,
                    "call_chain": ["src/app.py#entry"],
                    "payload": None,
                    "cve_id": cve_id,
                }
            ]
        ),
        encoding="utf-8",
    )
    vuln_profiles_dir = tmp_path / "profiles"
    profile_dir = vuln_profiles_dir / repo_name / cve_id
    profile_dir.mkdir(parents=True)
    source_profile = SimpleNamespace(metadata={"profile_fingerprint": {"hash": "source-hash"}})
    materialized_call_chain = _materialized_call_chain()
    cached_fingerprint = build_vulnerability_profile_fingerprint(
        repo_profile=source_profile,
        vuln_entry=build_vulnerability_entry(
            {
                "repo_name": repo_name,
                "commit": commit_hash,
                "call_chain": materialized_call_chain,
                "payload": None,
                "cve_id": cve_id,
            }
        ),
        llm_client=None,
        extraction_temperature=EXTRACTION_TEMPERATURE,
    )
    (profile_dir / "vulnerability_profile.json").write_text(
        json.dumps(
            {
                "repo_name": repo_name,
                "affected_version": commit_hash,
                "cve_id": cve_id,
                "call_chain": materialized_call_chain,
                "metadata": {"profile_fingerprint": cached_fingerprint},
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        "cli.batch_scanner._ensure_software_profile",
        lambda **kwargs: source_profile,
    )
    monkeypatch.setattr(
        "cli.batch_scanner.read_vuln_data",
        lambda *args, **kwargs: pytest.fail("cached-only mode should not read source repositories"),
    )
    monkeypatch.setattr(
        "cli.batch_scanner.run_vulnerability_profile_generation",
        lambda **kwargs: pytest.fail("cached-only mode should not regenerate vulnerability profiles"),
    )

    cache = {}
    profile = _ensure_vulnerability_profile(
        vuln_index=0,
        repo_name=repo_name,
        commit_hash=commit_hash,
        cve_id=cve_id,
        repos_root=tmp_path / "missing-repos",
        repo_profiles_dir=tmp_path / "software-profiles",
        vuln_profiles_dir=vuln_profiles_dir,
        llm_client=None,
        force_regenerate=False,
        software_cache={},
        regenerated_software_keys=set(),
        cache=cache,
        verbose=False,
        vuln_json_path=str(vuln_json_path),
    )

    assert getattr(profile, "cve_id", None) == cve_id
    assert getattr(cache[(repo_name, cve_id)], "cve_id", None) == cve_id


def test_missing_repo_cached_vulnerability_profile_returns_none_when_source_profile_changes(
    monkeypatch,
    tmp_path,
):
    repo_name = "demo"
    commit_hash = "abc123"
    cve_id = "CVE-2026-0001"
    vuln_json_path = tmp_path / "vuln.json"
    vuln_json_path.write_text(
        json.dumps(
            [
                {
                    "repo_name": repo_name,
                    "commit": commit_hash,
                    "call_chain": ["src/app.py#entry"],
                    "payload": None,
                    "cve_id": cve_id,
                }
            ]
        ),
        encoding="utf-8",
    )
    vuln_profiles_dir = tmp_path / "profiles"
    profile_dir = vuln_profiles_dir / repo_name / cve_id
    profile_dir.mkdir(parents=True)
    materialized_call_chain = _materialized_call_chain()
    (profile_dir / "vulnerability_profile.json").write_text(
        json.dumps(
            {
                "repo_name": repo_name,
                "affected_version": commit_hash,
                "cve_id": cve_id,
                "call_chain": materialized_call_chain,
                "metadata": {"profile_fingerprint": {"hash": "cached", "source_profile_hash": "stale-source"}},
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        "cli.batch_scanner._ensure_software_profile",
        lambda **kwargs: SimpleNamespace(metadata={"profile_fingerprint": {"hash": "current-source"}}),
    )
    monkeypatch.setattr(
        "cli.batch_scanner.run_vulnerability_profile_generation",
        lambda **kwargs: pytest.fail("missing repo stale cache should not regenerate vulnerability profiles"),
    )

    profile = _ensure_vulnerability_profile(
        vuln_index=0,
        repo_name=repo_name,
        commit_hash=commit_hash,
        cve_id=cve_id,
        repos_root=tmp_path / "missing-repos",
        repo_profiles_dir=tmp_path / "software-profiles",
        vuln_profiles_dir=vuln_profiles_dir,
        llm_client=None,
        force_regenerate=False,
        software_cache={},
        regenerated_software_keys=set(),
        cache={},
        verbose=False,
        vuln_json_path=str(vuln_json_path),
    )

    assert profile is None


def test_missing_repo_cached_vulnerability_profile_returns_none_when_llm_fingerprint_changes(
    monkeypatch,
    tmp_path,
):
    repo_name = "demo"
    commit_hash = "abc123"
    cve_id = "CVE-2026-0001"
    vuln_json_path = tmp_path / "vuln.json"
    vuln_json_path.write_text(
        json.dumps(
            [
                {
                    "repo_name": repo_name,
                    "commit": commit_hash,
                    "call_chain": ["src/app.py#entry"],
                    "payload": None,
                    "cve_id": cve_id,
                }
            ]
        ),
        encoding="utf-8",
    )
    vuln_profiles_dir = tmp_path / "profiles"
    profile_dir = vuln_profiles_dir / repo_name / cve_id
    profile_dir.mkdir(parents=True)
    source_profile = SimpleNamespace(metadata={"profile_fingerprint": {"hash": "source-hash"}})
    materialized_call_chain = _materialized_call_chain()
    cached_fingerprint = build_vulnerability_profile_fingerprint(
        repo_profile=source_profile,
        vuln_entry=build_vulnerability_entry(
            {
                "repo_name": repo_name,
                "commit": commit_hash,
                "call_chain": materialized_call_chain,
                "payload": None,
                "cve_id": cve_id,
            }
        ),
        llm_client=None,
        extraction_temperature=EXTRACTION_TEMPERATURE,
    )
    (profile_dir / "vulnerability_profile.json").write_text(
        json.dumps(
            {
                "repo_name": repo_name,
                "affected_version": commit_hash,
                "cve_id": cve_id,
                "call_chain": materialized_call_chain,
                "metadata": {"profile_fingerprint": cached_fingerprint},
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        "cli.batch_scanner._ensure_software_profile",
        lambda **kwargs: source_profile,
    )
    monkeypatch.setattr(
        "cli.batch_scanner.run_vulnerability_profile_generation",
        lambda **kwargs: pytest.fail("missing repo stale cache should not regenerate vulnerability profiles"),
    )

    llm_client = SimpleNamespace(
        config=SimpleNamespace(
            provider="deepseek",
            model="deepseek-chat",
            temperature=0.1,
            top_p=0.9,
            max_tokens=2048,
            enable_thinking=True,
        )
    )
    profile = _ensure_vulnerability_profile(
        vuln_index=0,
        repo_name=repo_name,
        commit_hash=commit_hash,
        cve_id=cve_id,
        repos_root=tmp_path / "missing-repos",
        repo_profiles_dir=tmp_path / "software-profiles",
        vuln_profiles_dir=vuln_profiles_dir,
        llm_client=llm_client,
        force_regenerate=False,
        software_cache={},
        regenerated_software_keys=set(),
        cache={},
        verbose=False,
        vuln_json_path=str(vuln_json_path),
    )

    assert profile is None


def test_loads_cached_vulnerability_profile_from_disk_when_repo_is_dirty(monkeypatch, tmp_path):
    repo_name = "demo"
    commit_hash = "abc123"
    cve_id = "CVE-2026-0001"
    repos_root = tmp_path / "repos"
    (repos_root / repo_name).mkdir(parents=True)

    vuln_profiles_dir = tmp_path / "profiles"
    profile_dir = vuln_profiles_dir / repo_name / cve_id
    profile_dir.mkdir(parents=True)
    (profile_dir / "vulnerability_profile.json").write_text(
        json.dumps(
            {
                "repo_name": repo_name,
                "affected_version": commit_hash,
                "cve_id": cve_id,
                "call_chain": [{"file_path": "src/app.py", "function_name": "entry"}],
                "metadata": {"profile_fingerprint": {"hash": "cached"}},
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr("cli.batch_scanner.has_uncommitted_changes", lambda repo_path: True)
    monkeypatch.setattr(
        "cli.batch_scanner._ensure_software_profile",
        lambda **kwargs: {"metadata": {"profile_fingerprint": {"hash": "source"}}},
    )
    monkeypatch.setattr(
        "cli.batch_scanner._cached_vulnerability_profile_matches_current_inputs",
        lambda **kwargs: True,
    )
    monkeypatch.setattr(
        "cli.batch_scanner.read_vuln_data",
        lambda *args, **kwargs: pytest.fail("dirty resume should not re-read source repositories"),
    )
    monkeypatch.setattr(
        "cli.batch_scanner.run_vulnerability_profile_generation",
        lambda **kwargs: pytest.fail("dirty resume should not regenerate vulnerability profiles"),
    )

    cache = {}
    profile = _ensure_vulnerability_profile(
        vuln_index=0,
        repo_name=repo_name,
        commit_hash=commit_hash,
        cve_id=cve_id,
        repos_root=repos_root,
        repo_profiles_dir=tmp_path / "software-profiles",
        vuln_profiles_dir=vuln_profiles_dir,
        llm_client=None,
        force_regenerate=False,
        software_cache={},
        regenerated_software_keys=set(),
        cache=cache,
        verbose=False,
        vuln_json_path=None,
    )

    assert getattr(profile, "cve_id", None) == cve_id
    assert getattr(cache[(repo_name, cve_id)], "cve_id", None) == cve_id


def test_loads_cached_software_profile_from_disk_when_repo_is_dirty(monkeypatch, tmp_path):
    repo_name = "demo"
    commit_hash = "abc123"
    repos_root = tmp_path / "repos"
    repo_dir = repos_root / repo_name
    repo_dir.mkdir(parents=True)
    (repo_dir / "app.py").write_text("print('cached')\n", encoding="utf-8")

    repo_profiles_dir = tmp_path / "profiles"
    profile_dir = repo_profiles_dir / repo_name / commit_hash
    profile_dir.mkdir(parents=True)
    fingerprint = _build_cached_software_profile_fingerprint(
        repo_profiles_dir,
        repo_path=repo_dir,
        repo_version=commit_hash,
    )
    (profile_dir / "software_profile.json").write_text(
        json.dumps(
            {
                "basic_info": {"name": repo_name, "version": commit_hash, "description": "cached"},
                "repo_info": {},
                "modules": [],
                "metadata": {"profile_fingerprint": fingerprint},
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr("cli.batch_scanner.has_uncommitted_changes", lambda repo_path: True)
    monkeypatch.setattr("cli.batch_scanner.get_git_commit", lambda repo_path: commit_hash)
    monkeypatch.setattr(
        "cli.batch_scanner.run_software_profile_generation",
        lambda **kwargs: pytest.fail("dirty resume should not regenerate software profiles"),
    )

    cache = {}
    profile = _ensure_software_profile(
        repo_name=repo_name,
        commit_hash=commit_hash,
        repos_root=repos_root,
        repo_profiles_dir=repo_profiles_dir,
        llm_client=None,
        force_regenerate=False,
        cache=cache,
        regenerated_keys=set(),
    )

    assert getattr(profile, "description", None) == "cached"
    assert getattr(cache[(repo_name, commit_hash)], "description", None) == "cached"


def test_dirty_repo_cached_software_profile_returns_none_when_repo_state_changes(
    monkeypatch,
    tmp_path,
):
    repo_name = "demo"
    commit_hash = "abc123"
    repos_root = tmp_path / "repos"
    repo_dir = repos_root / repo_name
    repo_dir.mkdir(parents=True)
    source_file = repo_dir / "app.py"
    source_file.write_text("print('cached')\n", encoding="utf-8")

    repo_profiles_dir = tmp_path / "profiles"
    profile_dir = repo_profiles_dir / repo_name / commit_hash
    profile_dir.mkdir(parents=True)
    fingerprint = _build_cached_software_profile_fingerprint(
        repo_profiles_dir,
        repo_path=repo_dir,
        repo_version=commit_hash,
    )
    (profile_dir / "software_profile.json").write_text(
        json.dumps(
            {
                "basic_info": {"name": repo_name, "version": commit_hash, "description": "cached"},
                "repo_info": {},
                "modules": [],
                "metadata": {"profile_fingerprint": fingerprint},
            }
        ),
        encoding="utf-8",
    )
    source_file.write_text("print('modified')\n", encoding="utf-8")

    monkeypatch.setattr("cli.batch_scanner.has_uncommitted_changes", lambda repo_path: True)
    monkeypatch.setattr("cli.batch_scanner.get_git_commit", lambda repo_path: commit_hash)
    monkeypatch.setattr(
        "cli.batch_scanner.run_software_profile_generation",
        lambda **kwargs: pytest.fail("dirty stale cache should not regenerate software profiles"),
    )

    profile = _ensure_software_profile(
        repo_name=repo_name,
        commit_hash=commit_hash,
        repos_root=repos_root,
        repo_profiles_dir=repo_profiles_dir,
        llm_client=None,
        force_regenerate=False,
        cache={},
        regenerated_keys=set(),
    )

    assert profile is None


def test_loads_cached_software_profile_from_disk_when_dirty_repo_is_off_target(monkeypatch, tmp_path):
    repo_name = "demo"
    commit_hash = "abc123"
    repos_root = tmp_path / "repos"
    repo_dir = repos_root / repo_name
    repo_dir.mkdir(parents=True)
    (repo_dir / "app.py").write_text("print('off-target')\n", encoding="utf-8")

    repo_profiles_dir = tmp_path / "profiles"
    profile_dir = repo_profiles_dir / repo_name / commit_hash
    profile_dir.mkdir(parents=True)
    fingerprint = _build_cached_software_profile_fingerprint(
        repo_profiles_dir,
        repo_path=repo_dir,
        repo_version=commit_hash,
    )
    (profile_dir / "software_profile.json").write_text(
        json.dumps(
            {
                "basic_info": {"name": repo_name, "version": commit_hash, "description": "cached"},
                "repo_info": {},
                "modules": [],
                "metadata": {"profile_fingerprint": fingerprint},
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr("cli.batch_scanner.has_uncommitted_changes", lambda repo_path: True)
    monkeypatch.setattr("cli.batch_scanner.get_git_commit", lambda repo_path: "other-branch-head")
    monkeypatch.setattr(
        "cli.batch_scanner.run_software_profile_generation",
        lambda **kwargs: pytest.fail("dirty off-target resume should not regenerate software profiles"),
    )

    cache = {}
    profile = _ensure_software_profile(
        repo_name=repo_name,
        commit_hash=commit_hash,
        repos_root=repos_root,
        repo_profiles_dir=repo_profiles_dir,
        llm_client=None,
        force_regenerate=False,
        cache=cache,
        regenerated_keys=set(),
    )

    assert getattr(profile, "description", None) == "cached"
    assert getattr(cache[(repo_name, commit_hash)], "description", None) == "cached"


def test_dirty_repo_cached_vulnerability_profile_returns_none_when_revalidation_fails(
    monkeypatch,
    tmp_path,
):
    repo_name = "demo"
    commit_hash = "abc123"
    cve_id = "CVE-2026-0001"
    repos_root = tmp_path / "repos"
    (repos_root / repo_name).mkdir(parents=True)

    vuln_profiles_dir = tmp_path / "profiles"
    profile_dir = vuln_profiles_dir / repo_name / cve_id
    profile_dir.mkdir(parents=True)
    profile_path = profile_dir / "vulnerability_profile.json"
    profile_path.write_text(
        json.dumps(
            {
                "repo_name": repo_name,
                "affected_version": commit_hash,
                "cve_id": cve_id,
                "call_chain": [{"file_path": "src/app.py", "function_name": "entry"}],
                "metadata": {"profile_fingerprint": {"hash": "stale"}},
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr("cli.batch_scanner.has_uncommitted_changes", lambda repo_path: True)
    monkeypatch.setattr(
        "cli.batch_scanner._ensure_software_profile",
        lambda **kwargs: {"metadata": {"profile_fingerprint": {"hash": "source"}}},
    )
    monkeypatch.setattr(
        "cli.batch_scanner._cached_vulnerability_profile_matches_current_inputs",
        lambda **kwargs: False,
    )
    monkeypatch.setattr(
        "cli.batch_scanner.read_vuln_data",
        lambda *args, **kwargs: pytest.fail("dirty stale cache should not re-read vulnerability data"),
    )

    cached_profile = SimpleNamespace(
        repo_name=repo_name,
        affected_version=commit_hash,
        cve_id=cve_id,
        payload=None,
        call_chain=[{"file_path": "src/app.py", "function_name": "entry"}],
        metadata={"profile_fingerprint": {"hash": "stale"}},
    )
    reloaded_profile = object()
    load_calls = {"count": 0}

    def _fake_load(*args, **kwargs):
        load_calls["count"] += 1
        if load_calls["count"] == 1:
            return cached_profile
        return reloaded_profile

    monkeypatch.setattr("cli.batch_scanner.load_vulnerability_profile", _fake_load)
    monkeypatch.setattr(
        "cli.batch_scanner.run_vulnerability_profile_generation",
        lambda **kwargs: pytest.fail("dirty stale cache should not attempt regeneration"),
    )

    profile = _ensure_vulnerability_profile(
        vuln_index=0,
        repo_name=repo_name,
        commit_hash=commit_hash,
        cve_id=cve_id,
        repos_root=repos_root,
        repo_profiles_dir=tmp_path / "software-profiles",
        vuln_profiles_dir=vuln_profiles_dir,
        llm_client=None,
        force_regenerate=False,
        software_cache={},
        regenerated_software_keys=set(),
        cache={},
        verbose=False,
        vuln_json_path=str(tmp_path / "vuln.json"),
    )

    assert profile is None


def test_dirty_repo_cached_vulnerability_profile_revalidation_uses_current_snippets(tmp_path):
    repo_name = "demo"
    commit_hash = "abc123"
    cve_id = "CVE-2026-0001"
    repo_path = tmp_path / "repos" / repo_name
    (repo_path / "src").mkdir(parents=True)
    (repo_path / "src" / "app.py").write_text(
        "def entry():\n    return 'new'\n",
        encoding="utf-8",
    )

    vuln_json_path = tmp_path / "vuln.json"
    vuln_json_path.write_text(
        json.dumps(
            [
                {
                    "repo_name": repo_name,
                    "commit": commit_hash,
                    "call_chain": ["src/app.py#entry"],
                    "payload": None,
                    "cve_id": cve_id,
                }
            ]
        ),
        encoding="utf-8",
    )

    source_profile = {"metadata": {"profile_fingerprint": {"hash": "source"}}}
    cached_vuln_data = {
        "repo_name": repo_name,
        "commit": commit_hash,
        "call_chain": [
            {
                "file_path": "src/app.py",
                "function_name": "entry",
                "file_content": "def entry():\n    return 'old'\n",
                "code_snippet": "1: def entry():\n2:     return 'old'",
            }
        ],
        "payload": None,
        "cve_id": cve_id,
    }
    cached_fingerprint = build_vulnerability_profile_fingerprint(
        repo_profile=source_profile,
        vuln_entry=build_vulnerability_entry(cached_vuln_data),
        llm_client=None,
        extraction_temperature=EXTRACTION_TEMPERATURE,
    )
    cached_profile = SimpleNamespace(
        repo_name=repo_name,
        affected_version=commit_hash,
        cve_id=cve_id,
        payload=None,
        call_chain=cached_vuln_data["call_chain"],
        metadata={"profile_fingerprint": cached_fingerprint},
    )

    assert (
        _cached_vulnerability_profile_matches_current_inputs(
            cached_profile=cached_profile,
            source_profile=source_profile,
            repo_path=repo_path,
            repo_name=repo_name,
            commit_hash=commit_hash,
            cve_id=cve_id,
            vuln_index=0,
            vuln_json_path=str(vuln_json_path),
            llm_client=None,
        )
        is False
    )


def test_dirty_repo_cached_vulnerability_profile_revalidation_reads_target_commit_content(
    monkeypatch,
    tmp_path,
):
    repo_name = "demo"
    commit_hash = "abc123"
    cve_id = "CVE-2026-0001"
    repo_path = tmp_path / "repos" / repo_name
    (repo_path / "src").mkdir(parents=True)
    (repo_path / "src" / "app.py").write_text(
        "def entry():\n    return 'dirty-working-tree'\n",
        encoding="utf-8",
    )

    vuln_json_path = tmp_path / "vuln.json"
    vuln_json_path.write_text(
        json.dumps(
            [
                {
                    "repo_name": repo_name,
                    "commit": commit_hash,
                    "call_chain": ["src/app.py#entry"],
                    "payload": None,
                    "cve_id": cve_id,
                }
            ]
        ),
        encoding="utf-8",
    )

    target_commit_content = "def entry():\n    return 'target-commit'\n"
    target_commit_snippet = "1: def entry():\n2:     return 'target-commit'"
    source_profile = {"metadata": {"profile_fingerprint": {"hash": "source"}}}
    cached_vuln_data = {
        "repo_name": repo_name,
        "commit": commit_hash,
        "call_chain": [
            {
                "file_path": "src/app.py",
                "function_name": "entry",
                "file_content": target_commit_content,
                "code_snippet": target_commit_snippet,
            }
        ],
        "payload": None,
        "cve_id": cve_id,
    }
    cached_fingerprint = build_vulnerability_profile_fingerprint(
        repo_profile=source_profile,
        vuln_entry=build_vulnerability_entry(cached_vuln_data),
        llm_client=None,
        extraction_temperature=EXTRACTION_TEMPERATURE,
    )
    cached_profile = SimpleNamespace(
        repo_name=repo_name,
        affected_version=commit_hash,
        cve_id=cve_id,
        payload=None,
        call_chain=cached_vuln_data["call_chain"],
        metadata={"profile_fingerprint": cached_fingerprint},
    )

    monkeypatch.setattr(batch_scanner_cache, "get_git_commit", lambda repo: "dirty-head")
    monkeypatch.setattr(
        batch_scanner_cache.subprocess,
        "run",
        lambda args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout=target_commit_content.encode("utf-8"),
            stderr=b"",
        ),
    )

    assert (
        _cached_vulnerability_profile_matches_current_inputs(
            cached_profile=cached_profile,
            source_profile=source_profile,
            repo_path=repo_path,
            repo_name=repo_name,
            commit_hash=commit_hash,
            cve_id=cve_id,
            vuln_index=0,
            vuln_json_path=str(vuln_json_path),
            llm_client=None,
        )
        is True
    )


def test_force_regenerate_ignores_cached_entry_and_preserves_stale_profile_until_success(
    monkeypatch,
    tmp_path,
):
    repo_name = "demo"
    commit_hash = "abc123"
    repo_dir = tmp_path / "repos" / repo_name
    repo_dir.mkdir(parents=True)

    repo_profiles_dir = tmp_path / "profiles"
    profile_dir = repo_profiles_dir / repo_name / commit_hash
    profile_dir.mkdir(parents=True)
    stale_profile = profile_dir / "software_profile.json"
    stale_profile.write_text(
        json.dumps(
            {
                "basic_info": {"name": repo_name, "version": commit_hash, "description": "stale"},
                "repo_info": {},
                "modules": [],
            }
        ),
        encoding="utf-8",
    )

    class StubProfiler:
        def __call__(self, *, repo_path, output_dir, llm_client, force_regenerate, target_version):
            assert repo_path == tmp_path / "repos" / repo_name
            assert output_dir == repo_profiles_dir
            assert llm_client is None
            assert force_regenerate is True
            assert target_version == commit_hash
            assert stale_profile.exists()

    monkeypatch.setattr("cli.batch_scanner.run_software_profile_generation", StubProfiler())

    cache = {(repo_name, commit_hash): object()}
    profile = _ensure_software_profile(
        repo_name=repo_name,
        commit_hash=commit_hash,
        repos_root=tmp_path / "repos",
        repo_profiles_dir=repo_profiles_dir,
        llm_client=None,
        force_regenerate=True,
        cache=cache,
        regenerated_keys=set(),
    )

    assert getattr(profile, "description", None) == "stale"
    assert getattr(cache[(repo_name, commit_hash)], "description", None) == "stale"
    assert stale_profile.exists()


def test_force_regenerate_vulnerability_profile_bypasses_cached_final_result(monkeypatch, tmp_path):
    repo_name = "demo"
    commit_hash = "abc123"
    cve_id = "CVE-2026-0001"
    repo_dir = tmp_path / "repos" / repo_name
    repo_dir.mkdir(parents=True)

    vuln_profiles_dir = tmp_path / "profiles"
    profile_dir = vuln_profiles_dir / repo_name / cve_id
    profile_dir.mkdir(parents=True)
    stale_profile = profile_dir / "vulnerability_profile.json"
    stale_profile.write_text(
        json.dumps(
            {
                "repo_name": repo_name,
                "affected_version": commit_hash,
                "cve_id": cve_id,
                "call_chain": [{"file_path": "src/app.py", "function_name": "entry"}],
                "metadata": {"profile_fingerprint": {"hash": "stale"}},
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr("cli.batch_scanner._ensure_software_profile", lambda **kwargs: object())
    monkeypatch.setattr(
        "cli.batch_scanner.read_vuln_data",
        lambda *args, **kwargs: [
            {
                "repo_name": repo_name,
                "commit": commit_hash,
                "call_chain": [{"file_path": "src/app.py", "function_name": "entry"}],
                "payload": None,
                "cve_id": cve_id,
            }
        ],
    )
    built_entry = object()
    monkeypatch.setattr("cli.batch_scanner.build_vulnerability_entry", lambda data: built_entry)
    monkeypatch.setattr("cli.batch_scanner.has_uncommitted_changes", lambda _repo: False)

    class StubProfiler:
        def __call__(
            self,
            *,
            repo_path,
            output_dir,
            llm_client,
            repo_profile,
            vuln_entry,
            force_regenerate,
        ):
            assert repo_path == repo_dir
            assert output_dir == vuln_profiles_dir
            assert llm_client is None
            assert repo_profile is not None
            assert vuln_entry is built_entry
            assert force_regenerate is True
            assert stale_profile.exists()

    monkeypatch.setattr("cli.batch_scanner.run_vulnerability_profile_generation", StubProfiler())

    cache = {}
    profile = _ensure_vulnerability_profile(
        vuln_index=0,
        repo_name=repo_name,
        commit_hash=commit_hash,
        cve_id=cve_id,
        repos_root=tmp_path / "repos",
        repo_profiles_dir=tmp_path / "software-profiles",
        vuln_profiles_dir=vuln_profiles_dir,
        llm_client=None,
        force_regenerate=True,
        software_cache={},
        regenerated_software_keys=set(),
        cache=cache,
        verbose=False,
        vuln_json_path=None,
    )

    assert getattr(profile, "cve_id", None) == cve_id
    assert getattr(cache[(repo_name, cve_id)], "cve_id", None) == cve_id


def test_force_regenerate_reuses_same_run_cached_profile(monkeypatch, tmp_path):
    repo_name = "demo"
    commit_hash = "abc123"
    (tmp_path / "repos" / repo_name).mkdir(parents=True)

    fresh_profile = object()
    cache = {(repo_name, commit_hash): fresh_profile}
    regenerated_keys = {(repo_name, commit_hash)}

    class StubProfiler:
        def __call__(self, **kwargs):
            raise AssertionError("should not regenerate twice in one batch")

    monkeypatch.setattr("cli.batch_scanner.run_software_profile_generation", StubProfiler())

    profile = _ensure_software_profile(
        repo_name=repo_name,
        commit_hash=commit_hash,
        repos_root=tmp_path / "repos",
        repo_profiles_dir=tmp_path / "profiles",
        llm_client=None,
        force_regenerate=True,
        cache=cache,
        regenerated_keys=regenerated_keys,
    )

    assert profile is fresh_profile
