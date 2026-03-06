import json

from cli.batch_scanner import _ensure_software_profile


def test_force_regenerate_ignores_cached_entry_and_unlinks_stale_profile(monkeypatch, tmp_path):
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
        def __init__(self, llm_client, output_dir):
            self.llm_client = llm_client
            self.output_dir = output_dir

        def generate_profile(self, repo_path, force_regenerate, target_version):
            assert force_regenerate is True
            assert target_version == commit_hash
            assert not stale_profile.exists()

    monkeypatch.setattr("cli.batch_scanner.SoftwareProfiler", StubProfiler)

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

    assert profile is None
    assert (repo_name, commit_hash) not in cache
    assert not stale_profile.exists()


def test_force_regenerate_reuses_same_run_cached_profile(monkeypatch, tmp_path):
    repo_name = "demo"
    commit_hash = "abc123"
    (tmp_path / "repos" / repo_name).mkdir(parents=True)

    fresh_profile = object()
    cache = {(repo_name, commit_hash): fresh_profile}
    regenerated_keys = {(repo_name, commit_hash)}

    class StubProfiler:
        def __init__(self, llm_client, output_dir):
            raise AssertionError("should not regenerate twice in one batch")

    monkeypatch.setattr("cli.batch_scanner.SoftwareProfiler", StubProfiler)

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
