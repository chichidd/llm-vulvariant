from pathlib import Path

from cli.common import resolve_cli_path, resolve_path_override


def test_resolve_cli_path_expands_user_and_preserves_absolute_path(monkeypatch, tmp_path) -> None:
    home_dir = tmp_path / "home"
    home_dir.mkdir()
    absolute_path = tmp_path / "absolute"
    monkeypatch.setenv("HOME", str(home_dir))

    assert resolve_cli_path("~/data") == home_dir / "data"
    assert resolve_cli_path(absolute_path) == absolute_path


def test_resolve_cli_path_uses_optional_base_dir_for_relative_path(tmp_path) -> None:
    base_dir = tmp_path / "repo-root"
    base_dir.mkdir()

    assert resolve_cli_path("scan-results", base_dir=base_dir) == base_dir / "scan-results"


def test_resolve_path_override_falls_back_to_default_path(tmp_path) -> None:
    default_path = tmp_path / "profiles"

    assert resolve_path_override(None, default_path) == default_path
    assert resolve_path_override("custom", default_path) == Path("custom")


def test_resolve_path_override_uses_optional_base_dir_for_relative_override(tmp_path) -> None:
    default_path = tmp_path / "profiles"
    repo_root = tmp_path / "repo-root"
    repo_root.mkdir()

    assert resolve_path_override("custom", default_path, base_dir=repo_root) == repo_root / "custom"
