from __future__ import annotations

import subprocess

from utils import git_utils


def test_has_uncommitted_changes_treats_non_git_directory_as_clean(monkeypatch) -> None:
    def fake_run(*args, **kwargs):
        raise subprocess.CalledProcessError(
            returncode=128,
            cmd=["git", "status", "--porcelain"],
            stderr="fatal: not a git repository (or any of the parent directories): .git",
        )

    monkeypatch.setattr(subprocess, "run", fake_run)

    assert git_utils.has_uncommitted_changes("/tmp/non-git-tree") is False


def test_has_uncommitted_changes_keeps_failing_closed_for_other_git_errors(monkeypatch) -> None:
    def fake_run(*args, **kwargs):
        raise subprocess.CalledProcessError(
            returncode=1,
            cmd=["git", "status", "--porcelain"],
            stderr="fatal: unexpected git failure",
        )

    monkeypatch.setattr(subprocess, "run", fake_run)

    assert git_utils.has_uncommitted_changes("/tmp/repo") is True
