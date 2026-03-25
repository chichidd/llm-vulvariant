import json
import os
import threading

import utils.repo_lock as repo_lock


def _write_lock_file(lock_path, payload):
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def test_acquire_repo_lock_blocks_until_previous_owner_releases(monkeypatch, tmp_path):
    repo_root = tmp_path / "llm-vulvariant"
    repo_root.mkdir()
    repo_dir = tmp_path / "repos" / "demo-repo"
    repo_dir.mkdir(parents=True)
    monkeypatch.setitem(repo_lock._path_config, "repo_root", repo_root)

    first_lock = repo_lock.acquire_repo_lock(repo_dir, purpose="first")
    acquired_event = threading.Event()
    release_event = threading.Event()
    worker_started = threading.Event()

    def _worker():
        worker_started.set()
        with repo_lock.hold_repo_lock(
            repo_dir,
            purpose="second",
            poll_interval_seconds=0.01,
        ):
            acquired_event.set()
            release_event.wait(timeout=1.0)

    worker = threading.Thread(target=_worker)
    worker.start()

    assert worker_started.wait(timeout=1.0) is True
    assert acquired_event.wait(timeout=0.05) is False

    repo_lock.release_repo_lock(first_lock, repo_dir, "first")

    assert acquired_event.wait(timeout=1.0) is True
    release_event.set()
    worker.join(timeout=1.0)
    assert worker.is_alive() is False


def test_release_lock_does_not_remove_foreign_owner(monkeypatch, tmp_path):
    repo_root = tmp_path / "llm-vulvariant"
    repo_root.mkdir()
    repo_dir = tmp_path / "repos" / "demo-repo"
    repo_dir.mkdir(parents=True)
    monkeypatch.setitem(repo_lock._path_config, "repo_root", repo_root)

    lock_info = repo_lock.acquire_repo_lock(repo_dir, purpose="owner")
    lock_path = repo_lock.resolve_repo_lock_path(repo_dir)

    repo_lock.release_lock(
        {
            "lock_path": lock_path,
            "token": "wrong-token",
        }
    )

    assert lock_path.exists() is True
    repo_lock.release_repo_lock(lock_info, repo_dir, "owner")
    assert lock_path.exists() is False


def test_acquire_repo_lock_removes_stale_lock(monkeypatch, tmp_path):
    repo_root = tmp_path / "llm-vulvariant"
    repo_root.mkdir()
    repo_dir = tmp_path / "repos" / "demo-repo"
    repo_dir.mkdir(parents=True)
    monkeypatch.setitem(repo_lock._path_config, "repo_root", repo_root)

    lock_path = repo_lock.resolve_repo_lock_path(repo_dir)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path.write_text(
        json.dumps(
            {
                "token": "stale",
                "pid": -1,
                "purpose": "stale-owner",
            },
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    with repo_lock.hold_repo_lock(repo_dir, purpose="fresh-owner"):
        assert lock_path.exists() is True
        payload = json.loads(lock_path.read_text(encoding="utf-8"))
        assert payload["purpose"] == "fresh-owner"

    assert lock_path.exists() is False


def test_acquire_repo_lock_does_not_delete_republished_lock_during_stale_cleanup(monkeypatch, tmp_path):
    repo_root = tmp_path / "llm-vulvariant"
    repo_root.mkdir()
    repo_dir = tmp_path / "repos" / "demo-repo"
    repo_dir.mkdir(parents=True)
    monkeypatch.setitem(repo_lock._path_config, "repo_root", repo_root)

    lock_path = repo_lock.resolve_repo_lock_path(repo_dir)
    _write_lock_file(
        lock_path,
        {
            "token": "stale",
            "pid": -1,
            "purpose": "stale-owner",
        },
    )

    real_remove_if_identity_matches = repo_lock._remove_lock_path_if_identity_matches
    republished = {"done": False}

    def fake_remove_if_identity_matches(lock_path_arg, expected_identity):
        if lock_path_arg == lock_path and not republished["done"]:
            republished["done"] = True
            repo_lock._remove_lock_path(lock_path_arg)
            _write_lock_file(
                lock_path_arg,
                {
                    "token": "other-token",
                    "pid": os.getpid(),
                    "uid": os.getuid() if hasattr(os, "getuid") else None,
                    "run_id": "run-other",
                    "purpose": "other-owner",
                    "command": repo_lock._read_process_identity(os.getpid()) or "python",
                    "pid_start_time": repo_lock._read_process_start_time(os.getpid()),
                },
            )
        return real_remove_if_identity_matches(lock_path_arg, expected_identity)

    monkeypatch.setattr(repo_lock, "_remove_lock_path_if_identity_matches", fake_remove_if_identity_matches)

    status, lock_info, detail = repo_lock.acquire_lock(
        lock_path,
        run_id="run-1",
        owner_fields={"purpose": "fresh-owner"},
    )

    assert status == repo_lock.LOCK_STATUS_BUSY
    assert lock_info is None
    assert "purpose=other-owner" in (detail or "")
    assert json.loads(lock_path.read_text(encoding="utf-8"))["token"] == "other-token"


def test_acquire_lock_does_not_remove_replaced_stale_lock(monkeypatch, tmp_path):
    repo_root = tmp_path / "llm-vulvariant"
    repo_root.mkdir()
    repo_dir = tmp_path / "repos" / "demo-repo"
    repo_dir.mkdir(parents=True)
    monkeypatch.setitem(repo_lock._path_config, "repo_root", repo_root)

    lock_path = repo_lock.resolve_repo_lock_path(repo_dir)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path.write_text(
        json.dumps(
            {
                "token": "stale",
                "pid": -1,
                "purpose": "stale-owner",
            },
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    original_lock_pid_is_active = repo_lock._lock_pid_is_active
    replacement_payload = {
        "token": "replacement",
        "pid": os.getpid(),
        "uid": os.getuid() if hasattr(os, "getuid") else None,
        "run_id": "replacement-run",
        "command": repo_lock._read_process_identity(os.getpid()) or "pytest",
        "pid_start_time": repo_lock._read_process_start_time(os.getpid()),
        "purpose": "replacement-owner",
    }
    replaced = {"done": False}

    def _replace_then_check(*args, **kwargs):
        if not replaced["done"]:
            replaced["done"] = True
            lock_path.unlink()
            lock_path.write_text(
                json.dumps(replacement_payload, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            return False
        return original_lock_pid_is_active(*args, **kwargs)

    monkeypatch.setattr(repo_lock, "_lock_pid_is_active", _replace_then_check)

    status, lock_info, _ = repo_lock.acquire_lock(
        lock_path,
        run_id="fresh-run",
        owner_fields={"purpose": "fresh-owner"},
    )

    assert status == repo_lock.LOCK_STATUS_BUSY
    assert lock_info is None
    assert json.loads(lock_path.read_text(encoding="utf-8"))["token"] == "replacement"


def test_acquire_lock_reports_busy_when_holder_is_unverifiable(monkeypatch, tmp_path):
    repo_root = tmp_path / "llm-vulvariant"
    repo_root.mkdir()
    repo_dir = tmp_path / "repos" / "demo-repo"
    repo_dir.mkdir(parents=True)
    monkeypatch.setitem(repo_lock._path_config, "repo_root", repo_root)

    lock_path = repo_lock.resolve_repo_lock_path(repo_dir)
    _write_lock_file(
        lock_path,
        {
            "token": "other-token",
            "pid": 4242,
            "run_id": "run-other",
        },
    )

    def raise_permission_error(pid, signal_num):
        raise PermissionError()

    monkeypatch.setattr(repo_lock.os, "kill", raise_permission_error)
    monkeypatch.setattr(repo_lock, "_read_process_start_time", lambda pid: None)
    monkeypatch.setattr(repo_lock, "_read_process_identity", lambda pid: None)

    status, lock_info, detail = repo_lock.acquire_lock(
        lock_path,
        run_id="run-1",
        owner_fields={"purpose": "fresh-owner"},
    )

    assert status == repo_lock.LOCK_STATUS_BUSY
    assert lock_info is None
    assert "holder=unverified" in (detail or "")
