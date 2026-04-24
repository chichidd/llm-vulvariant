import json
import os
import stat
import subprocess
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run_all_software_profiles.sh"
FAKE_GIT_HEAD = "a" * 40


def _write_fake_software_profile(bin_dir: Path, calls_log: Path) -> None:
    fake_cmd = bin_dir / "software-profile"
    fake_cmd.write_text(
        "\n".join(
            [
                "#!/usr/bin/env bash",
                "set -euo pipefail",
                f"{sys.executable} - \"$@\" <<'PY'",
                "import json",
                "import os",
                "import sys",
                "from pathlib import Path",
                "log_path = Path(os.environ['CALLS_LOG'])",
                "fail_repo_name = os.environ.get('FAIL_REPO_NAME', '')",
                "repo_name = ''",
                "args = sys.argv[1:]",
                "if '--repo-name' in args:",
                "    repo_name = args[args.index('--repo-name') + 1]",
                "with log_path.open('a', encoding='utf-8') as handle:",
                "    handle.write(json.dumps(sys.argv[1:]) + '\\n')",
                "if fail_repo_name and repo_name == fail_repo_name:",
                "    raise SystemExit(1)",
                "PY",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    fake_cmd.chmod(fake_cmd.stat().st_mode | stat.S_IEXEC)


def _write_fake_python(bin_dir: Path, name: str = "python3") -> None:
    fake_python = bin_dir / name
    fake_python.write_text(
        "\n".join(
            [
                f"#!{sys.executable}",
                "import os",
                "import sys",
                "from pathlib import Path",
                "",
                "if len(sys.argv) >= 5 and sys.argv[1] == '-' and sys.argv[2] == 'resolve_locked_head_commit':",
                "    print(os.environ['FAKE_GIT_HEAD'])",
                "    raise SystemExit(0)",
                "",
                "if len(sys.argv) >= 5 and sys.argv[1] == '-' and sys.argv[2] == 'cleanup_codeql_temp_artifacts':",
                "    app_dir = Path(sys.argv[3]).resolve()",
                "    repo_dir = Path(sys.argv[4]).resolve()",
                "    sys.path.insert(0, str(app_dir / 'src'))",
                "    from config import _path_config",
                "    from utils import repo_lock as repo_lock_module",
                "    import shutil",
                "    _path_config['repo_root'] = app_dir",
                "    cleaned = False",
                "    with repo_lock_module.hold_repo_lock(repo_dir, purpose='cleanup_codeql_temp_artifacts'):",
                "        detected = repo_dir / '_codeql_detected_source_root'",
                "        if detected.exists() or detected.is_symlink():",
                "            detected.unlink()",
                "            cleaned = True",
                "        build_dir = repo_dir / '_codeql_build_dir'",
                "        if build_dir.exists():",
                "            shutil.rmtree(build_dir)",
                "            cleaned = True",
                "    if cleaned:",
                "        print(f'Cleaned CodeQL temp artifacts: {repo_dir}')",
                "    raise SystemExit(0)",
                "",
                "raise SystemExit(f'unexpected python invocation: {sys.argv[1:]}')",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    fake_python.chmod(fake_python.stat().st_mode | stat.S_IEXEC)


def _write_fake_conda(bin_dir: Path) -> None:
    fake_conda = bin_dir / "conda"
    fake_conda.write_text(
        "\n".join(
            [
                f"#!{sys.executable}",
                "import os",
                "import sys",
                "from pathlib import Path",
                "",
                "args = sys.argv[1:]",
                "if len(args) < 4 or args[:3] != ['run', '-n', 'custom-env'] or args[3] != 'python':",
                "    raise SystemExit(f'unexpected conda invocation: {args}')",
                "python_args = args[4:]",
                "if len(python_args) >= 4 and python_args[0] == '-' and python_args[1] == 'resolve_locked_head_commit':",
                "    print(os.environ['FAKE_GIT_HEAD'])",
                "    raise SystemExit(0)",
                "if len(python_args) >= 4 and python_args[0] == '-' and python_args[1] == 'cleanup_codeql_temp_artifacts':",
                "    app_dir = Path(python_args[2]).resolve()",
                "    repo_dir = Path(python_args[3]).resolve()",
                "    sys.path.insert(0, str(app_dir / 'src'))",
                "    from config import _path_config",
                "    from utils import repo_lock as repo_lock_module",
                "    import shutil",
                "    _path_config['repo_root'] = app_dir",
                "    cleaned = False",
                "    with repo_lock_module.hold_repo_lock(repo_dir, purpose='cleanup_codeql_temp_artifacts'):",
                "        detected = repo_dir / '_codeql_detected_source_root'",
                "        if detected.exists() or detected.is_symlink():",
                "            detected.unlink()",
                "            cleaned = True",
                "        build_dir = repo_dir / '_codeql_build_dir'",
                "        if build_dir.exists():",
                "            shutil.rmtree(build_dir)",
                "            cleaned = True",
                "    if cleaned:",
                "        print(f'Cleaned CodeQL temp artifacts: {repo_dir}')",
                "    raise SystemExit(0)",
                "os.execv(sys.executable, [sys.executable, *python_args])",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    fake_conda.chmod(fake_conda.stat().st_mode | stat.S_IEXEC)


def _write_failing_python(bin_dir: Path, name: str = "python") -> None:
    fake_python = bin_dir / name
    fake_python.write_text(
        "\n".join(
            [
                "#!/usr/bin/env bash",
                "set -euo pipefail",
                "echo unexpected python invocation >&2",
                "exit 97",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    fake_python.chmod(fake_python.stat().st_mode | stat.S_IEXEC)


def _start_repo_lock_holder(repo_dir: Path, ready_path: Path, release_path: Path) -> subprocess.Popen[str]:
    lock_holder_code = """
from pathlib import Path
import sys
import time

app_dir = Path(sys.argv[1]).resolve()
repo_dir = Path(sys.argv[2]).resolve()
ready_path = Path(sys.argv[3]).resolve()
release_path = Path(sys.argv[4]).resolve()

sys.path.insert(0, str(app_dir / "src"))

from config import _path_config
from utils import repo_lock

_path_config["repo_root"] = app_dir

with repo_lock.hold_repo_lock(repo_dir, purpose="test_run_all_software_profiles_lock_holder"):
    ready_path.write_text("ready", encoding="utf-8")
    while not release_path.exists():
        time.sleep(0.01)
"""
    return subprocess.Popen(
        [
            sys.executable,
            "-c",
            lock_holder_code,
            str(ROOT),
            str(repo_dir),
            str(ready_path),
            str(release_path),
        ],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def _wait_for_path(path: Path, timeout_seconds: float = 5.0) -> bool:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        if path.exists():
            return True
        time.sleep(0.01)
    return path.exists()


def _stays_call_free(calls_log: Path, duration_seconds: float = 0.2) -> bool:
    deadline = time.time() + duration_seconds
    while time.time() < deadline:
        if calls_log.exists() and calls_log.read_text(encoding="utf-8").strip():
            return False
        time.sleep(0.01)
    return True


def _run_script(launch_dir: Path, path_root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PATH"] = f"{path_root / 'bin'}:{env['PATH']}"
    env["CALLS_LOG"] = str(path_root / "calls.log")
    env["_PROFILE_PATHS_REPO_ROOT"] = str(path_root / "repo-root")
    env["FAKE_GIT_HEAD"] = FAKE_GIT_HEAD
    return subprocess.run(
        ["bash", str(SCRIPT), *args],
        cwd=launch_dir,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def _init_git_repo(repo_dir: Path) -> str:
    (repo_dir / "README.md").write_text("demo\n", encoding="utf-8")
    (repo_dir / ".git").mkdir()
    return FAKE_GIT_HEAD


def test_run_all_software_profiles_anchors_relative_profile_base_to_repo_root(tmp_path: Path) -> None:
    launch_dir = tmp_path / "launch"
    launch_dir.mkdir()
    repo_root = tmp_path / "repo-root"
    repo_root.mkdir()
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    calls_log = tmp_path / "calls.log"
    _write_fake_software_profile(bin_dir, calls_log)
    _write_fake_python(bin_dir, "python")

    repo_dir = repo_root / "repos" / "demo"
    repo_dir.mkdir(parents=True)
    commit = _init_git_repo(repo_dir)

    result = _run_script(
        launch_dir,
        tmp_path,
        "--root",
        "repos",
        "--profile-base-path",
        "profiles",
        "--soft-profile-dirname",
        "soft-custom",
    )

    assert result.returncode == 0, result.stderr
    calls = [
        json.loads(line)
        for line in calls_log.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert calls == [
        [
            "--profile-base-path",
            str(repo_root / "profiles"),
            "--software-profile-dirname",
            "soft-custom",
            "--repo-base-path",
            str(repo_root / "repos"),
            "--repo-name",
            "demo",
            "--target-version",
            commit,
        ]
    ]


def test_run_all_software_profiles_prefers_active_python_for_repo_lock_helpers(tmp_path: Path) -> None:
    launch_dir = tmp_path / "launch"
    launch_dir.mkdir()
    repo_root = tmp_path / "repo-root"
    repo_root.mkdir()
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    calls_log = tmp_path / "calls.log"
    _write_fake_software_profile(bin_dir, calls_log)
    _write_fake_python(bin_dir, "python")
    _write_failing_python(bin_dir, "python3")

    repo_dir = repo_root / "repos" / "demo"
    repo_dir.mkdir(parents=True)
    _init_git_repo(repo_dir)

    result = _run_script(
        launch_dir,
        tmp_path,
        "--root",
        "repos",
        "--profile-base-path",
        "profiles",
        "--soft-profile-dirname",
        "soft-custom",
    )

    assert result.returncode == 0, result.stderr
    assert "unexpected python invocation" not in result.stderr


def test_run_all_software_profiles_supports_multiword_python_bin(tmp_path: Path) -> None:
    launch_dir = tmp_path / "launch"
    launch_dir.mkdir()
    repo_root = tmp_path / "repo-root"
    repo_root.mkdir()
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    calls_log = tmp_path / "calls.log"
    _write_fake_software_profile(bin_dir, calls_log)
    _write_fake_conda(bin_dir)

    repo_dir = repo_root / "repos" / "demo"
    repo_dir.mkdir(parents=True)
    commit = _init_git_repo(repo_dir)

    env = os.environ.copy()
    env["PATH"] = f"{bin_dir}:{env['PATH']}"
    env["CALLS_LOG"] = str(calls_log)
    env["_PROFILE_PATHS_REPO_ROOT"] = str(repo_root)
    env["FAKE_GIT_HEAD"] = FAKE_GIT_HEAD
    env["PYTHON_BIN"] = "conda run -n custom-env python"

    result = subprocess.run(
        [
            "bash",
            str(SCRIPT),
            "--root",
            "repos",
            "--profile-base-path",
            "profiles",
            "--soft-profile-dirname",
            "soft-custom",
        ],
        cwd=launch_dir,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    calls = [
        json.loads(line)
        for line in calls_log.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert calls == [
        [
            "--profile-base-path",
            str(repo_root / "profiles"),
            "--software-profile-dirname",
            "soft-custom",
            "--repo-base-path",
            str(repo_root / "repos"),
            "--repo-name",
            "demo",
            "--target-version",
            commit,
        ]
    ]


def test_run_all_software_profiles_continues_after_repo_failure_and_reports_it(tmp_path: Path) -> None:
    launch_dir = tmp_path / "launch"
    launch_dir.mkdir()
    repo_root = tmp_path / "repo-root"
    repo_root.mkdir()
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    calls_log = tmp_path / "calls.log"
    _write_fake_software_profile(bin_dir, calls_log)
    _write_fake_python(bin_dir, "python")

    ok_repo = repo_root / "repos" / "demo-ok"
    broken_repo = repo_root / "repos" / "demo-broken"
    ok_repo.mkdir(parents=True)
    broken_repo.mkdir(parents=True)
    _init_git_repo(ok_repo)
    _init_git_repo(broken_repo)

    env = os.environ.copy()
    env["PATH"] = f"{bin_dir}:{env['PATH']}"
    env["CALLS_LOG"] = str(calls_log)
    env["FAIL_REPO_NAME"] = "demo-broken"
    env["_PROFILE_PATHS_REPO_ROOT"] = str(repo_root)
    env["FAKE_GIT_HEAD"] = FAKE_GIT_HEAD

    result = subprocess.run(
        [
            "bash",
            str(SCRIPT),
            "--root",
            "repos",
            "--profile-base-path",
            "profiles",
            "--soft-profile-dirname",
            "soft",
        ],
        cwd=launch_dir,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 1, result.stderr
    calls = [
        json.loads(line)
        for line in calls_log.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(calls) == 2
    assert any("--repo-name" in call and call[call.index("--repo-name") + 1] == "demo-ok" for call in calls)
    assert any("--repo-name" in call and call[call.index("--repo-name") + 1] == "demo-broken" for call in calls)
    assert "Failed repos:" in result.stdout
    assert "demo-broken" in result.stdout


def test_run_all_software_profiles_waits_for_repo_lock_before_cleaning_codeql_artifacts(tmp_path: Path) -> None:
    launch_dir = tmp_path / "launch"
    launch_dir.mkdir()
    repo_root = tmp_path / "repo-root"
    repo_root.mkdir()
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    calls_log = tmp_path / "calls.log"
    _write_fake_software_profile(bin_dir, calls_log)
    _write_fake_python(bin_dir, "python")

    repo_dir = repo_root / "repos" / "demo"
    repo_dir.mkdir(parents=True)
    _init_git_repo(repo_dir)
    (repo_dir / "_codeql_build_dir").mkdir()
    (repo_dir / "_codeql_build_dir" / "artifact.txt").write_text("artifact", encoding="utf-8")
    (repo_dir / "_codeql_detected_source_root").write_text("source-root", encoding="utf-8")

    ready_path = tmp_path / "ready"
    release_path = tmp_path / "release"
    lock_holder = _start_repo_lock_holder(repo_dir, ready_path, release_path)
    try:
        assert _wait_for_path(ready_path)

        env = os.environ.copy()
        env["PATH"] = f"{bin_dir}:{env['PATH']}"
        env["CALLS_LOG"] = str(calls_log)
        env["_PROFILE_PATHS_REPO_ROOT"] = str(repo_root)
        env["FAKE_GIT_HEAD"] = FAKE_GIT_HEAD

        result = subprocess.Popen(
            [
                "bash",
                str(SCRIPT),
                "--root",
                "repos",
                "--profile-base-path",
                "profiles",
                "--soft-profile-dirname",
                "soft",
            ],
            cwd=launch_dir,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            assert _stays_call_free(calls_log)
            assert (repo_dir / "_codeql_build_dir").exists() is True
            assert (repo_dir / "_codeql_detected_source_root").exists() is True

            release_path.write_text("release", encoding="utf-8")
            stdout, stderr = result.communicate(timeout=5)
            assert result.returncode == 0, stderr
            assert (repo_dir / "_codeql_build_dir").exists() is False
            assert (repo_dir / "_codeql_detected_source_root").exists() is False
            calls = [
                json.loads(line)
                for line in calls_log.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            assert len(calls) == 1
            assert "--repo-name" in calls[0]
            assert stdout.count("Cleaned CodeQL temp artifacts:") == 1
        finally:
            if result.poll() is None:
                result.terminate()
                result.wait(timeout=5)
    finally:
        release_path.write_text("release", encoding="utf-8")
        lock_holder.wait(timeout=5)


def test_run_all_software_profiles_rechecks_existing_outputs(tmp_path: Path) -> None:
    launch_dir = tmp_path / "launch"
    launch_dir.mkdir()
    repo_root = tmp_path / "repo-root"
    repo_root.mkdir()
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    calls_log = tmp_path / "calls.log"
    _write_fake_software_profile(bin_dir, calls_log)
    _write_fake_python(bin_dir, "python")

    repo_dir = repo_root / "repos" / "demo"
    repo_dir.mkdir(parents=True)
    commit = _init_git_repo(repo_dir)
    existing_profile = repo_root / "profiles" / "soft" / "demo" / commit / "software_profile.json"
    existing_profile.parent.mkdir(parents=True)
    existing_profile.write_text("{}", encoding="utf-8")

    result = _run_script(
        launch_dir,
        tmp_path,
        "--root",
        "repos",
        "--profile-base-path",
        "profiles",
    )

    assert result.returncode == 0, result.stderr
    calls = [
        json.loads(line)
        for line in calls_log.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(calls) == 1
