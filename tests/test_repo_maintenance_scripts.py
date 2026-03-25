import json
import os
import stat
import subprocess
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
UPDATE_SCRIPT = ROOT / "scripts" / "update_repos.sh"
CHECKOUT_SCRIPT = ROOT / "scripts" / "checkout_main.sh"


def _write_fake_git(bin_dir: Path) -> None:
    fake_git = bin_dir / "git"
    fake_git.write_text(
        "\n".join(
            [
                f"#!{sys.executable}",
                "import json",
                "import os",
                "import sys",
                "from pathlib import Path",
                "",
                "args = sys.argv[1:]",
                "log_path = Path(os.environ['CALLS_LOG'])",
                "with log_path.open('a', encoding='utf-8') as handle:",
                "    handle.write(json.dumps(args) + '\\n')",
                "command = args[2:] if len(args) >= 2 and args[0] == '-C' else args",
                "if command[:2] == ['rev-parse', '--is-inside-work-tree']:",
                "    print('true')",
                "elif command[:3] == ['symbolic-ref', '-q', '--short']:",
                "    print('origin/main')",
                "raise SystemExit(0)",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    fake_git.chmod(fake_git.stat().st_mode | stat.S_IEXEC)


def _load_calls(calls_log: Path) -> list[list[str]]:
    return [
        json.loads(line)
        for line in calls_log.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _write_python3_shim(bin_dir: Path) -> None:
    fake_python3 = bin_dir / "python3"
    fake_python3.write_text(
        "\n".join(
            [
                f"#!{sys.executable}",
                "import os",
                "import sys",
                "os.execv(sys.executable, [sys.executable, *sys.argv[1:]])",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    fake_python3.chmod(fake_python3.stat().st_mode | stat.S_IEXEC)


def _write_python_shim(bin_dir: Path) -> None:
    fake_python = bin_dir / "python"
    fake_python.write_text(
        "\n".join(
            [
                f"#!{sys.executable}",
                "import os",
                "import sys",
                "os.execv(sys.executable, [sys.executable, *sys.argv[1:]])",
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
                "",
                "args = sys.argv[1:]",
                "if len(args) < 4 or args[:3] != ['run', '-n', 'dsocr'] or args[3] != 'python':",
                "    raise SystemExit(f'unexpected conda invocation: {args}')",
                "os.execv(sys.executable, [sys.executable, *args[4:]])",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    fake_conda.chmod(fake_conda.stat().st_mode | stat.S_IEXEC)


def _write_failing_executable(bin_dir: Path, name: str, message: str) -> None:
    executable = bin_dir / name
    executable.write_text(
        "\n".join(
            [
                "#!/usr/bin/env bash",
                "set -euo pipefail",
                f"echo {message!r} >&2",
                "exit 97",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    executable.chmod(executable.stat().st_mode | stat.S_IEXEC)


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

with repo_lock.hold_repo_lock(repo_dir, purpose="test_repo_maintenance_lock_holder"):
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
        if calls_log.exists() and _load_calls(calls_log):
            return False
        time.sleep(0.01)
    return True


def test_repo_maintenance_scripts_have_valid_bash_syntax() -> None:
    for script in (UPDATE_SCRIPT, CHECKOUT_SCRIPT):
        result = subprocess.run(
            ["bash", "-n", str(script)],
            text=True,
            capture_output=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr


def test_update_repos_script_executes_pull_for_git_repositories(tmp_path: Path) -> None:
    repo_root = tmp_path / "repos"
    (repo_root / "demo" / ".git").mkdir(parents=True)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    calls_log = tmp_path / "calls.log"
    _write_fake_git(bin_dir)

    env = os.environ.copy()
    env["PATH"] = f"{bin_dir}:{env['PATH']}"
    env["CALLS_LOG"] = str(calls_log)
    env["ROOT"] = str(repo_root)

    result = subprocess.run(
        ["bash", str(UPDATE_SCRIPT)],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    calls = _load_calls(calls_log)
    assert ["-C", str(repo_root / "demo"), "pull", "--ff-only"] in calls


def test_update_repos_script_supports_multiword_python_bin(tmp_path: Path) -> None:
    repo_root = tmp_path / "repos"
    (repo_root / "demo" / ".git").mkdir(parents=True)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    calls_log = tmp_path / "calls.log"
    _write_fake_git(bin_dir)
    _write_fake_conda(bin_dir)

    env = os.environ.copy()
    env["PATH"] = f"{bin_dir}:{env['PATH']}"
    env["CALLS_LOG"] = str(calls_log)
    env["ROOT"] = str(repo_root)
    env["PYTHON_BIN"] = "conda run -n dsocr python"

    result = subprocess.run(
        ["bash", str(UPDATE_SCRIPT)],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    calls = _load_calls(calls_log)
    assert ["-C", str(repo_root / "demo"), "pull", "--ff-only"] in calls


def test_checkout_main_script_resolves_and_checks_out_default_branch(tmp_path: Path) -> None:
    repo_root = tmp_path / "repos"
    (repo_root / "demo" / ".git").mkdir(parents=True)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    calls_log = tmp_path / "calls.log"
    _write_fake_git(bin_dir)

    env = os.environ.copy()
    env["PATH"] = f"{bin_dir}:{env['PATH']}"
    env["CALLS_LOG"] = str(calls_log)
    env["ROOT"] = str(repo_root)

    result = subprocess.run(
        ["bash", str(CHECKOUT_SCRIPT)],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    calls = _load_calls(calls_log)
    assert [
        "-C",
        str(repo_root / "demo"),
        "symbolic-ref",
        "-q",
        "--short",
        "refs/remotes/origin/HEAD",
    ] in calls
    assert ["-C", str(repo_root / "demo"), "checkout", "main"] in calls


def test_checkout_main_script_supports_multiword_python_bin(tmp_path: Path) -> None:
    repo_root = tmp_path / "repos"
    (repo_root / "demo" / ".git").mkdir(parents=True)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    calls_log = tmp_path / "calls.log"
    _write_fake_git(bin_dir)
    _write_fake_conda(bin_dir)

    env = os.environ.copy()
    env["PATH"] = f"{bin_dir}:{env['PATH']}"
    env["CALLS_LOG"] = str(calls_log)
    env["ROOT"] = str(repo_root)
    env["PYTHON_BIN"] = "conda run -n dsocr python"

    result = subprocess.run(
        ["bash", str(CHECKOUT_SCRIPT)],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    calls = _load_calls(calls_log)
    assert ["-C", str(repo_root / "demo"), "checkout", "main"] in calls


def test_repo_maintenance_scripts_use_python3_when_python_is_unavailable(tmp_path: Path) -> None:
    repo_root = tmp_path / "repos"
    (repo_root / "demo" / ".git").mkdir(parents=True)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    calls_log = tmp_path / "calls.log"
    _write_fake_git(bin_dir)
    _write_python3_shim(bin_dir)

    env = os.environ.copy()
    env["PATH"] = str(bin_dir)
    env["CALLS_LOG"] = str(calls_log)
    env["ROOT"] = str(repo_root)

    update_result = subprocess.run(
        ["/bin/bash", str(UPDATE_SCRIPT)],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    checkout_result = subprocess.run(
        ["/bin/bash", str(CHECKOUT_SCRIPT)],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert update_result.returncode == 0, update_result.stderr
    assert checkout_result.returncode == 0, checkout_result.stderr
    calls = _load_calls(calls_log)
    assert ["-C", str(repo_root / "demo"), "pull", "--ff-only"] in calls
    assert ["-C", str(repo_root / "demo"), "checkout", "main"] in calls


def test_repo_maintenance_scripts_prefer_active_python_when_available(tmp_path: Path) -> None:
    repo_root = tmp_path / "repos"
    (repo_root / "demo" / ".git").mkdir(parents=True)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    calls_log = tmp_path / "calls.log"
    _write_fake_git(bin_dir)
    _write_python_shim(bin_dir)
    _write_failing_executable(bin_dir, "python3", "unexpected python3 invocation")

    env = os.environ.copy()
    env["PATH"] = str(bin_dir)
    env["CALLS_LOG"] = str(calls_log)
    env["ROOT"] = str(repo_root)

    update_result = subprocess.run(
        ["/bin/bash", str(UPDATE_SCRIPT)],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    checkout_result = subprocess.run(
        ["/bin/bash", str(CHECKOUT_SCRIPT)],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert update_result.returncode == 0, update_result.stderr
    assert checkout_result.returncode == 0, checkout_result.stderr
    assert "unexpected python3 invocation" not in update_result.stderr
    assert "unexpected python3 invocation" not in checkout_result.stderr


def test_update_repos_script_waits_for_repo_lock_before_pulling(tmp_path: Path) -> None:
    repo_root = tmp_path / "repos"
    repo_dir = repo_root / "demo"
    (repo_dir / ".git").mkdir(parents=True)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    calls_log = tmp_path / "calls.log"
    _write_fake_git(bin_dir)

    ready_path = tmp_path / "ready-update"
    release_path = tmp_path / "release-update"
    lock_holder = _start_repo_lock_holder(repo_dir, ready_path, release_path)
    try:
        assert _wait_for_path(ready_path)

        env = os.environ.copy()
        env["PATH"] = f"{bin_dir}:{env['PATH']}"
        env["CALLS_LOG"] = str(calls_log)
        env["ROOT"] = str(repo_root)

        proc = subprocess.Popen(
            ["bash", str(UPDATE_SCRIPT)],
            cwd=ROOT,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            assert _stays_call_free(calls_log)
            release_path.write_text("release", encoding="utf-8")
            stdout, stderr = proc.communicate(timeout=5)
            assert proc.returncode == 0, stderr
            calls = _load_calls(calls_log)
            assert ["-C", str(repo_dir), "pull", "--ff-only"] in calls
            assert stdout.count("=== Updating:") == 1
        finally:
            if proc.poll() is None:
                proc.terminate()
                proc.wait(timeout=5)
    finally:
        release_path.write_text("release", encoding="utf-8")
        lock_holder.wait(timeout=5)


def test_checkout_main_script_waits_for_repo_lock_before_checkout(tmp_path: Path) -> None:
    repo_root = tmp_path / "repos"
    repo_dir = repo_root / "demo"
    (repo_dir / ".git").mkdir(parents=True)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    calls_log = tmp_path / "calls.log"
    _write_fake_git(bin_dir)

    ready_path = tmp_path / "ready-checkout"
    release_path = tmp_path / "release-checkout"
    lock_holder = _start_repo_lock_holder(repo_dir, ready_path, release_path)
    try:
        assert _wait_for_path(ready_path)

        env = os.environ.copy()
        env["PATH"] = f"{bin_dir}:{env['PATH']}"
        env["CALLS_LOG"] = str(calls_log)
        env["ROOT"] = str(repo_root)

        proc = subprocess.Popen(
            ["bash", str(CHECKOUT_SCRIPT)],
            cwd=ROOT,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            assert _stays_call_free(calls_log)
            release_path.write_text("release", encoding="utf-8")
            stdout, stderr = proc.communicate(timeout=5)
            assert proc.returncode == 0, stderr
            calls = _load_calls(calls_log)
            assert [
                "-C",
                str(repo_dir),
                "symbolic-ref",
                "-q",
                "--short",
                "refs/remotes/origin/HEAD",
            ] in calls
            assert ["-C", str(repo_dir), "checkout", "main"] in calls
            assert stdout.count("=== Updating:") == 1
        finally:
            if proc.poll() is None:
                proc.terminate()
                proc.wait(timeout=5)
    finally:
        release_path.write_text("release", encoding="utf-8")
        lock_holder.wait(timeout=5)
