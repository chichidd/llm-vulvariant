import json
import os
import stat
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run_nvidia_full_pipeline.sh"
FAKE_GIT_HEAD = "a" * 40


def _write_fake_python(bin_dir: Path, name: str = "python") -> None:
    fake_python = bin_dir / name
    fake_python.write_text(
        "\n".join(
            [
                f"#!{sys.executable}",
                "import json",
                "import os",
                "import sys",
                "from pathlib import Path",
                "",
                "log_path = Path(os.environ['CALLS_LOG'])",
                "args = sys.argv[1:]",
                "if args and args[0] == '-':",
                "    if len(args) >= 3:",
                "        print(os.environ['FAKE_GIT_HEAD'])",
                "    raise SystemExit(0)",
                "with log_path.open('a', encoding='utf-8') as handle:",
                "    handle.write(json.dumps(args) + '\\n')",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    fake_python.chmod(fake_python.stat().st_mode | stat.S_IEXEC)


def _write_fake_timeout(bin_dir: Path) -> None:
    fake_timeout = bin_dir / "timeout"
    fake_timeout.write_text(
        "\n".join(
            [
                "#!/usr/bin/env bash",
                "set -euo pipefail",
                "shift",
                "\"$@\"",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    fake_timeout.chmod(fake_timeout.stat().st_mode | stat.S_IEXEC)


def _write_fake_conda(bin_dir: Path) -> None:
    fake_conda = bin_dir / "conda"
    fake_conda.write_text(
        "\n".join(
            [
                f"#!{sys.executable}",
                "import json",
                "import os",
                "import sys",
                "from pathlib import Path",
                "",
                "args = sys.argv[1:]",
                "if len(args) < 4 or args[:3] != ['run', '-n', 'custom-env'] or args[3] != 'python':",
                "    raise SystemExit(f'unexpected conda invocation: {args}')",
                "python_args = args[4:]",
                "log_path = Path(os.environ['CALLS_LOG'])",
                "if python_args and python_args[0] == '-':",
                "    if len(python_args) >= 3:",
                "        print(os.environ['FAKE_GIT_HEAD'])",
                "    raise SystemExit(0)",
                "with log_path.open('a', encoding='utf-8') as handle:",
                "    handle.write(json.dumps(python_args) + '\\n')",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    fake_conda.chmod(fake_conda.stat().st_mode | stat.S_IEXEC)


def _prepare_pipeline_root(tmp_path: Path) -> Path:
    pipeline_root = tmp_path / "pipeline-root"
    (pipeline_root / "llm-vulvariant").mkdir(parents=True)
    (pipeline_root / "data").mkdir(parents=True)
    (pipeline_root / "data" / "repos-nvidia" / "demo" / ".git").mkdir(parents=True)
    vuln_json = pipeline_root / "data" / "vuln.json"
    vuln_json.write_text(
        json.dumps(
            [
                {
                    "repo_name": "demo",
                    "commit": FAKE_GIT_HEAD,
                    "cve_id": "CVE-2026-0001",
                    "call_chain": [],
                }
            ]
        ),
        encoding="utf-8",
    )
    return pipeline_root


def _load_logged_calls(calls_log: Path) -> list[list[str]]:
    return [
        json.loads(line)
        for line in calls_log.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def test_run_nvidia_full_pipeline_has_valid_bash_syntax() -> None:
    result = subprocess.run(
        ["bash", "-n", str(SCRIPT)],
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr


def test_run_nvidia_full_pipeline_executes_expected_cli_commands(tmp_path: Path) -> None:
    pipeline_root = _prepare_pipeline_root(tmp_path)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    calls_log = tmp_path / "calls.log"
    _write_fake_python(bin_dir)
    _write_fake_timeout(bin_dir)

    env = os.environ.copy()
    env["PATH"] = f"{bin_dir}:{env['PATH']}"
    env["CALLS_LOG"] = str(calls_log)
    env["FAKE_GIT_HEAD"] = FAKE_GIT_HEAD
    env["ROOT"] = str(pipeline_root)
    env["SCAN_JOBS"] = "2"
    env["EXPLOITABILITY_JOBS"] = "2"
    env["EXPLOITABILITY_RUNTIME_MODE"] = "run"
    env["LLM_PROVIDER"] = "deepseek"
    env["LLM_NAME"] = "deepseek-chat"
    env["EXPLOITABILITY_TIMEOUT"] = "123"

    result = subprocess.run(
        ["bash", str(SCRIPT)],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    calls = _load_logged_calls(calls_log)

    software_call = next(call for call in calls if call[:3] == ["-m", "cli.software", "--repo-name"])
    batch_call = next(call for call in calls if call[:2] == ["-m", "cli.batch_scanner"])
    exploitability_call = next(call for call in calls if call[:2] == ["-m", "cli.exploitability"])

    assert "--target-version" in software_call
    assert FAKE_GIT_HEAD in software_call

    expected_batch_args = [
        "--vuln-json",
        str(pipeline_root / "data" / "vuln.json"),
        "--source-repos-root",
        str(pipeline_root / "data" / "repos"),
        "--source-soft-profiles-dir",
        str(pipeline_root / "profiles" / "soft"),
        "--target-repos-root",
        str(pipeline_root / "data" / "repos-nvidia"),
        "--target-soft-profiles-dir",
        str(pipeline_root / "profiles" / "soft-nvidia"),
        "--jobs",
        "2",
        "--llm-provider",
        "deepseek",
        "--llm-name",
        "deepseek-chat",
    ]
    positions = [batch_call.index(arg) for arg in expected_batch_args]
    assert positions == sorted(positions)
    assert "--repos-root" not in batch_call
    assert "--soft-profiles-dir" not in batch_call
    assert "--critical-stop-mode" in batch_call
    assert batch_call[batch_call.index("--critical-stop-mode") + 1] == "max"

    assert "--claude-runtime-mode" in exploitability_call
    assert exploitability_call[exploitability_call.index("--claude-runtime-mode") + 1] == "folder"
    assert "--timeout" in exploitability_call
    assert exploitability_call[exploitability_call.index("--timeout") + 1] == "123"


def test_run_nvidia_full_pipeline_uses_distinct_default_run_ids(tmp_path: Path) -> None:
    pipeline_root = _prepare_pipeline_root(tmp_path)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    calls_log = tmp_path / "calls.log"
    _write_fake_python(bin_dir)
    _write_fake_timeout(bin_dir)

    env = os.environ.copy()
    env["PATH"] = f"{bin_dir}:{env['PATH']}"
    env["CALLS_LOG"] = str(calls_log)
    env["FAKE_GIT_HEAD"] = FAKE_GIT_HEAD
    env["ROOT"] = str(pipeline_root)
    env["SCAN_JOBS"] = "1"
    env["EXPLOITABILITY_JOBS"] = "1"
    env["EXPLOITABILITY_RUNTIME_MODE"] = "folder"
    env["LLM_PROVIDER"] = "deepseek"

    first = subprocess.run(
        ["bash", str(SCRIPT)],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    second = subprocess.run(
        ["bash", str(SCRIPT)],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert first.returncode == 0, first.stderr
    assert second.returncode == 0, second.stderr

    status_logs = sorted(pipeline_root.glob("output-nvidia-status-*.log"))
    assert len(status_logs) == 2
    run_ids = {path.stem.removeprefix("output-nvidia-status-") for path in status_logs}
    assert len(run_ids) == 2


def test_run_nvidia_full_pipeline_uses_python3_when_python_alias_is_missing(tmp_path: Path) -> None:
    pipeline_root = _prepare_pipeline_root(tmp_path)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    calls_log = tmp_path / "calls.log"
    _write_fake_python(bin_dir, "python3")
    _write_fake_timeout(bin_dir)

    env = os.environ.copy()
    env["PATH"] = f"{bin_dir}:/bin"
    env["CALLS_LOG"] = str(calls_log)
    env["FAKE_GIT_HEAD"] = FAKE_GIT_HEAD
    env["ROOT"] = str(pipeline_root)
    env["SCAN_JOBS"] = "1"
    env["EXPLOITABILITY_JOBS"] = "1"
    env["EXPLOITABILITY_RUNTIME_MODE"] = "folder"
    env["LLM_PROVIDER"] = "deepseek"

    result = subprocess.run(
        ["bash", str(SCRIPT)],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    calls = _load_logged_calls(calls_log)
    assert any(call[:2] == ["-m", "cli.batch_scanner"] for call in calls)


def test_run_nvidia_full_pipeline_supports_multiword_python_bin(tmp_path: Path) -> None:
    pipeline_root = _prepare_pipeline_root(tmp_path)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    calls_log = tmp_path / "calls.log"
    _write_fake_conda(bin_dir)
    _write_fake_timeout(bin_dir)

    env = os.environ.copy()
    env["PATH"] = f"{bin_dir}:{env['PATH']}"
    env["CALLS_LOG"] = str(calls_log)
    env["FAKE_GIT_HEAD"] = FAKE_GIT_HEAD
    env["ROOT"] = str(pipeline_root)
    env["SCAN_JOBS"] = "1"
    env["EXPLOITABILITY_JOBS"] = "1"
    env["EXPLOITABILITY_RUNTIME_MODE"] = "folder"
    env["LLM_PROVIDER"] = "deepseek"
    env["PYTHON_BIN"] = "conda run -n custom-env python"

    result = subprocess.run(
        ["bash", str(SCRIPT)],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    calls = _load_logged_calls(calls_log)
    assert any(call[:2] == ["-m", "cli.batch_scanner"] for call in calls)
