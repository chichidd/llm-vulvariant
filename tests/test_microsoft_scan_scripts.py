import json
import os
import stat
import subprocess
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
FULL_SCRIPT = ROOT / "scripts" / "run_microsoft_scan_full.sh"


def _require_bash() -> str:
    if os.name != "posix":
        pytest.skip("requires POSIX shell environment")
    bash_path = shutil.which("bash")
    if bash_path is None:
        pytest.skip("requires bash in PATH")
    return bash_path


def _require_script_runtime() -> str:
    bash_path = _require_bash()
    probe = subprocess.run(
        ["date", "-Iseconds"],
        text=True,
        capture_output=True,
        check=False,
    )
    if probe.returncode != 0:
        pytest.skip("requires date -Iseconds support")
    return bash_path


def _write_fake_python(bin_dir: Path, name: str = "python") -> Path:
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
                "with log_path.open('a', encoding='utf-8') as handle:",
                "    handle.write(json.dumps(args) + '\\n')",
                "if args[:2] == ['-m', 'cli.batch_scanner'] and os.environ.get('FAKE_BATCH_SCANNER_EXIT'):",
                "    scan_output = Path(args[args.index('--scan-output-dir') + 1])",
                "    if os.environ.get('FAKE_BATCH_SCANNER_WRITE_PARTIAL') == '1':",
                "        out = scan_output / 'CVE-TEST' / 'demo-repo-abcdef123456'",
                "        out.mkdir(parents=True, exist_ok=True)",
                "        (out / 'agentic_vuln_findings.json').write_text('{\"vulnerabilities\": []}', encoding='utf-8')",
                "    raise SystemExit(int(os.environ['FAKE_BATCH_SCANNER_EXIT']))",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    fake_python.chmod(fake_python.stat().st_mode | stat.S_IEXEC)
    return fake_python


def _fake_python_bin(fake_python: Path) -> str:
    return f"{sys.executable} {fake_python}"


def _prepare_pipeline_root(tmp_path: Path) -> Path:
    pipeline_root = tmp_path / "pipeline-root"
    (pipeline_root / "llm-vulvariant").mkdir(parents=True)
    (pipeline_root / "data" / "repos").mkdir(parents=True)
    (pipeline_root / "data" / "repos-microsoft").mkdir(parents=True)
    (pipeline_root / "profiles").mkdir(parents=True)
    vuln_json = pipeline_root / "data" / "vuln.json"
    vuln_json.write_text("[]", encoding="utf-8")
    return pipeline_root


def _prepare_repo_root(tmp_path: Path) -> Path:
    repo_root = tmp_path / "repo-root"
    (repo_root / "data" / "repos").mkdir(parents=True)
    (repo_root / "data" / "repos-microsoft").mkdir(parents=True)
    (repo_root / "profiles").mkdir(parents=True)
    vuln_json = repo_root / "data" / "vuln.json"
    vuln_json.write_text("[]", encoding="utf-8")
    return repo_root


def _load_logged_calls(calls_log: Path) -> list[list[str]]:
    return [
        json.loads(line)
        for line in calls_log.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def test_run_microsoft_scan_smoke_script_is_removed() -> None:
    assert not (ROOT / "scripts" / "run_microsoft_scan_smoke.sh").exists()


def test_run_microsoft_scan_full_has_valid_bash_syntax() -> None:
    bash_path = _require_bash()
    result = subprocess.run(
        [bash_path, "-n", str(FULL_SCRIPT)],
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def test_run_microsoft_scan_full_executes_scan_and_exploitability(tmp_path: Path) -> None:
    bash_path = _require_script_runtime()
    pipeline_root = _prepare_pipeline_root(tmp_path)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    calls_log = tmp_path / "calls.log"
    fake_python = _write_fake_python(bin_dir)

    env = os.environ.copy()
    env["CALLS_LOG"] = str(calls_log)
    env["ROOT"] = str(pipeline_root)
    env["RUN_TAG"] = "20260406-000000"
    env["PYTHON_BIN"] = _fake_python_bin(fake_python)
    env["LLM_PROVIDER"] = "deepseek"
    env["LLM_NAME"] = "deepseek-chat"
    env["EXPLOITABILITY_JOBS"] = "2"
    env["EXPLOITABILITY_RUNTIME_MODE"] = "run"
    env["EXPLOITABILITY_TIMEOUT"] = "321"

    result = subprocess.run(
        [bash_path, str(FULL_SCRIPT)],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    calls = _load_logged_calls(calls_log)
    assert sum(call[:2] == ["-m", "cli.exploitability"] for call in calls) == 1

    batch_call = next(call for call in calls if call[:2] == ["-m", "cli.batch_scanner"])
    exploitability_call = next(call for call in calls if call[:2] == ["-m", "cli.exploitability"])

    assert "--target-repos-root" in batch_call
    assert batch_call[batch_call.index("--target-repos-root") + 1] == str(
        pipeline_root / "data" / "repos-microsoft"
    )
    assert "--target-soft-profiles-dir" in batch_call
    assert batch_call[batch_call.index("--target-soft-profiles-dir") + 1] == str(
        pipeline_root / "profiles" / "soft-microsoft"
    )
    assert "--scan-all-profiled-targets" in batch_call
    assert "--max-workers" in batch_call
    assert batch_call[batch_call.index("--max-workers") + 1] == "8"
    assert "--scan-workers" in batch_call
    assert batch_call[batch_call.index("--scan-workers") + 1] == "8"
    assert "--target-scan-timeout" in batch_call
    assert batch_call[batch_call.index("--target-scan-timeout") + 1] == "7200"

    assert "--scan-results-dir" in exploitability_call
    assert exploitability_call[exploitability_call.index("--scan-results-dir") + 1] == str(
        pipeline_root / "results" / "scan-microsoft-full-20260406-000000"
    )
    assert "--repo-base-path" in exploitability_call
    assert exploitability_call[exploitability_call.index("--repo-base-path") + 1] == str(
        pipeline_root / "data" / "repos-microsoft"
    )
    assert "--soft-profile-dir" in exploitability_call
    assert exploitability_call[exploitability_call.index("--soft-profile-dir") + 1] == str(
        pipeline_root / "profiles" / "soft-microsoft"
    )
    assert "--generate-report" in exploitability_call
    assert "--report-only-exploitable" in exploitability_call
    assert "--submission-output-dir" in exploitability_call
    assert exploitability_call[exploitability_call.index("--submission-output-dir") + 1] == str(
        pipeline_root / "results" / "exploitability-microsoft-full-20260406-000000"
    )
    assert "--claude-runtime-mode" in exploitability_call
    assert exploitability_call[exploitability_call.index("--claude-runtime-mode") + 1] == "folder"
    assert "--run-id" in exploitability_call
    assert exploitability_call[exploitability_call.index("--run-id") + 1] == "microsoft-full-20260406-000000"
    assert "--timeout" in exploitability_call
    assert exploitability_call[exploitability_call.index("--timeout") + 1] == "321"


def test_run_microsoft_scan_full_accepts_repo_root_without_nested_llm_vulvariant_dir(
    tmp_path: Path,
) -> None:
    bash_path = _require_script_runtime()
    repo_root = _prepare_repo_root(tmp_path)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    calls_log = tmp_path / "calls.log"
    fake_python = _write_fake_python(bin_dir)

    env = os.environ.copy()
    env["CALLS_LOG"] = str(calls_log)
    env["ROOT"] = str(repo_root)
    env["RUN_TAG"] = "20260408-000000"
    env["PYTHON_BIN"] = _fake_python_bin(fake_python)
    env["LLM_PROVIDER"] = "deepseek"
    env["LLM_NAME"] = "deepseek-chat"

    result = subprocess.run(
        [bash_path, str(FULL_SCRIPT)],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    calls = _load_logged_calls(calls_log)
    assert any(call[:2] == ["-m", "cli.batch_scanner"] for call in calls)


def test_run_microsoft_scan_full_uses_default_provider_and_empty_model_when_unset(tmp_path: Path) -> None:
    bash_path = _require_script_runtime()
    pipeline_root = _prepare_pipeline_root(tmp_path)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    calls_log = tmp_path / "calls.log"
    fake_python = _write_fake_python(bin_dir)

    env = os.environ.copy()
    env["CALLS_LOG"] = str(calls_log)
    env["ROOT"] = str(pipeline_root)
    env["PYTHON_BIN"] = _fake_python_bin(fake_python)
    env.pop("LLM_PROVIDER", None)
    env.pop("LLM_NAME", None)
    env["RUN_TAG"] = "20260408-010000"

    result = subprocess.run(
        [bash_path, str(FULL_SCRIPT)],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    calls = _load_logged_calls(calls_log)
    batch_call = next(call for call in calls if call[:2] == ["-m", "cli.batch_scanner"])

    assert "--llm-provider" in batch_call
    assert batch_call[batch_call.index("--llm-provider") + 1] == "lab"
    assert "--llm-name" in batch_call
    assert batch_call[batch_call.index("--llm-name") + 1] == ""


def test_run_microsoft_scan_full_default_run_id_is_unique_when_run_tag_unset(tmp_path: Path) -> None:
    bash_path = _require_script_runtime()
    pipeline_root = _prepare_pipeline_root(tmp_path)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake_python = _write_fake_python(bin_dir)

    def _run_once(calls_log: Path) -> str:
        env = os.environ.copy()
        env["CALLS_LOG"] = str(calls_log)
        env["ROOT"] = str(pipeline_root)
        env["PYTHON_BIN"] = _fake_python_bin(fake_python)
        env.pop("RUN_TAG", None)

        result = subprocess.run(
            [bash_path, str(FULL_SCRIPT)],
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )

        assert result.returncode == 0, result.stderr
        calls = _load_logged_calls(calls_log)
        exploitability_call = next(call for call in calls if call[:2] == ["-m", "cli.exploitability"])
        return exploitability_call[exploitability_call.index("--run-id") + 1]

    first_run_id = _run_once(tmp_path / "calls-1.log")
    second_run_id = _run_once(tmp_path / "calls-2.log")

    assert first_run_id.startswith("microsoft-full-")
    assert second_run_id.startswith("microsoft-full-")
    assert first_run_id != second_run_id


def test_run_microsoft_scan_full_aborts_on_scan_failure_even_with_partial_outputs(tmp_path: Path) -> None:
    bash_path = _require_script_runtime()
    pipeline_root = _prepare_pipeline_root(tmp_path)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    calls_log = tmp_path / "calls.log"
    fake_python = _write_fake_python(bin_dir)

    env = os.environ.copy()
    env["CALLS_LOG"] = str(calls_log)
    env["ROOT"] = str(pipeline_root)
    env["RUN_TAG"] = "20260408-020000"
    env["PYTHON_BIN"] = _fake_python_bin(fake_python)
    env["FAKE_BATCH_SCANNER_EXIT"] = "7"
    env["FAKE_BATCH_SCANNER_WRITE_PARTIAL"] = "1"

    result = subprocess.run(
        [bash_path, str(FULL_SCRIPT)],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 7
    calls = _load_logged_calls(calls_log)
    assert any(call[:2] == ["-m", "cli.batch_scanner"] for call in calls)
    assert not any(call[:2] == ["-m", "cli.exploitability"] for call in calls)
    assert "abort before exploitability" in result.stdout


def test_run_microsoft_scan_full_allows_partial_exploitability_when_explicitly_enabled(tmp_path: Path) -> None:
    bash_path = _require_script_runtime()
    pipeline_root = _prepare_pipeline_root(tmp_path)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    calls_log = tmp_path / "calls.log"
    fake_python = _write_fake_python(bin_dir)

    env = os.environ.copy()
    env["CALLS_LOG"] = str(calls_log)
    env["ROOT"] = str(pipeline_root)
    env["RUN_TAG"] = "20260408-030000"
    env["PYTHON_BIN"] = _fake_python_bin(fake_python)
    env["FAKE_BATCH_SCANNER_EXIT"] = "7"
    env["FAKE_BATCH_SCANNER_WRITE_PARTIAL"] = "1"
    env["ALLOW_PARTIAL_EXPLOITABILITY"] = "1"

    result = subprocess.run(
        [bash_path, str(FULL_SCRIPT)],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 7
    calls = _load_logged_calls(calls_log)
    assert any(call[:2] == ["-m", "cli.exploitability"] for call in calls)
    assert "Partial exploitability explicitly allowed" in result.stdout
