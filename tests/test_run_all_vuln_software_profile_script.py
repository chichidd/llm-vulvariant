import os
import stat
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run_all_vuln_software_profile.sh"


def _write_failing_software_profile(bin_dir: Path) -> None:
    fake_cmd = bin_dir / "software-profile"
    fake_cmd.write_text(
        "\n".join(
            [
                "#!/usr/bin/env bash",
                "set -euo pipefail",
                "exit 1",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    fake_cmd.chmod(fake_cmd.stat().st_mode | stat.S_IEXEC)


def test_run_all_vuln_software_profile_exits_non_zero_when_any_profile_fails(tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    _write_failing_software_profile(bin_dir)

    vuln_json = tmp_path / "vuln.json"
    vuln_json.write_text(
        '[{"repo_name":"demo","commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]\n',
        encoding="utf-8",
    )
    repo_base_path = tmp_path / "repos"
    (repo_base_path / "demo").mkdir(parents=True)
    output_dir = tmp_path / "profiles" / "soft"

    env = os.environ.copy()
    env["PATH"] = f"{bin_dir}:{env['PATH']}"
    result = subprocess.run(
        [
            "bash",
            str(SCRIPT),
            "--vuln-json",
            str(vuln_json),
            "--repo-base-path",
            str(repo_base_path),
            "--output-dir",
            str(output_dir),
        ],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 1
    assert "Failed: 1" in result.stdout


def test_run_all_vuln_software_profile_fails_when_vuln_json_is_invalid(tmp_path: Path) -> None:
    vuln_json = tmp_path / "vuln.json"
    vuln_json.write_text("{invalid json\n", encoding="utf-8")
    repo_base_path = tmp_path / "repos"
    repo_base_path.mkdir()
    output_dir = tmp_path / "profiles" / "soft"

    result = subprocess.run(
        [
            "bash",
            str(SCRIPT),
            "--vuln-json",
            str(vuln_json),
            "--repo-base-path",
            str(repo_base_path),
            "--output-dir",
            str(output_dir),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 1
    assert f"Error: failed to parse vuln.json: {vuln_json}" in result.stderr
    assert "No entries found in vuln.json" not in result.stdout


def test_run_all_vuln_software_profile_uses_repo_relative_defaults(tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    calls_log = tmp_path / "calls.log"
    fake_cmd = bin_dir / "software-profile"
    fake_cmd.write_text(
        "\n".join(
            [
                "#!/usr/bin/env bash",
                "set -euo pipefail",
                "python - \"$@\" <<'PY'",
                "import json",
                "import os",
                "import sys",
                "from pathlib import Path",
                "log_path = Path(os.environ['CALLS_LOG'])",
                "with log_path.open('a', encoding='utf-8') as handle:",
                "    handle.write(json.dumps(sys.argv[1:]) + '\\n')",
                "PY",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    fake_cmd.chmod(fake_cmd.stat().st_mode | stat.S_IEXEC)

    repo_root = tmp_path / "llm-vulvariant"
    project_root = tmp_path
    data_root = project_root / "data"
    profiles_root = project_root / "profiles"
    (data_root / "repos" / "demo").mkdir(parents=True)
    vuln_json = data_root / "vuln.json"
    vuln_json.write_text(
        '[{"repo_name":"demo","commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]\n',
        encoding="utf-8",
    )

    env = os.environ.copy()
    env["PATH"] = f"{bin_dir}:{env['PATH']}"
    env["CALLS_LOG"] = str(calls_log)
    env["_PROFILE_PATHS_REPO_ROOT"] = str(repo_root)
    result = subprocess.run(
        ["bash", str(SCRIPT)],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    calls = [
        line.strip()
        for line in calls_log.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(calls) == 1
    assert f"VULN_JSON:      {vuln_json}" in result.stdout
    assert str(data_root / "repos") in calls[0]
    assert str(profiles_root / "soft") in calls[0]
