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
