import json
import os
import stat
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run_all_software_profiles.sh"


def _write_fake_software_profile(bin_dir: Path, calls_log: Path) -> None:
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


def _run_script(launch_dir: Path, path_root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PATH"] = f"{path_root / 'bin'}:{env['PATH']}"
    env["CALLS_LOG"] = str(path_root / "calls.log")
    return subprocess.run(
        ["bash", str(SCRIPT), *args],
        cwd=launch_dir,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def test_run_all_software_profiles_anchors_relative_profile_base_to_launch_dir(tmp_path: Path) -> None:
    launch_dir = tmp_path / "launch"
    launch_dir.mkdir()
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    calls_log = tmp_path / "calls.log"
    _write_fake_software_profile(bin_dir, calls_log)

    repo_dir = launch_dir / "repos" / "demo"
    (repo_dir / ".git").mkdir(parents=True)

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
            str(launch_dir / "profiles"),
            "--software-profile-dirname",
            "soft-custom",
            "--repo-base-path",
            str(launch_dir / "repos"),
            "--repo-name",
            "demo",
        ]
    ]
