import os
import shutil
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "profile_paths.sh"


def test_profile_realpath_fallback_anchors_relative_paths_to_repo_root(tmp_path):
    launch_dir = tmp_path / "launch"
    nested_dir = tmp_path / "nested"
    repo_root = tmp_path / "repo-root"
    launch_dir.mkdir()
    nested_dir.mkdir()
    repo_root.mkdir()

    env = os.environ.copy()
    env["PATH"] = ""
    env["_PROFILE_PATHS_REPO_ROOT"] = str(repo_root)
    bash_path = shutil.which("bash") or "/bin/bash"
    result = subprocess.run(
        [
            bash_path,
            "-c",
            f'. "{SCRIPT}"; cd "{nested_dir}"; _profile_realpath "profiles/soft"',
        ],
        cwd=launch_dir,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == str(repo_root / "profiles" / "soft")
