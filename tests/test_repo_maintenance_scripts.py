from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_update_repos_script_uses_script_relative_default_root() -> None:
    script_text = (ROOT / "scripts" / "update_repos.sh").read_text(encoding="utf-8")

    assert 'ROOT="${ROOT:-$SCRIPT_DIR/../../data/repos}"' in script_text
    assert 'ERROR: repo root not found:' in script_text


def test_checkout_main_script_uses_script_relative_default_root() -> None:
    script_text = (ROOT / "scripts" / "checkout_main.sh").read_text(encoding="utf-8")

    assert 'ROOT="${ROOT:-$SCRIPT_DIR/../../data/repos}"' in script_text
    assert 'ERROR: repo root not found:' in script_text
