from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run_nvidia_full_pipeline.sh"


def test_run_nvidia_full_pipeline_passes_source_inputs_to_batch_scanner():
    script_text = SCRIPT.read_text(encoding="utf-8")
    required_args = [
        "python -m cli.batch_scanner",
        '--vuln-json "$VULN_JSON"',
        '--source-repos-root "$SOURCE_REPOS_ROOT"',
        '--source-soft-profiles-dir "$SOURCE_REPO_PROFILES"',
        '--target-repos-root "$REPOS_NVIDIA"',
        '--target-soft-profiles-dir "$REPO_PROFILES_NVIDIA"',
    ]

    positions = [script_text.index(arg) for arg in required_args]
    assert positions == sorted(positions)
    assert '--repos-root "$REPOS_NVIDIA"' not in script_text
    assert '--soft-profiles-dir "$REPO_PROFILES_NVIDIA"' not in script_text


def test_run_nvidia_full_pipeline_uses_env_overrides_for_provider_and_timeout():
    script_text = SCRIPT.read_text(encoding="utf-8")

    assert 'LLM_PROVIDER="${LLM_PROVIDER:-deepseek}"' in script_text
    assert 'LLM_NAME="${LLM_NAME:-}"' in script_text
    assert 'EXPLOITABILITY_TIMEOUT="${EXPLOITABILITY_TIMEOUT:-1800}"' in script_text
    assert '--llm-provider "$LLM_PROVIDER"' in script_text
    assert '--timeout "$EXPLOITABILITY_TIMEOUT"' in script_text
