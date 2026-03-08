# AGENTS.md

## Important Principles

- **不需要后向兼容**: 修改代码时不用考虑后向兼容性。对于已有的结果文件（JSON/CSV 等），可以直接修改结果格式来兼容最新的代码，不需要写兼容旧格式的适配层。
- **不要过度设计**: 只做被要求的改动，不要添加额外的抽象层、不必要的错误处理、或"以防万一"的兼容代码。
- **先读后改**: 修改任何文件前，先读取并理解其完整上下文，不要基于猜测修改。

## Environment

- The project uses conda environment `dsocr`. Activate by `conda activate dsocr` before using python.
- If you need to install new packages, make sure to activate the conda environment `dsocr` first, then use pip to install.

## Coding Conventions (llm-vulvariant)

### Python Style
- Use type hints on all function parameters and return types (`Optional[T]`, `List[T]`, `Dict[K,V]`)
- Use `from __future__ import annotations` for forward references
- Use Google-style docstrings (Args/Returns sections)
- Import order: `__future__` → stdlib → third-party → project modules

### Data Structures
- Use `@dataclass` with `to_dict()` / `from_dict()` round-trip pattern
- Use `@dataclass(frozen=True)` for immutable value types
- Use `field(default_factory=list)` for mutable defaults

### File I/O
- Always use `pathlib.Path`, not `os.path`
- Always specify `encoding='utf-8'`
- JSON: `json.loads(path.read_text(encoding='utf-8'))` / `path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding='utf-8')`
- Use `path.mkdir(parents=True, exist_ok=True)` for directory creation

### Logging
- Use project's `setup_logger(name)` / `get_logger(name)` from `utils/logging_utils.py`
- Format: `%(asctime)s - %(name)s - %(levelname)s - %(message)s`
- No print statements for non-CLI output; use logger

### CLI Modules
- Follow pattern: `parse_args()` → `main() -> int` → `if __name__ == "__main__": raise SystemExit(main())`
- Use try/except ImportError fallback for direct script execution vs package import

### Configuration
- YAML configs in `config/` directory, loaded via `config.py`
- Use `Path(string).expanduser()` for home-relative paths

### LLM Integration
- Use `LLMConfig` + `create_llm_client()` factory pattern
- Track LLM usage with `capture_llm_usage_snapshot()` / `aggregate_llm_usage_since()`
- Parse responses with `extract_message_content()` / `_extract_json_candidates()`
