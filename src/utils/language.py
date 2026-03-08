"""Centralised language configuration for multi-language support.

Every module that needs to know about programming-language-specific details
(file extensions, CodeQL packs, Docker base images, …) should import from
here instead of hard-coding values.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, List, Optional, Set


# ──────────────────────────────────────────────
#  Per-language configuration
# ──────────────────────────────────────────────

LANGUAGE_CONFIG: Dict[str, Dict] = {
    "python": {
        "extensions": {".py"},
        "codeql_pack": "codeql/python-all",
        "codeql_import": "import python",
        "docker_base": "python:3.11-slim",
        "build_cmd": (
            "pip install --no-cache-dir -r requirements.txt 2>/dev/null || "
            "pip install --no-cache-dir -e . 2>/dev/null || true"
        ),
        "run_cmd": "python3 /evidence/exploit.py",
        "indicator_files": {"setup.py", "pyproject.toml", "requirements.txt", "Pipfile"},
        "comment_prefix": "#",
    },
    "cpp": {
        "extensions": {".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".hh", ".hxx", ".cu", ".cuh"},
        "codeql_pack": "codeql/cpp-all",
        "codeql_import": "import cpp",
        "docker_base": "gcc:latest",
        "build_cmd": (
            "if [ -f CMakeLists.txt ]; then cmake -B build && cmake --build build; "
            "elif [ -f Makefile ]; then make; "
            "elif [ -f configure ]; then ./configure && make; "
            "else echo 'No build system detected'; fi"
        ),
        "run_cmd": "/evidence/exploit",
        "indicator_files": {"CMakeLists.txt", "Makefile", "configure", "meson.build"},
        "comment_prefix": "//",
    },
    "go": {
        "extensions": {".go"},
        "codeql_pack": "codeql/go-all",
        "codeql_import": "import go",
        "docker_base": "golang:1.22",
        "build_cmd": "go build ./...",
        "run_cmd": "/evidence/exploit",
        "indicator_files": {"go.mod", "go.sum"},
        "comment_prefix": "//",
    },
    "java": {
        "extensions": {".java"},
        "codeql_pack": "codeql/java-all",
        "codeql_import": "import java",
        "docker_base": "eclipse-temurin:21",
        "build_cmd": (
            "if [ -f pom.xml ]; then mvn -q package -DskipTests; "
            "elif [ -f build.gradle ]; then gradle build -x test; "
            "else javac -d /app/out $(find . -name '*.java'); fi"
        ),
        "run_cmd": "java -cp /evidence:/app/out Exploit",
        "indicator_files": {"pom.xml", "build.gradle", "build.gradle.kts"},
        "comment_prefix": "//",
    },
    "javascript": {
        "extensions": {".js", ".jsx", ".ts", ".tsx", ".mts", ".cts", ".mjs", ".cjs"},
        "codeql_pack": "codeql/javascript-all",
        "codeql_import": "import javascript",
        "docker_base": "node:20-slim",
        "build_cmd": (
            "if [ -f package-lock.json ]; then npm ci; "
            "elif [ -f yarn.lock ]; then yarn install --frozen-lockfile; "
            "elif [ -f pnpm-lock.yaml ]; then corepack enable && pnpm install; "
            "else npm install; fi"
        ),
        "run_cmd": "node /evidence/exploit.js",
        "indicator_files": {"package.json", "tsconfig.json"},
        "comment_prefix": "//",
    },
    "ruby": {
        "extensions": {".rb"},
        "codeql_pack": "codeql/ruby-all",
        "codeql_import": "import ruby",
        "docker_base": "ruby:3.3-slim",
        "build_cmd": "bundle install 2>/dev/null || true",
        "run_cmd": "ruby /evidence/exploit.rb",
        "indicator_files": {"Gemfile", "Rakefile"},
        "comment_prefix": "#",
    },
    "rust": {
        "extensions": {".rs"},
        "codeql_pack": None,  # CodeQL doesn't support Rust natively yet
        "codeql_import": None,
        "docker_base": "rust:1.77-slim",
        "build_cmd": "cargo build --release",
        "run_cmd": "/evidence/exploit",
        "indicator_files": {"Cargo.toml", "Cargo.lock"},
        "comment_prefix": "//",
    },
}

# All recognised source-code extensions (union of all languages)
ALL_SOURCE_EXTENSIONS: Set[str] = set()
for _cfg in LANGUAGE_CONFIG.values():
    ALL_SOURCE_EXTENSIONS |= _cfg["extensions"]


EXPLICITLY_UNSUPPORTED_SOURCE_EXTENSIONS: Set[str] = {".cs"}
IGNORED_LANGUAGE_DIRS = {
    ".git",
    "node_modules",
    "__pycache__",
    "build",
    "dist",
    ".tox",
    "venv",
    ".venv",
    "vendor",
    "third_party",
}


# ──────────────────────────────────────────────
#  Helper functions
# ──────────────────────────────────────────────

def get_extensions(language: str) -> Set[str]:
    """Return the set of file extensions for *language*."""
    cfg = LANGUAGE_CONFIG.get(language)
    if cfg is None:
        raise ValueError(f"Unsupported language: {language}")
    return cfg["extensions"]


def get_codeql_pack(language: str) -> Optional[str]:
    """Return the CodeQL qlpack dependency string (e.g. ``codeql/python-all``)."""
    cfg = LANGUAGE_CONFIG.get(language)
    if cfg is None:
        raise ValueError(f"Unsupported language: {language}")
    return cfg["codeql_pack"]


def get_run_cmd(language: str) -> str:
    """Return the default Docker run command for executing the PoC."""
    return LANGUAGE_CONFIG[language]["run_cmd"]


def _collect_language_scores(repo_path: Path) -> Dict[str, float]:
    """Collect weighted language scores."""
    scores: Dict[str, float] = {lang: 0.0 for lang in LANGUAGE_CONFIG}

    # Indicator-file bonus
    INDICATOR_WEIGHT = 15
    for lang, cfg in LANGUAGE_CONFIG.items():
        for indicator in cfg.get("indicator_files", set()):
            if (repo_path / indicator).exists():
                scores[lang] += INDICATOR_WEIGHT

    # Extension count (walk, skip ignored dirs)
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in IGNORED_LANGUAGE_DIRS]
        for fname in files:
            ext = Path(fname).suffix.lower()
            for lang, cfg in LANGUAGE_CONFIG.items():
                if ext in cfg["extensions"]:
                    scores[lang] += 1
                    break  # one file counted once

    return scores


def _has_explicitly_unsupported_sources(repo_path: Path) -> bool:
    """Return True when the repo contains source files for removed languages."""
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in IGNORED_LANGUAGE_DIRS]
        for fname in files:
            if Path(fname).suffix.lower() in EXPLICITLY_UNSUPPORTED_SOURCE_EXTENSIONS:
                return True
    return False


def detect_languages(repo_path: Path, limit: Optional[int] = None) -> List[str]:
    """Detect all programming languages present in a repository (ranked).

    Languages are ranked by indicator-file + extension-count score.
    """
    scores = _collect_language_scores(repo_path)
    ranked = [
        lang
        for lang, score in sorted(scores.items(), key=lambda item: (-item[1], item[0]))
        if score > 0
    ]
    if not ranked:
        if _has_explicitly_unsupported_sources(repo_path):
            return []
        ranked = ["python"]  # truly empty / unrecognised → safe fallback
    if limit is not None:
        return ranked[:max(limit, 0)]
    return ranked


def detect_language(repo_path: Path) -> str:
    """Detect the primary programming language of a repository.

    Strategy:
    1. Check for language-specific indicator files (weighted higher).
    2. Count source files by extension.
    3. Return the language with the highest score.
    4. Return ``"unknown"`` when the repo only contains explicitly unsupported
       source files, and ``"python"`` only for a truly empty/unrecognised repo.
    """
    ranked = detect_languages(repo_path, limit=1)
    return ranked[0] if ranked else "unknown"
