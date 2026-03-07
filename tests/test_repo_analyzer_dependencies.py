from pathlib import Path

from profiler.software.repo_analyzer import CodeLocation, DependencyInfo, RepoAnalyzer


def _build_analyzer(repo_path: Path, language: str = "python") -> RepoAnalyzer:
    analyzer = RepoAnalyzer.__new__(RepoAnalyzer)
    analyzer.repo_path = repo_path
    analyzer.languages = [language]
    analyzer._dependencies = {}
    return analyzer


def test_analyze_dependencies_resets_previous_dependency_state(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("import os\n", encoding="utf-8")

    analyzer = _build_analyzer(repo)
    analyzer._dependencies = {
        "stale_dependency": DependencyInfo(
            name="stale_dependency",
            import_locations=[CodeLocation(file="legacy.py", line=99)],
        )
    }

    analyzer._analyze_dependencies()

    assert "stale_dependency" not in analyzer._dependencies
    assert "os" in analyzer._dependencies
    assert len(analyzer._dependencies["os"].import_locations) == 1


def test_analyze_dependencies_is_stable_across_repeated_runs(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("import os\n", encoding="utf-8")

    analyzer = _build_analyzer(repo)
    analyzer._analyze_dependencies()
    first_count = len(analyzer._dependencies["os"].import_locations)

    analyzer._analyze_dependencies()
    second_count = len(analyzer._dependencies["os"].import_locations)

    assert first_count == 1
    assert second_count == 1


def test_analyze_dependencies_resets_cpp_include_cache_between_runs(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "main.cpp").write_text('#include "utils/log.h"\n', encoding="utf-8")

    analyzer = _build_analyzer(repo, language="cpp")
    analyzer._analyze_dependencies()
    assert "utils" in analyzer._dependencies

    (repo / "utils").mkdir()
    (repo / "utils" / "log.h").write_text("// local header\n", encoding="utf-8")
    analyzer._analyze_dependencies()

    assert "utils" not in analyzer._dependencies


def test_analyze_dependencies_resets_go_module_cache_between_runs(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "main.go").write_text(
        'package main\n'
        'import "github.com/acme/repo/internal/config"\n',
        encoding="utf-8",
    )
    (repo / "go.mod").write_text("module github.com/acme/other\n\ngo 1.21\n", encoding="utf-8")

    analyzer = _build_analyzer(repo, language="go")
    analyzer._analyze_dependencies()
    assert "github.com/acme/repo/internal/config" in analyzer._dependencies

    (repo / "go.mod").write_text("module github.com/acme/repo\n\ngo 1.21\n", encoding="utf-8")
    analyzer._analyze_dependencies()

    assert "github.com/acme/repo/internal/config" not in analyzer._dependencies


def test_analyze_dependencies_extracts_cpp_headers(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "utils").mkdir()
    (repo / "main.cpp").write_text(
        '#include <vector>\n'
        '#include "glog/logging.h"\n'
        '#include "utils/log.h"\n'
        '#include "../internal/local.hpp"\n'
        '#include "repo.hpp"\n'
        '#include "3rdparty/cutlass/include/cutlass/gemm.h"\n',
        encoding="utf-8",
    )
    (repo / "repo.hpp").write_text("// local header\n", encoding="utf-8")
    (repo / "utils" / "log.h").write_text("// local header\n", encoding="utf-8")
    (repo / "internal").mkdir()
    (repo / "internal" / "local.hpp").write_text("// local header\n", encoding="utf-8")

    analyzer = _build_analyzer(repo, language="cpp")
    analyzer._analyze_dependencies()

    assert "vector" in analyzer._dependencies
    assert "glog" in analyzer._dependencies
    assert "cutlass" in analyzer._dependencies
    assert ".." not in analyzer._dependencies
    assert "repo" not in analyzer._dependencies
    assert "utils" not in analyzer._dependencies


def test_analyze_dependencies_classifies_cpp_stdlib_as_builtin(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "main.cpp").write_text(
        '#include <stdio.h>\n'
        '#include <vector>\n'
        '#include <string>\n'
        '#include <cuda_runtime.h>\n',
        encoding="utf-8",
    )

    analyzer = _build_analyzer(repo, language="cpp")
    analyzer._analyze_dependencies()

    assert "stdio" in analyzer._dependencies
    assert "vector" in analyzer._dependencies
    assert "string" in analyzer._dependencies
    assert analyzer._dependencies["stdio"].is_builtin is True
    assert analyzer._dependencies["vector"].is_builtin is True
    assert analyzer._dependencies["string"].is_builtin is True
    assert analyzer._dependencies["cuda_runtime"].is_builtin is False
    assert analyzer._dependencies["cuda_runtime"].is_third_party is True


def test_analyze_dependencies_filters_repo_namespace_in_cpp(tmp_path):
    repo = tmp_path / "TensorRT-LLM"
    repo.mkdir()
    (repo / "main.cpp").write_text(
        '#include <tensorrt_llm/runtime/model.h>\n'
        '#include <cuda_runtime.h>\n',
        encoding="utf-8",
    )

    analyzer = _build_analyzer(repo, language="cpp")
    analyzer._analyze_dependencies()

    assert "tensorrt_llm" not in analyzer._dependencies
    assert "cuda_runtime" in analyzer._dependencies


def test_analyze_dependencies_filters_numeric_and_experiment_cpp_names(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "main.cpp").write_text(
        '#include <63_hopper_gemm_with_weight_prefetch/gemm.h>\n'
        '#include <2022_03_21__fp8_stride_batch_example/worker.hpp>\n'
        '#include <benchmarks/micro_bench.hpp>\n'
        '#include <cutlass/gemm.h>\n',
        encoding="utf-8",
    )

    analyzer = _build_analyzer(repo, language="cpp")
    analyzer._analyze_dependencies()

    assert "63_hopper_gemm_with_weight_prefetch" not in analyzer._dependencies
    assert "2022_03_21__fp8_stride_batch_example" not in analyzer._dependencies
    assert "benchmarks" not in analyzer._dependencies
    assert "cutlass" in analyzer._dependencies


def test_analyze_dependencies_extracts_go_imports_and_strips_quotes(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "go.mod").write_text("module github.com/acme/repo\n\ngo 1.21\n", encoding="utf-8")
    (repo / "main.go").write_text(
        'package main\n'
        'import "fmt"\n'
        'import (\n'
        '    "context"\n'
        '    "github.com/acme/repo/internal/config"\n'
        '    alias "github.com/pkg/errors"\n'
        ')\n',
        encoding="utf-8",
    )

    analyzer = _build_analyzer(repo, language="go")
    analyzer._analyze_dependencies()

    assert "fmt" in analyzer._dependencies
    assert "context" in analyzer._dependencies
    assert "github.com/pkg/errors" in analyzer._dependencies
    assert "github.com/acme/repo/internal/config" not in analyzer._dependencies
    assert '"fmt"' not in analyzer._dependencies
    assert analyzer._dependencies["fmt"].is_builtin is True
    assert analyzer._dependencies["github.com/pkg/errors"].is_builtin is False


def test_analyze_dependencies_extracts_javascript_imports(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.js").write_text(
        "const express = require('express')\n"
        "// import nope from 'left-pad'\n"
        "/* require('lodash') */\n"
        "/*\n"
        "import disabled from 'comment-only'\n"
        "*/\n"
        "import fs from 'fs'\n"
        "import { parse } from '@scope/pkg/submodule'\n"
        "import './local'\n",
        encoding="utf-8",
    )

    analyzer = _build_analyzer(repo, language="javascript")
    analyzer._analyze_dependencies()

    assert "express" in analyzer._dependencies
    assert "fs" in analyzer._dependencies
    assert "@scope/pkg" in analyzer._dependencies
    assert "left-pad" not in analyzer._dependencies
    assert "lodash" not in analyzer._dependencies
    assert "comment-only" not in analyzer._dependencies
    assert "./local" not in analyzer._dependencies


def test_analyze_dependencies_ignores_javascript_import_like_strings(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.js").write_text(
        "const snippet1 = \"import fake from 'left-pad'\";\n"
        "const snippet2 = \"require('lodash')\";\n"
        "const express = require('express')\n"
        "import fs from 'fs'\n",
        encoding="utf-8",
    )

    analyzer = _build_analyzer(repo, language="javascript")
    analyzer._analyze_dependencies()

    assert "express" in analyzer._dependencies
    assert "fs" in analyzer._dependencies
    assert "left-pad" not in analyzer._dependencies
    assert "lodash" not in analyzer._dependencies


def test_analyze_dependencies_extracts_dynamic_import_and_spaced_require(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.js").write_text(
        "const dep = require ('axios')\n"
        "const mod = import('dayjs')\n",
        encoding="utf-8",
    )

    analyzer = _build_analyzer(repo, language="javascript")
    analyzer._analyze_dependencies()

    assert "axios" in analyzer._dependencies
    assert "dayjs" in analyzer._dependencies


def test_analyze_dependencies_ignores_javascript_regex_literals(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.js").write_text(
        "const r = /import x from 'left-pad'/\n"
        "const re = /require\\('lodash'\\)/g\n"
        "import fs from 'fs'\n",
        encoding="utf-8",
    )

    analyzer = _build_analyzer(repo, language="javascript")
    analyzer._analyze_dependencies()

    assert "fs" in analyzer._dependencies
    assert "left-pad" not in analyzer._dependencies
    assert "lodash" not in analyzer._dependencies


def test_analyze_dependencies_extracts_rust_and_ruby_imports(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "lib.rs").write_text(
        "use serde_json::Value;\nextern crate anyhow as ah;\n",
        encoding="utf-8",
    )
    (repo / "app.rb").write_text(
        'require "json"\nrequire_relative "lib/utils"\n',
        encoding="utf-8",
    )

    rust_analyzer = _build_analyzer(repo, language="rust")
    rust_analyzer._analyze_dependencies()
    assert "serde_json" in rust_analyzer._dependencies
    assert "anyhow" in rust_analyzer._dependencies

    ruby_analyzer = _build_analyzer(repo, language="ruby")
    ruby_analyzer._analyze_dependencies()
    assert "json" in ruby_analyzer._dependencies
    assert "lib" not in ruby_analyzer._dependencies


def test_analyze_dependencies_extracts_java_imports(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "Main.java").write_text(
        "import java.util.List;\n"
        "import static com.google.common.base.Preconditions.checkNotNull;\n",
        encoding="utf-8",
    )

    analyzer = _build_analyzer(repo, language="java")
    analyzer._analyze_dependencies()

    assert "java" in analyzer._dependencies
    assert "com" in analyzer._dependencies
