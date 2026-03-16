from scanner.agent import toolkit as toolkit_module


class _FakeCodeQLAnalyzer:
    def __init__(self, *args, **kwargs):
        self.is_available = True


def test_get_function_code_skips_call_site_before_definition(tmp_path, monkeypatch):
    repo_path = tmp_path / "repo"
    repo_path.mkdir()

    source_file = repo_path / "entry.ts"
    source_file.write_text(
        "\n".join(
            [
                "const value = loadSettings();",
                "",
                "function loadSettings(): UiSettings {",
                "  return defaults;",
                "}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        toolkit_module,
        "_path_config",
        {
            "repo_root": tmp_path,
            "codeql_db_path": tmp_path / "codeql-dbs",
        },
    )
    monkeypatch.setattr(toolkit_module, "CodeQLAnalyzer", _FakeCodeQLAnalyzer)

    toolkit = toolkit_module.AgenticToolkit(repo_path=repo_path, languages=["javascript"])
    result = toolkit._get_function_code(source_file.name, "loadSettings")

    assert result.success is True
    assert "function loadSettings(): UiSettings {" in result.content
    assert "const value = loadSettings();" not in result.content


def test_get_function_code_matches_java_annotation_prefixed_declaration(tmp_path, monkeypatch):
    repo_path = tmp_path / "repo"
    repo_path.mkdir()

    source_file = repo_path / "Service.java"
    source_file.write_text(
        "\n".join(
            [
                "@Transactional public void handle() {",
                "  process();",
                "}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        toolkit_module,
        "_path_config",
        {
            "repo_root": tmp_path,
            "codeql_db_path": tmp_path / "codeql-dbs",
        },
    )
    monkeypatch.setattr(toolkit_module, "CodeQLAnalyzer", _FakeCodeQLAnalyzer)

    toolkit = toolkit_module.AgenticToolkit(repo_path=repo_path, languages=["java"])
    result = toolkit._get_function_code(source_file.name, "handle")

    assert result.success is True
    assert "@Transactional public void handle() {" in result.content


def test_get_function_code_matches_qualified_return_type(tmp_path, monkeypatch):
    repo_path = tmp_path / "repo"
    repo_path.mkdir()

    source_file = repo_path / "Service.cs"
    source_file.write_text(
        "\n".join(
            [
                "System.Threading.Tasks.Task DoWork() {",
                "  return Task.CompletedTask;",
                "}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        toolkit_module,
        "_path_config",
        {
            "repo_root": tmp_path,
            "codeql_db_path": tmp_path / "codeql-dbs",
        },
    )
    monkeypatch.setattr(toolkit_module, "CodeQLAnalyzer", _FakeCodeQLAnalyzer)

    toolkit = toolkit_module.AgenticToolkit(repo_path=repo_path, languages=["csharp"])
    result = toolkit._get_function_code(source_file.name, "DoWork")

    assert result.success is True
    assert "System.Threading.Tasks.Task DoWork() {" in result.content
    assert "return Task.CompletedTask;" in result.content


def test_get_function_code_matches_csharp_attribute_list_prefixed_declaration(tmp_path, monkeypatch):
    repo_path = tmp_path / "repo"
    repo_path.mkdir()

    source_file = repo_path / "Service.cs"
    source_file.write_text(
        "\n".join(
            [
                "[Foo, Bar] public void Handle() {",
                "  Process();",
                "}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        toolkit_module,
        "_path_config",
        {
            "repo_root": tmp_path,
            "codeql_db_path": tmp_path / "codeql-dbs",
        },
    )
    monkeypatch.setattr(toolkit_module, "CodeQLAnalyzer", _FakeCodeQLAnalyzer)

    toolkit = toolkit_module.AgenticToolkit(repo_path=repo_path, languages=["csharp"])
    result = toolkit._get_function_code(source_file.name, "Handle")

    assert result.success is True
    assert "[Foo, Bar] public void Handle() {" in result.content
    assert "Process();" in result.content


def test_get_function_code_skips_split_line_call_site_before_template_return_type_definition(tmp_path, monkeypatch):
    repo_path = tmp_path / "repo"
    repo_path.mkdir()

    source_file = repo_path / "service.cpp"
    source_file.write_text(
        "\n".join(
            [
                "getMap",
                "(",
                "  values,",
                ");",
                "",
                "std::map<int, int> getMap",
                "() {",
                "  return values;",
                "}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        toolkit_module,
        "_path_config",
        {
            "repo_root": tmp_path,
            "codeql_db_path": tmp_path / "codeql-dbs",
        },
    )
    monkeypatch.setattr(toolkit_module, "CodeQLAnalyzer", _FakeCodeQLAnalyzer)

    toolkit = toolkit_module.AgenticToolkit(repo_path=repo_path, languages=["cpp"])
    result = toolkit._get_function_code(source_file.name, "getMap")

    assert result.success is True
    assert "std::map<int, int> getMap" in result.content
    assert "() {" in result.content
    assert "return values;" in result.content
    assert "1: getMap" not in result.content


def test_get_function_code_matches_generic_java_return_type(tmp_path, monkeypatch):
    repo_path = tmp_path / "repo"
    repo_path.mkdir()

    source_file = repo_path / "Service.java"
    source_file.write_text(
        "\n".join(
            [
                "Map<String, Integer> build() {",
                "  return values;",
                "}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        toolkit_module,
        "_path_config",
        {
            "repo_root": tmp_path,
            "codeql_db_path": tmp_path / "codeql-dbs",
        },
    )
    monkeypatch.setattr(toolkit_module, "CodeQLAnalyzer", _FakeCodeQLAnalyzer)

    toolkit = toolkit_module.AgenticToolkit(repo_path=repo_path, languages=["java"])
    result = toolkit._get_function_code(source_file.name, "build")

    assert result.success is True
    assert "Map<String, Integer> build() {" in result.content
    assert "return values;" in result.content


def test_get_function_code_matches_csharp_expression_bodied_declaration(tmp_path, monkeypatch):
    repo_path = tmp_path / "repo"
    repo_path.mkdir()

    source_file = repo_path / "Service.cs"
    source_file.write_text(
        "\n".join(
            [
                "public int Foo() => 1;",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        toolkit_module,
        "_path_config",
        {
            "repo_root": tmp_path,
            "codeql_db_path": tmp_path / "codeql-dbs",
        },
    )
    monkeypatch.setattr(toolkit_module, "CodeQLAnalyzer", _FakeCodeQLAnalyzer)

    toolkit = toolkit_module.AgenticToolkit(repo_path=repo_path, languages=["csharp"])
    result = toolkit._get_function_code(source_file.name, "Foo")

    assert result.success is True
    assert "public int Foo() => 1;" in result.content


def test_get_function_code_preserves_multiline_csharp_expression_body(tmp_path, monkeypatch):
    repo_path = tmp_path / "repo"
    repo_path.mkdir()

    source_file = repo_path / "Service.cs"
    source_file.write_text(
        "\n".join(
            [
                "public int Foo() =>",
                "  Compute();",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        toolkit_module,
        "_path_config",
        {
            "repo_root": tmp_path,
            "codeql_db_path": tmp_path / "codeql-dbs",
        },
    )
    monkeypatch.setattr(toolkit_module, "CodeQLAnalyzer", _FakeCodeQLAnalyzer)

    toolkit = toolkit_module.AgenticToolkit(repo_path=repo_path, languages=["csharp"])
    result = toolkit._get_function_code(source_file.name, "Foo")

    assert result.success is True
    assert "public int Foo() =>" in result.content
    assert "Compute();" in result.content


def test_get_function_code_skips_qualified_call_site_before_expression_bodied_definition(tmp_path, monkeypatch):
    repo_path = tmp_path / "repo"
    repo_path.mkdir()

    source_file = repo_path / "service.cpp"
    source_file.write_text(
        "\n".join(
            [
                "Namespace::foo();",
                "",
                "int foo() => 1;",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        toolkit_module,
        "_path_config",
        {
            "repo_root": tmp_path,
            "codeql_db_path": tmp_path / "codeql-dbs",
        },
    )
    monkeypatch.setattr(toolkit_module, "CodeQLAnalyzer", _FakeCodeQLAnalyzer)

    toolkit = toolkit_module.AgenticToolkit(repo_path=repo_path, languages=["cpp"])
    result = toolkit._get_function_code(source_file.name, "foo")

    assert result.success is True
    assert "int foo() => 1;" in result.content
    assert "Namespace::foo();" not in result.content


def test_get_function_code_matches_ruby_method_without_braces(tmp_path, monkeypatch):
    repo_path = tmp_path / "repo"
    repo_path.mkdir()

    source_file = repo_path / "service.rb"
    source_file.write_text(
        "\n".join(
            [
                "puts foo(1)",
                "",
                "def foo(arg)",
                "  items.each do |item|",
                "    return item if item == arg",
                "  end",
                "  nil",
                "end",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        toolkit_module,
        "_path_config",
        {
            "repo_root": tmp_path,
            "codeql_db_path": tmp_path / "codeql-dbs",
        },
    )
    monkeypatch.setattr(toolkit_module, "CodeQLAnalyzer", _FakeCodeQLAnalyzer)

    toolkit = toolkit_module.AgenticToolkit(repo_path=repo_path, languages=["ruby"])
    result = toolkit._get_function_code(source_file.name, "foo")

    assert result.success is True
    assert "def foo(arg)" in result.content
    assert "items.each do |item|" in result.content
    assert "puts foo(1)" not in result.content


def test_get_function_code_matches_long_java_signature(tmp_path, monkeypatch):
    repo_path = tmp_path / "repo"
    repo_path.mkdir()

    params = [f"    String arg{i}," for i in range(45)]
    source_file = repo_path / "Service.java"
    source_file.write_text(
        "\n".join(
            ["public void handle("]
            + params
            + [
                "    String lastArg",
                ")",
                "throws",
                "    IOException,",
                "    SQLException",
                "{",
                "  process();",
                "}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        toolkit_module,
        "_path_config",
        {
            "repo_root": tmp_path,
            "codeql_db_path": tmp_path / "codeql-dbs",
        },
    )
    monkeypatch.setattr(toolkit_module, "CodeQLAnalyzer", _FakeCodeQLAnalyzer)

    toolkit = toolkit_module.AgenticToolkit(repo_path=repo_path, languages=["java"])
    result = toolkit._get_function_code(source_file.name, "handle")

    assert result.success is True
    assert "public void handle(" in result.content
    assert "process();" in result.content


def test_get_function_code_skips_preprocessor_macro_before_real_function(tmp_path, monkeypatch):
    repo_path = tmp_path / "repo"
    repo_path.mkdir()

    source_file = repo_path / "service.c"
    source_file.write_text(
        "\n".join(
            [
                "#define foo(value) { value; }",
                "",
                "int foo(int value) {",
                "  return value;",
                "}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        toolkit_module,
        "_path_config",
        {
            "repo_root": tmp_path,
            "codeql_db_path": tmp_path / "codeql-dbs",
        },
    )
    monkeypatch.setattr(toolkit_module, "CodeQLAnalyzer", _FakeCodeQLAnalyzer)

    toolkit = toolkit_module.AgenticToolkit(repo_path=repo_path, languages=["c"])
    result = toolkit._get_function_code(source_file.name, "foo")

    assert result.success is True
    assert "int foo(int value) {" in result.content
    assert "#define foo(value)" not in result.content
