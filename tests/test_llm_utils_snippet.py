from utils.llm_utils import extract_function_snippet_based_on_name_with_ast


def test_extract_function_snippet_falls_back_for_typescript() -> None:
    file_content = """
export function loadSettings(): UiSettings {
  const raw = localStorage.getItem(KEY);
  if (!raw) {
    return defaults;
  }
  return JSON.parse(raw) as UiSettings;
}
""".strip()

    snippet = extract_function_snippet_based_on_name_with_ast(
        file_content,
        "loadSettings",
        with_line_numbers=True,
    )

    assert "loadSettings" in snippet
    assert "localStorage.getItem(KEY)" in snippet


def test_extract_function_snippet_skips_call_site_before_typescript_function_definition() -> None:
    file_content = """
const value = loadSettings();

function loadSettings(): UiSettings {
  return defaults;
}
""".strip()

    snippet = extract_function_snippet_based_on_name_with_ast(
        file_content,
        "loadSettings",
        with_line_numbers=True,
    )

    assert "function loadSettings(): UiSettings {" in snippet
    assert "const value = loadSettings();" not in snippet


def test_extract_function_snippet_skips_bare_call_before_typescript_method_definition() -> None:
    file_content = """
loadSettings(
  defaults,
);

class SettingsStore {
  loadSettings(): UiSettings {
    return defaults;
  }
}
""".strip()

    snippet = extract_function_snippet_based_on_name_with_ast(
        file_content,
        "loadSettings",
        with_line_numbers=True,
    )

    assert "loadSettings(): UiSettings {" in snippet
    assert snippet.splitlines()[0].endswith("loadSettings(): UiSettings {")
    assert "1: loadSettings(" not in snippet


def test_extract_function_snippet_matches_java_annotation_prefixed_declaration() -> None:
    file_content = """
@Transactional public void handle() {
  process();
}
""".strip()

    snippet = extract_function_snippet_based_on_name_with_ast(
        file_content,
        "handle",
        with_line_numbers=True,
    )

    assert "@Transactional public void handle() {" in snippet
    assert "process();" in snippet


def test_extract_function_snippet_matches_qualified_java_annotation_prefixed_declaration() -> None:
    file_content = """
@org.foo.Tx public void handle() {
  process();
}
""".strip()

    snippet = extract_function_snippet_based_on_name_with_ast(
        file_content,
        "handle",
        with_line_numbers=True,
    )

    assert "@org.foo.Tx public void handle() {" in snippet
    assert "process();" in snippet


def test_extract_function_snippet_matches_csharp_attribute_list_prefixed_declaration() -> None:
    file_content = """
[Foo, Bar] public void Handle() {
  Process();
}
""".strip()

    snippet = extract_function_snippet_based_on_name_with_ast(
        file_content,
        "Handle",
        with_line_numbers=True,
    )

    assert "[Foo, Bar] public void Handle() {" in snippet
    assert "Process();" in snippet


def test_extract_function_snippet_matches_qualified_return_type() -> None:
    file_content = """
System.Threading.Tasks.Task DoWork() {
  return Task.CompletedTask;
}
""".strip()

    snippet = extract_function_snippet_based_on_name_with_ast(
        file_content,
        "DoWork",
        with_line_numbers=True,
    )

    assert "System.Threading.Tasks.Task DoWork() {" in snippet
    assert "return Task.CompletedTask;" in snippet


def test_extract_function_snippet_skips_split_line_call_site_before_qualified_return_type_declaration() -> None:
    file_content = """
DoWork
(
  pending,
);

System.Threading.Tasks.Task DoWork
() {
  return Task.CompletedTask;
}
""".strip()

    snippet = extract_function_snippet_based_on_name_with_ast(
        file_content,
        "DoWork",
        with_line_numbers=True,
    )

    assert "System.Threading.Tasks.Task DoWork" in snippet
    assert "() {" in snippet
    assert "return Task.CompletedTask;" in snippet
    assert "1: DoWork" not in snippet


def test_extract_function_snippet_matches_generic_java_return_type() -> None:
    file_content = """
Map<String, Integer> build() {
  return values;
}
""".strip()

    snippet = extract_function_snippet_based_on_name_with_ast(
        file_content,
        "build",
        with_line_numbers=True,
    )

    assert "Map<String, Integer> build() {" in snippet
    assert "return values;" in snippet


def test_extract_function_snippet_matches_wildcard_generic_return_type() -> None:
    file_content = """
List<? extends Number> build() {
  return values;
}
""".strip()

    snippet = extract_function_snippet_based_on_name_with_ast(
        file_content,
        "build",
        with_line_numbers=True,
    )

    assert "List<? extends Number> build() {" in snippet
    assert "return values;" in snippet


def test_extract_function_snippet_matches_cpp_template_return_type() -> None:
    file_content = """
std::map<int, int> getMap() {
  return values;
}
""".strip()

    snippet = extract_function_snippet_based_on_name_with_ast(
        file_content,
        "getMap",
        with_line_numbers=True,
    )

    assert "std::map<int, int> getMap() {" in snippet
    assert "return values;" in snippet


def test_extract_function_snippet_matches_csharp_expression_bodied_declaration() -> None:
    file_content = """
public int Foo() => 1;
""".strip()

    snippet = extract_function_snippet_based_on_name_with_ast(
        file_content,
        "Foo",
        with_line_numbers=True,
    )

    assert "public int Foo() => 1;" in snippet


def test_extract_function_snippet_matches_kotlin_expression_bodied_declaration() -> None:
    file_content = """
fun foo(): Int = 1
""".strip()

    snippet = extract_function_snippet_based_on_name_with_ast(
        file_content,
        "foo",
        with_line_numbers=True,
    )

    assert "fun foo(): Int = 1" in snippet


def test_extract_function_snippet_skips_qualified_call_site_before_expression_bodied_definition() -> None:
    file_content = """
Namespace::foo();

int foo() => 1;
""".strip()

    snippet = extract_function_snippet_based_on_name_with_ast(
        file_content,
        "foo",
        with_line_numbers=True,
    )

    assert "int foo() => 1;" in snippet
    assert "Namespace::foo();" not in snippet


def test_extract_function_snippet_matches_cpp_virtual_declaration() -> None:
    file_content = """
virtual int foo() {
  return 1;
}
""".strip()

    snippet = extract_function_snippet_based_on_name_with_ast(
        file_content,
        "foo",
        with_line_numbers=True,
    )

    assert "virtual int foo() {" in snippet
    assert "return 1;" in snippet


def test_extract_function_snippet_matches_ruby_method_with_nested_block() -> None:
    file_content = """
def foo(arg)
  items.each do |item|
    return item if item == arg
  end
  nil
end
""".strip()

    snippet = extract_function_snippet_based_on_name_with_ast(
        file_content,
        "foo",
        with_line_numbers=True,
    )

    assert "def foo(arg)" in snippet
    assert "items.each do |item|" in snippet
    assert snippet.splitlines()[-1].endswith("end")


def test_extract_function_snippet_matches_ruby_endless_method() -> None:
    file_content = """
def foo(arg) = normalize(arg)
""".strip()

    snippet = extract_function_snippet_based_on_name_with_ast(
        file_content,
        "foo",
        with_line_numbers=True,
    )

    assert "def foo(arg) = normalize(arg)" in snippet


def test_extract_function_snippet_matches_ruby_single_line_method() -> None:
    file_content = """
def foo(arg); arg + 1; end
""".strip()

    snippet = extract_function_snippet_based_on_name_with_ast(
        file_content,
        "foo",
        with_line_numbers=True,
    )

    assert "def foo(arg); arg + 1; end" in snippet


def test_extract_function_snippet_preserves_multiline_kotlin_expression_body() -> None:
    file_content = """
fun foo() =
  compute(
    arg,
  )
""".strip()

    snippet = extract_function_snippet_based_on_name_with_ast(
        file_content,
        "foo",
        with_line_numbers=True,
    )

    assert "fun foo() =" in snippet
    assert "compute(" in snippet
    assert "arg," in snippet


def test_extract_function_snippet_matches_long_java_signature() -> None:
    params = [f"    String arg{i}," for i in range(45)]
    file_content = "\n".join(
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

    snippet = extract_function_snippet_based_on_name_with_ast(
        file_content,
        "handle",
        with_line_numbers=True,
    )

    assert "public void handle(" in snippet
    assert "process();" in snippet


def test_extract_function_snippet_skips_preprocessor_macro_before_real_function() -> None:
    file_content = """
#define foo(value) { value; }

int foo(int value) {
  return value;
}
""".strip()

    snippet = extract_function_snippet_based_on_name_with_ast(
        file_content,
        "foo",
        with_line_numbers=True,
    )

    assert "int foo(int value) {" in snippet
    assert "#define foo(value)" not in snippet
