# CodeQL Queries

Organized by language. Each subdirectory contains its own `qlpack.yml` and query files.

## Structure

```
.codeql-queries/
├── python/          # Python queries (codeql/python-all)
│   ├── qlpack.yml
│   └── *.ql
├── cpp/             # C/C++ queries (codeql/cpp-all) — auto-generated at runtime
├── go/              # Go queries (codeql/go-all) — auto-generated at runtime
├── java/            # Java queries (codeql/java-all) — auto-generated at runtime
├── javascript/      # JavaScript/TypeScript queries (codeql/javascript-all) — auto-generated at runtime
├── ruby/            # Ruby queries (codeql/ruby-all) — auto-generated at runtime
├── csharp/          # C# queries (codeql/csharp-all) — auto-generated at runtime
└── rust/            # Rust queries — auto-generated at runtime
```

The toolkit automatically creates language subdirectories with appropriate `qlpack.yml`
when running queries for a new language for the first time.
