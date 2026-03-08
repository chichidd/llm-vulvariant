"""Repository Analyzer - a CodeQL-based static analysis tool.

Capabilities:
1. Call graph analysis: extract inter-function call relationships
2. Dependency analysis: analyze third-party library dependencies
3. Entry point detection: identify HTTP endpoints, CLI entries, etc.
"""

import os
import pickle
import re
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Union
from dataclasses import dataclass, field
from utils.codeql_native import CodeQLAnalyzer, load_codeql_config, CallGraphEdge
from utils.git_utils import get_git_commit
from utils.language import get_extensions

from utils.logger import get_logger

logger = get_logger(__name__)

# ========== Dependency parser constants ==========

C_FAMILY_EXTS = set(get_extensions("cpp"))
C_FAMILY_HEADER_EXTS = {'.h', '.hpp', '.hh', '.hxx', '.cuh'}
C_FAMILY_SOURCE_EXTS = C_FAMILY_EXTS - C_FAMILY_HEADER_EXTS
JS_TS_EXTS = set(get_extensions("javascript"))

VENDOR_PREFIXES = {'3rdparty', 'third_party', 'thirdparty', 'external', 'extern', 'vendor', 'vendors', 'deps', 'dependencies'}
INTERNAL_PREFIXES = {
    'src', 'source', 'include', 'inc', 'internal', 'tests', 'test',
    'examples', 'example', 'benchmarks', 'benchmark', 'tools', 'samples',
    'plugins', 'plugin', 'cmake', 'build'
}

NODE_BUILTIN_MODULES = {
    'assert', 'buffer', 'child_process', 'cluster', 'crypto', 'dgram', 'dns', 'events',
    'fs', 'http', 'http2', 'https', 'net', 'os', 'path', 'querystring', 'readline',
    'stream', 'timers', 'tls', 'tty', 'url', 'util', 'vm', 'worker_threads', 'zlib'
}

RUBY_BUILTINS = {'json', 'set', 'time', 'uri', 'yaml', 'pathname', 'fileutils', 'tempfile', 'digest', 'date', 'csv'}

# C/C++ standard library headers normalized to Path(...).stem used by _normalize_dependency_name.
# Example: stdio.h -> stdio, vector -> vector
C_CPP_BUILTIN_HEADERS = {
    # C standard library (and common C++ wrappers)
    'assert', 'cassert', 'ctype', 'cctype', 'errno', 'cerrno', 'fenv', 'cfenv', 'float', 'cfloat',
    'inttypes', 'cinttypes', 'iso646', 'limits', 'climits', 'locale', 'clocale', 'math', 'cmath',
    'setjmp', 'csetjmp', 'signal', 'csignal', 'stdarg', 'cstdarg', 'stdbool', 'cstdbool',
    'stddef', 'cstddef', 'stdint', 'cstdint', 'stdio', 'cstdio', 'stdlib', 'cstdlib', 'string',
    'cstring', 'tgmath', 'ctgmath', 'time', 'ctime', 'uchar', 'cuchar', 'wchar', 'cwchar',
    'wctype', 'cwctype', 'stdatomic', 'stdnoreturn', 'threads',
    # C++ standard library
    'algorithm', 'any', 'array', 'atomic', 'barrier', 'bit', 'bitset', 'charconv', 'chrono',
    'codecvt', 'compare', 'complex', 'concepts', 'condition_variable', 'coroutine', 'deque',
    'exception', 'execution', 'expected', 'filesystem', 'format', 'forward_list', 'fstream',
    'functional', 'future', 'initializer_list', 'iomanip', 'ios', 'iosfwd', 'iostream', 'istream',
    'iterator', 'latch', 'list', 'map', 'memory', 'memory_resource', 'mutex', 'new', 'numbers',
    'numeric', 'optional', 'ostream', 'print', 'queue', 'random', 'ranges', 'ratio', 'regex',
    'scoped_allocator', 'semaphore', 'set', 'shared_mutex', 'source_location', 'span', 'sstream',
    'stack', 'stacktrace', 'stdexcept', 'stop_token', 'streambuf', 'string_view', 'strstream',
    'syncstream', 'system_error', 'thread', 'tuple', 'type_traits', 'typeindex', 'typeinfo',
    'unordered_map', 'unordered_set', 'utility', 'valarray', 'variant', 'vector', 'version',
}


# ========== Data structures ==========

@dataclass
class CodeLocation:
    """A code location."""
    file: str
    line: int
    column: int = 0
    code: str = ""
    
    def __str__(self):
        return f"{self.file}:{self.line}"
    
    def __hash__(self):
        return hash((self.file, self.line))
    
    def __eq__(self, other):
        return isinstance(other, CodeLocation) and \
               self.file == other.file and self.line == other.line


@dataclass
class FunctionInfo:
    """Function information."""
    id: str
    name: str
    file: str
    start_line: int
    end_line: int
    parameters: List[str] = field(default_factory=list)
    
    def __str__(self):
        return f"{self.name} @ {self.file}:{self.start_line}"


@dataclass
class DependencyInfo:
    """Dependency information."""
    name: str
    version: Optional[str] = None
    import_locations: List[CodeLocation] = field(default_factory=list)
    is_builtin: bool = False
    is_third_party: bool = True


# ========== Main class ==========

class RepoAnalyzer:
    """
    Repository analyzer - deep static analysis using CodeQL.

    Features:
    - Automatic language detection (supports Python, C/C++)
    - Commit-hash-based caching
    - Call graph extraction
    - Dependency analysis, entry point detection, and sensitive data tracking

    Args:
        repo_path: Repository path
        languages: Optional explicit language config ("auto" or list)
        cache_dir: Cache directory
    """
    

    def __init__(
        self,
        repo_path: str,
        languages: Optional[Union[str, List[str]]] = "auto",
        cache_dir: Optional[str] = None,
        rebuild_cache: bool = False
    ):
        """Initialize the analyzer."""
        self.repo_path = Path(repo_path).resolve()
        if not self.repo_path.exists():
            raise ValueError(f"Repository path does not exist: {repo_path}")

        # Resolve analysis languages (multi-language aware).
        self.languages = self._resolve_languages(languages=languages)
        logger.info(
            "Detected languages: %s",
            ", ".join(self.languages) if self.languages else "none",
        )
        
        # Set cache directory
        if cache_dir is None:
            cache_dir = os.path.join(os.path.dirname(__file__), "..", ".cache", "repo_analyzer")
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        # Get current commit hash
        self.commit_hash = get_git_commit(str(self.repo_path))
        if not self.commit_hash:
            logger.warning("Could not get commit hash, using timestamp as fallback")
            import time
            self.commit_hash = str(int(time.time()))
        
        # Initialize CodeQL analyzer
        try:
            from config import _path_config
        except ImportError as e:
            logger.warning(f"Failed to import config module: {e}, using default config")
            _path_config = None
        
        codeql_config = load_codeql_config()
        
        # Only set database_dir when _path_config is successfully imported
        if _path_config:
            codeql_config['database_dir'] = str(_path_config['codeql_db_path'])
        
        logger.debug(f"CodeQL config queries_path before init: {codeql_config.get('queries_path')}")
        self.codeql_analyzer = CodeQLAnalyzer(codeql_config)
        logger.debug(f"CodeQL analyzer queries_path after init: {self.codeql_analyzer.config.get('queries_path')}")
        

        if not self.codeql_analyzer.is_available:
            raise RuntimeError("CodeQL is not installed or not in PATH. "
                             "Please install from https://github.com/github/codeql-cli-binaries/releases")
        
        logger.info(f"Using CodeQL version: {self.codeql_analyzer.version}")

        supported = set(self.codeql_analyzer.SUPPORTED_LANGUAGES.keys())
        codeql_candidates = [lang for lang in self.languages if lang in supported]
        self.codeql_languages = self._filter_codeql_languages(codeql_candidates)
        if not self.codeql_languages:
            logger.warning(
                "No CodeQL-supported languages detected in %s. Call graph/function extraction will be skipped.",
                self.repo_path,
            )
        else:
            skipped = [lang for lang in self.languages if lang not in supported]
            skipped.extend([lang for lang in codeql_candidates if lang not in self.codeql_languages])
            skipped = self._dedupe_preserve_order(skipped)
            if skipped:
                logger.info("Skipping unsupported CodeQL languages: %s", ", ".join(skipped))
        
        # Data storage
        self._call_graph_edges: List[CallGraphEdge] = []
        self._codeql_db_paths: Dict[str, str] = {}
        self._functions: Dict[str, FunctionInfo] = {}
        self._function_key_index: Dict[Tuple[str, str, int], str] = {}
        self._dependencies: Dict[str, DependencyInfo] = {}

        # Load or build analysis data
        self._load_or_build(rebuild_cache)
    
    def get_info(self):
        active_codeql_languages = list(getattr(self, '_codeql_db_paths', {}).keys())
        if not active_codeql_languages:
            active_codeql_languages = list(getattr(self, 'codeql_languages', []))
        info = {
            'languages': list(getattr(self, 'languages', [])),
            'codeql_languages': active_codeql_languages,
            'call_graph_edges': [],
            'functions': [],
            'dependencies': []
        }
        
        # Extract call graph

        call_graph = self._call_graph_edges
        if call_graph:
            info['call_graph_edges'] = [
                {
                    'caller': edge.caller_name,
                    'caller_file': edge.caller_file,
                    'caller_line': edge.caller_line,
                    'caller_id': self._resolve_function_id(edge.caller_name, edge.caller_file, edge.caller_line),
                    'callee': edge.callee_name,
                    'callee_file': edge.callee_file,
                    'callee_line': edge.callee_line,
                    'callee_id': self._resolve_function_id(edge.callee_name, edge.callee_file, edge.callee_line),
                    'call_site_line': edge.call_site_line
                }
                for edge in call_graph
            ]
            logger.info(f"Extracted {len(info['call_graph_edges'])} call graph edges")
        
        functions = self._functions
        if functions:
            info['functions'] = [
                {
                    'function_id': func.id,
                    'name': func.name,
                    'file': func.file,
                    'start_line': func.start_line,
                    'end_line': func.end_line,
                    'parameters': func.parameters
                }
                for func in list(functions.values())
            ]
            logger.info(f"Extracted {len(info['functions'])} functions")
        
        dependencies = self._dependencies
        if dependencies:
            info['dependencies'] = [
                {
                    'name': dep.name,
                    'version': dep.version,
                    'is_builtin': dep.is_builtin,
                    'is_third_party': dep.is_third_party,
                    'import_count': len(dep.import_locations),
                    'import_files': list(set([loc.file for loc in dep.import_locations]))
                }
                for dep in list(dependencies.values())
            ]
            logger.info(f"Extracted {len(info['dependencies'])} dependencies")
        logger.info(f"Deep analysis completed successfully")
        return info
    
    @staticmethod
    def _dedupe_preserve_order(items: List[str]) -> List[str]:
        seen = set()
        ordered: List[str] = []
        for item in items:
            if item and item not in seen:
                seen.add(item)
                ordered.append(item)
        return ordered

    def _detect_languages(self) -> List[str]:
        """Auto-detect repository languages ranked by relevance."""
        from utils.language import detect_languages

        return detect_languages(self.repo_path)

    def _has_cpp_translation_units(self) -> bool:
        """Return True when repository contains C/C++ source units (not headers only)."""
        ignored_dirs = {
            ".git",
            "node_modules",
            "__pycache__",
            "build",
            "dist",
            ".tox",
            "venv",
            ".venv",
        }
        for root, dirs, files in os.walk(self.repo_path):
            dirs[:] = [d for d in dirs if d not in ignored_dirs]
            for fname in files:
                if Path(fname).suffix.lower() in C_FAMILY_SOURCE_EXTS:
                    return True
        return False

    def _filter_codeql_languages(self, languages: List[str]) -> List[str]:
        """Filter out languages that are technically supported but not analyzable."""
        filtered: List[str] = []
        for lang in languages:
            if lang == "cpp" and not self._has_cpp_translation_units():
                logger.info(
                    "Skipping CodeQL language cpp for %s: no C/C++ translation units detected.",
                    self.repo_path,
                )
                continue
            filtered.append(lang)
        return filtered

    def _resolve_languages(
        self,
        languages: Optional[Union[str, List[str]]],
    ) -> List[str]:
        """Resolve configured analysis languages into a canonical list."""
        if languages is not None:
            if isinstance(languages, str):
                normalized_value = languages.strip().lower()
                if not normalized_value or normalized_value == "auto":
                    return self._detect_languages()
                return [normalized_value]

            if isinstance(languages, list):
                normalized = [
                    str(lang).strip().lower()
                    for lang in languages
                    if isinstance(lang, str) and str(lang).strip()
                ]
                normalized = self._dedupe_preserve_order(normalized)
                normalized = [lang for lang in normalized if lang != "auto"]
                return normalized or self._detect_languages()

            logger.warning(
                "Invalid `languages` type (%s), fallback to auto-detection.",
                type(languages).__name__,
            )
        return self._detect_languages()
    

    def _load_or_build(self, rebuild: bool = False, cache_path: Optional[Path] = None):
        """Load cache or rebuild analysis data."""
        if cache_path is None:
            language_key = "-".join(self.languages) if self.languages else "none"
            cache_path = self.cache_dir / f"{self.repo_path.name}-{self.commit_hash[:8]}-{language_key}.pkl"
        
        # Try loading cache
        if not rebuild and cache_path.exists():
            try:
                logger.info(f"Loading cache from {cache_path}")
                with open(cache_path, 'rb') as f:
                    cache_data = pickle.load(f)
                
                self._call_graph_edges = cache_data['call_graph_edges']
                self._codeql_db_paths = cache_data.get('codeql_db_paths', {})
                self._functions = cache_data['functions']
                self._function_key_index = cache_data.get('function_key_index', {})
                self._dependencies = cache_data['dependencies']
                cached_languages = cache_data.get('languages')
                if isinstance(cached_languages, list):
                    self.languages = self._dedupe_preserve_order(
                        [str(lang).strip().lower() for lang in cached_languages if str(lang).strip()]
                    ) or self.languages

                self._rebuild_function_indexes()

                logger.info(f"Cache loaded successfully")
                logger.info(f"  - Functions: {len(self._functions)}")
                logger.info(f"  - Call graph edges: {len(self._call_graph_edges)}")
                logger.info(f"  - Dependencies: {len(self._dependencies)}")
                return
            except Exception as e:
                logger.warning(f"Failed to load cache: {e}, rebuilding...")
        
        # Build analysis data
        logger.info(f"Building analysis data (this may take a few minutes)...")
        self._build_analysis()
        
        # Save cache
        self._save_cache(cache_path)

    def _save_cache(self, cache_path: Path):
        """Persist current analysis cache to disk."""
        try:
            cache_data = {
                'languages': self.languages,
                'call_graph_edges': self._call_graph_edges,
                'codeql_db_paths': self._codeql_db_paths,
                'functions': self._functions,
                'function_key_index': self._function_key_index,
                'dependencies': self._dependencies,
            }
            with open(cache_path, 'wb') as f:
                pickle.dump(cache_data, f)
            logger.info(f"Cache saved to {cache_path}")
        except Exception as e:
            logger.warning(f"Failed to save cache: {e}")

    @staticmethod
    def _build_function_id(name: str, file_path: str, start_line: int) -> str:
        return f"{file_path}::{name}@{start_line}"

    def _rebuild_function_indexes(self):
        """Rebuild location indexes from function table."""
        rebuilt_key_index: Dict[Tuple[str, str, int], str] = {}

        for key, func in list(self._functions.items()):
            func_id = getattr(func, 'id', '') or (key if isinstance(key, str) else '')
            if not func_id:
                func_id = self._build_function_id(func.name, func.file, int(func.start_line))
            func.id = func_id

            rebuilt_key_index[(func.name, func.file, int(func.start_line))] = func_id

        self._function_key_index = rebuilt_key_index

    def _register_function(self, name: str, file_path: str, start_line: int) -> Optional[str]:
        """Create/register a function and return its function ID."""
        if not name or not file_path:
            return None

        line = int(start_line or 0)
        func_id = self._build_function_id(name, file_path, line)
        if func_id not in self._functions:
            self._functions[func_id] = FunctionInfo(
                id=func_id,
                name=name,
                file=file_path,
                start_line=line,
                end_line=line,
            )

        self._function_key_index[(name, file_path, line)] = func_id
        return func_id

    def _resolve_function_id(self, name: str, file_path: str, line: int) -> str:
        if not name or not file_path:
            return ""
        return self._function_key_index.get((name, file_path, int(line or 0)), "")
    
    def _build_analysis(self):
        """Build the full analysis dataset."""
        # Step 1: Create CodeQL databases (one per detected language)
        logger.info("[1/4] Creating CodeQL database(s)...")
        self._codeql_db_paths = {}
        db_errors: Dict[str, str] = {}

        for lang in self.codeql_languages:
            db_name = f"{self.repo_path.name}-{self.commit_hash[:8]}-{lang}"
            success, db_path_or_error = self.codeql_analyzer.create_database(
                source_path=str(self.repo_path),
                language=lang,
                database_name=db_name,
                overwrite=False,
            )
            if success:
                self._codeql_db_paths[lang] = db_path_or_error
                logger.info("    Database created [%s]: %s", lang, db_path_or_error)
            else:
                db_errors[lang] = db_path_or_error
                logger.warning("    Failed to create database for %s: %s", lang, db_path_or_error)

        if self.codeql_languages and not self._codeql_db_paths:
            detail = "; ".join(f"{lang}={err}" for lang, err in sorted(db_errors.items()))
            raise RuntimeError(f"Failed to create CodeQL database(s): {detail}")
        
        # Step 2: Build call graph
        logger.info("[2/4] Building call graph...")
        self._build_call_graph()
        
        # Step 3: Extract function info
        logger.info("[3/4] Extracting function information...")
        self._extract_functions()
        
        # Step 4: Analyze dependencies
        logger.info("[4/4] Analyzing dependencies...")
        self._analyze_dependencies()

        
        logger.info("[RepoAnalyzer] Analysis complete!")
        logger.info(f"  - Functions: {len(self._functions)}")
        logger.info(f"  - Call graph edges: {len(self._call_graph_edges)}")
        logger.info(f"  - Dependencies: {len(self._dependencies)}")
    
    def _build_call_graph(self):
        """Build the call graph (using CodeQL)."""
        merged_edges: List[CallGraphEdge] = []
        seen_edge_keys = set()

        if not self._codeql_db_paths:
            logger.info("No CodeQL database available; call graph will be empty.")
            self._call_graph_edges = []
            return

        for lang, db_path in self._codeql_db_paths.items():
            try:
                logger.info("Building call graph with CodeQL for %s database: %s", lang, db_path)
                language_edges = self.codeql_analyzer._build_call_graph(db_path, lang)
                logger.info("CodeQL returned %s call graph edges for %s", len(language_edges), lang)
                for edge in language_edges:
                    key = (
                        edge.caller_name,
                        edge.caller_file,
                        int(edge.caller_line or 0),
                        edge.callee_name,
                        edge.callee_file,
                        int(edge.callee_line or 0),
                        int(edge.call_site_line or 0),
                    )
                    if key in seen_edge_keys:
                        continue
                    seen_edge_keys.add(key)
                    merged_edges.append(edge)
            except Exception as e:
                logger.warning(f"Failed to build call graph via CodeQL for {lang}: {e}")
                import traceback

                logger.debug(traceback.format_exc())

        self._call_graph_edges = merged_edges


    
    def _extract_functions(self):
        """Extract function information from the call graph.
        
        Only includes functions with resolved file paths (excludes builtins,
        standard library, third-party packages, and unresolved dynamic calls).
        """
        self._functions = {}
        self._function_key_index = {}
        skipped_unresolved = 0
        
        for edge in self._call_graph_edges:
            # Add caller (module-level callers may use line=0)
            if edge.caller_file:
                self._register_function(
                    edge.caller_name,
                    edge.caller_file,
                    edge.caller_line,
                )
            
            # Add callee only if it has a valid file path
            # Skip builtins, stdlib, third-party, and unresolved dynamic calls
            if edge.callee_file and edge.callee_line > 0:
                self._register_function(
                    edge.callee_name,
                    edge.callee_file,
                    edge.callee_line,
                )
            else:
                skipped_unresolved += 1
        
        if skipped_unresolved > 0:
            logger.debug(f"Skipped {skipped_unresolved} unresolved callee references (builtins/stdlib/third-party)")
    
    def _analyze_dependencies(self):
        """Analyze third-party library dependencies."""
        # Dependency analysis is a full rebuild; clear any previous state first.
        self._dependencies = {}
        self._reset_dependency_analysis_caches()

        # Build set of extensions to scan for all active languages
        active_languages = list(getattr(self, "languages", []) or [])
        lang_exts: Set[str] = set()
        for lang in active_languages:
            try:
                lang_exts |= get_extensions(lang)
            except ValueError:
                logger.debug("Skip unsupported dependency language: %s", lang)
                continue

        for root, dirs, files in os.walk(self.repo_path):
            dirs[:] = [d for d in dirs if d not in {'.git', '__pycache__', 'node_modules'}]

            for file in files:
                ext = Path(file).suffix.lower()
                if ext not in lang_exts:
                    continue

                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_path, self.repo_path)

                try:
                    in_go_import_block = False
                    in_js_block_comment = False
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        for line_num, line in enumerate(f, 1):
                            scan_line, in_js_block_comment = self._preprocess_dependency_scan_line(
                                line, ext, in_js_block_comment
                            )
                            stripped = scan_line.strip()

                            should_extract, in_go_import_block = self._should_extract_import(
                                ext, stripped, in_go_import_block
                            )
                            if should_extract:
                                self._extract_import(stripped, rel_path, line_num, ext)
                except Exception:
                    continue

    def _reset_dependency_analysis_caches(self) -> None:
        """Reset caches used by dependency analysis for a clean rebuild."""
        self._go_module_name_cache = None
        self._cpp_local_include_cache = {}

    def _preprocess_dependency_scan_line(
        self,
        line: str,
        ext: str,
        in_js_block_comment: bool,
    ) -> Tuple[str, bool]:
        """Language-aware line preprocessing before import candidate checks."""
        if ext in JS_TS_EXTS:
            return self._strip_js_comments(line, in_js_block_comment)
        return line, in_js_block_comment

    def _should_extract_import(
        self,
        ext: str,
        stripped: str,
        in_go_import_block: bool,
    ) -> Tuple[bool, bool]:
        """Decide whether a stripped line should be sent to _extract_import."""
        if not stripped:
            return False, in_go_import_block

        if ext == '.py':
            return stripped.startswith('import ') or stripped.startswith('from '), in_go_import_block

        if ext in C_FAMILY_EXTS:
            return stripped.startswith('#include') or stripped.startswith('# include'), in_go_import_block

        if ext == '.go':
            if re.match(r'^import(?:\s|\()', stripped):
                return True, bool(re.match(r'^import\s*\($', stripped))
            if in_go_import_block:
                if stripped.startswith(')'):
                    return False, False
                return True, True
            return False, False

        if ext == '.java':
            return stripped.startswith('import '), in_go_import_block

        if ext in JS_TS_EXTS:
            # Use a broad token pre-filter; actual extraction is syntax-aware in _extract_js_modules.
            return bool(re.search(r'\b(?:import|export|require)\b', stripped)), in_go_import_block

        if ext == '.rs':
            return stripped.startswith('use ') or stripped.startswith('extern crate '), in_go_import_block

        if ext == '.rb':
            return stripped.startswith('require'), in_go_import_block

        return False, in_go_import_block
    
    def _extract_import(self, line: str, file: str, line_num: int, ext: str):
        """Extract dependencies from an import statement."""
        try:
            modules = self._parse_import_modules(line, ext)
            for raw_module in modules:
                module = self._normalize_dependency_name(raw_module, ext)
                if not module:
                    continue
                if self._is_internal_dependency(raw_module, module, ext, file, line):
                    continue

                if module not in self._dependencies:
                    is_builtin = self._is_builtin_dependency(module, ext)
                    self._dependencies[module] = DependencyInfo(
                        name=module,
                        is_builtin=is_builtin,
                        is_third_party=not is_builtin
                    )
                
                # Add import location
                loc = CodeLocation(file=file, line=line_num, code=line)
                self._dependencies[module].import_locations.append(loc)
        except Exception as e:
            logger.debug(f"Failed to analyze imports in {file}: {e}")

    @staticmethod
    def _strip_js_comments(line: str, in_block_comment: bool) -> Tuple[str, bool]:
        """Strip JS/TS comments while preserving string literals."""
        out: List[str] = []
        i = 0
        in_single = False
        in_double = False
        in_template = False
        escaped = False

        while i < len(line):
            ch = line[i]
            nxt = line[i + 1] if i + 1 < len(line) else ""

            if in_block_comment:
                if ch == "*" and nxt == "/":
                    in_block_comment = False
                    i += 2
                    continue
                i += 1
                continue

            if in_single:
                out.append(ch)
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == "'":
                    in_single = False
                i += 1
                continue

            if in_double:
                out.append(ch)
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == '"':
                    in_double = False
                i += 1
                continue

            if in_template:
                out.append(ch)
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == "`":
                    in_template = False
                i += 1
                continue

            if ch == "/" and nxt == "*":
                in_block_comment = True
                i += 2
                continue
            if ch == "/" and nxt == "/":
                break

            out.append(ch)
            if ch == "'":
                in_single = True
            elif ch == '"':
                in_double = True
            elif ch == "`":
                in_template = True
            i += 1

        return "".join(out), in_block_comment

    @staticmethod
    def _looks_like_local_experiment_name(name: str) -> bool:
        """Heuristically detect local/experimental folder-style names."""
        lower = name.lower()
        if not lower:
            return True
        if lower in {'include', 'src', 'source', 'internal', 'test', 'tests', 'example', 'examples', 'benchmark', 'benchmarks', 'sample', 'samples', 'demo', 'demos', 'tmp', 'temp', 'playground', 'tools', 'scripts', 'cmake', 'build'}:
            return True
        if re.match(r'^\d+[a-z0-9_-]*$', lower):
            return True
        if re.match(r'^\d+[_-].*$', lower):
            return True
        if re.match(r'^\d{4}[_-]\d{2}[_-]\d{2}.*$', lower):
            return True
        return False

    def _parse_import_modules(self, line: str, ext: str) -> List[str]:
        """Parse one source line and extract raw import targets."""
        modules: List[str] = []

        if ext == '.py':
            if line.startswith('import '):
                modules.extend(part.strip() for part in line[7:].split(','))
            elif line.startswith('from '):
                parts = line.split('import', 1)
                if len(parts) == 2:
                    modules.append(parts[0][5:].strip().split()[0])
        elif ext in C_FAMILY_EXTS:
            match = re.match(r'^#\s*include\s*[<"]([^">]+)[">]', line)
            if match:
                modules.append(match.group(1).strip())
        elif ext == '.go':
            # Support: import "pkg", import alias "pkg", and lines in import (...) blocks.
            content = line.split('//', 1)[0].strip()
            if content.startswith('import'):
                content = content[6:].strip()
            if content and content not in {'(', ')'}:
                match = re.search(r'["`]([^"`]+)["`]', content)
                if match:
                    modules.append(match.group(1).strip())
        elif ext == '.java':
            content = line[len('import '):].strip() if line.startswith('import ') else ""
            if content.startswith('static '):
                content = content[7:].strip()
            if content:
                modules.append(content.rstrip(';'))
        elif ext == '.rs':
            content = line.rstrip(';').strip()
            if content.startswith('extern crate '):
                modules.append(content[len('extern crate '):].split(' as ', 1)[0].strip())
            elif content.startswith('use '):
                path = content[len('use '):].strip()
                if path:
                    modules.append(path.split('::', 1)[0].strip())
        elif ext == '.rb':
            relative_match = re.search(r'^require_relative\s*(?:\(\s*)?[\'"]([^\'"]+)[\'"]', line)
            if relative_match:
                modules.append(f"./{relative_match.group(1).strip()}")
            match = re.search(r'^require\s*(?:\(\s*)?[\'"]([^\'"]+)[\'"]', line)
            if match:
                modules.append(match.group(1).strip())
        elif ext in JS_TS_EXTS:
            modules.extend(self._extract_js_modules(line))

        return modules

    @staticmethod
    def _is_js_ident_char(ch: str) -> bool:
        return ch.isalnum() or ch in {'_', '$'}

    @classmethod
    def _is_js_word_boundary(cls, text: str, start: int, end: int) -> bool:
        left_ok = start == 0 or not cls._is_js_ident_char(text[start - 1])
        right_ok = end >= len(text) or not cls._is_js_ident_char(text[end])
        return left_ok and right_ok

    @staticmethod
    def _skip_js_whitespace(text: str, idx: int) -> int:
        while idx < len(text) and text[idx].isspace():
            idx += 1
        return idx

    @staticmethod
    def _read_js_string(text: str, idx: int) -> Tuple[Optional[str], int]:
        """Read a JS string literal starting at idx and return (value, next_idx)."""
        if idx >= len(text) or text[idx] not in {"'", '"', '`'}:
            return None, idx

        quote = text[idx]
        i = idx + 1
        escaped = False
        chars: List[str] = []

        while i < len(text):
            ch = text[i]
            if escaped:
                chars.append(ch)
                escaped = False
                i += 1
                continue
            if ch == '\\':
                escaped = True
                i += 1
                continue
            if ch == quote:
                return "".join(chars), i + 1
            chars.append(ch)
            i += 1

        return None, len(text)

    @staticmethod
    def _looks_like_js_regex_start(text: str, idx: int, last_sig_char: str) -> bool:
        """Heuristic check: treat '/' as regex opener only in expression-start context."""
        if idx + 1 >= len(text):
            return False
        if text[idx + 1] in {'/', '*'}:
            return False
        if not last_sig_char:
            return True
        if last_sig_char in {'(', '[', '{', ',', ';', ':', '=', '!', '?', '&', '|', '+', '-', '*', '%', '^', '~', '<', '>'}:
            return True
        return False

    @staticmethod
    def _skip_js_regex_literal(text: str, idx: int) -> int:
        """Skip a JS regex literal `/.../flags` and return the index after it."""
        i = idx + 1
        in_char_class = False
        escaped = False

        while i < len(text):
            ch = text[i]
            if escaped:
                escaped = False
                i += 1
                continue
            if ch == '\\':
                escaped = True
                i += 1
                continue
            if ch == '[':
                in_char_class = True
                i += 1
                continue
            if ch == ']' and in_char_class:
                in_char_class = False
                i += 1
                continue
            if ch == '/' and not in_char_class:
                i += 1
                while i < len(text) and text[i].isalpha():
                    i += 1
                return i
            i += 1

        return len(text)

    def _extract_js_modules(self, line: str) -> List[str]:
        """
        Extract JS/TS module strings by scanning code tokens.

        Strategy:
        1) Skip string literals and regex literals.
        2) Match require/import/export only in code context.
        """
        modules: List[str] = []
        i = 0
        n = len(line)
        last_sig_char = ""

        while i < n:
            ch = line[i]
            if ch in {"'", '"', '`'}:
                _, i = self._read_js_string(line, i)
                last_sig_char = '#'
                continue
            if ch == '/' and self._looks_like_js_regex_start(line, i, last_sig_char):
                i = self._skip_js_regex_literal(line, i)
                last_sig_char = '#'
                continue

            # require("x")
            if line.startswith('require', i) and self._is_js_word_boundary(line, i, i + 7):
                j = self._skip_js_whitespace(line, i + 7)
                if j < n and line[j] == '(':
                    j = self._skip_js_whitespace(line, j + 1)
                    module, next_idx = self._read_js_string(line, j)
                    if module:
                        modules.append(module.strip())
                        i = next_idx
                        last_sig_char = '#'
                        continue

            # import ... from "x" | import "x" | import("x")
            if line.startswith('import', i) and self._is_js_word_boundary(line, i, i + 6):
                j = self._skip_js_whitespace(line, i + 6)

                # dynamic import("x")
                if j < n and line[j] == '(':
                    j = self._skip_js_whitespace(line, j + 1)
                    module, next_idx = self._read_js_string(line, j)
                    if module:
                        modules.append(module.strip())
                        i = next_idx
                        last_sig_char = '#'
                        continue

                # side-effect import "x"
                module, next_idx = self._read_js_string(line, j)
                if module:
                    modules.append(module.strip())
                    i = next_idx
                    last_sig_char = '#'
                    continue

                # import ... from "x"
                k = j
                while k < n:
                    if line[k] in {"'", '"', '`'}:
                        _, k = self._read_js_string(line, k)
                        continue
                    if line.startswith('from', k) and self._is_js_word_boundary(line, k, k + 4):
                        k = self._skip_js_whitespace(line, k + 4)
                        module, next_idx = self._read_js_string(line, k)
                        if module:
                            modules.append(module.strip())
                        i = next_idx
                        last_sig_char = '#'
                        break
                    if line[k] == ';':
                        i = k + 1
                        break
                    k += 1
                else:
                    i = n
                continue

            # export ... from "x"
            if line.startswith('export', i) and self._is_js_word_boundary(line, i, i + 6):
                k = self._skip_js_whitespace(line, i + 6)
                while k < n:
                    if line[k] in {"'", '"', '`'}:
                        _, k = self._read_js_string(line, k)
                        continue
                    if line.startswith('from', k) and self._is_js_word_boundary(line, k, k + 4):
                        k = self._skip_js_whitespace(line, k + 4)
                        module, next_idx = self._read_js_string(line, k)
                        if module:
                            modules.append(module.strip())
                        i = next_idx
                        last_sig_char = '#'
                        break
                    if line[k] == ';':
                        i = k + 1
                        break
                    k += 1
                else:
                    i = n
                continue

            if not ch.isspace():
                last_sig_char = ch
            i += 1

        return modules

    def _normalize_dependency_name(self, module: str, ext: str) -> Optional[str]:
        """Normalize parser output into a dependency key."""
        normalized = module.strip().strip(',;')
        normalized = normalized.strip('\'"`<>').replace('\\', '/')
        if not normalized:
            return None

        if ext == '.py':
            normalized = normalized.split()[0].split('.')[0]
        elif ext in C_FAMILY_EXTS:
            parts = [part for part in normalized.split('/') if part and part not in {'.', '..'}]
            if not parts:
                return None
            first = parts[0]
            first_lower = first.lower()
            if first_lower in INTERNAL_PREFIXES:
                return None
            if first_lower in VENDOR_PREFIXES:
                if len(parts) < 2:
                    return None
                first = parts[1]
            normalized = Path(first).stem
        elif ext == '.java':
            normalized = normalized.split('.')[0]
        elif ext == '.rb':
            if normalized.startswith('.') or normalized.startswith('/'):
                return None
            normalized = normalized.split('/', 1)[0]
        elif ext == '.rs' and normalized in {'self', 'super', 'crate'}:
            return None
        elif ext in JS_TS_EXTS:
            # Skip relative imports: they are internal module references.
            if normalized.startswith('.') or normalized.startswith('/'):
                return None
            if normalized.startswith('node:'):
                normalized = normalized[5:]
            if normalized.startswith('@'):
                parts = normalized.split('/')
                if len(parts) >= 2:
                    normalized = '/'.join(parts[:2])
            else:
                normalized = normalized.split('/', 1)[0]

        return normalized or None

    def _is_builtin_dependency(self, module: str, ext: str) -> bool:
        """Return whether a module should be considered language built-in."""
        if ext == '.py':
            import sys

            return module in sys.builtin_module_names or module in {'os', 'sys', 'json', 'time', 're', 'math'}
        if ext in C_FAMILY_EXTS:
            return module in C_CPP_BUILTIN_HEADERS
        if ext == '.go':
            return '.' not in module.split('/', 1)[0]
        if ext == '.rs':
            return module in {'std', 'core', 'alloc', 'proc_macro', 'test'}
        if ext == '.java':
            return module in {'java', 'javax', 'jdk'}
        if ext == '.rb':
            return module in RUBY_BUILTINS
        if ext in JS_TS_EXTS:
            return module in NODE_BUILTIN_MODULES
        return False

    def _is_internal_dependency(
        self,
        raw_module: str,
        module: str,
        ext: str,
        importer_file: str,
        line: str,
    ) -> bool:
        """Determine whether an extracted module is internal and should be skipped."""
        raw = raw_module.strip().strip('\'"`<>').replace('\\', '/')
        if not raw:
            return True

        if ext in JS_TS_EXTS:
            return raw.startswith('.') or raw.startswith('/')

        if ext == '.rb':
            return line.startswith('require_relative') or raw.startswith('.') or raw.startswith('/')

        if ext == '.go':
            if raw.startswith('.') or raw.startswith('/'):
                return True
            module_name = self._get_go_module_name()
            if module_name and (module == module_name or module.startswith(f"{module_name}/")):
                return True
            return False

        if ext in C_FAMILY_EXTS:
            if raw in {'.', '..'} or raw.startswith('./') or raw.startswith('../') or raw.startswith('/'):
                return True

            first_segment = raw.split('/', 1)[0].lower()
            if first_segment in VENDOR_PREFIXES:
                return False
            if first_segment in INTERNAL_PREFIXES:
                return True
            if first_segment in self._repo_name_aliases():
                return True
            if re.match(r'^#\s*include\s*"', line) and self._is_local_cpp_include(raw, importer_file):
                return True
            if (
                re.match(r'^#\s*include\s*"', line)
                and '/' not in raw
                and re.search(r'\.(h|hh|hpp|hxx|inl|inc|cuh)$', raw, re.IGNORECASE)
            ):
                return True
            if module in self._repo_name_aliases():
                return True
            if self._looks_like_local_experiment_name(module):
                return True

        return False

    def _is_local_cpp_include(self, include_path: str, importer_file: str) -> bool:
        """Check whether a quoted C/C++ include resolves to a local repository path."""
        normalized = include_path.strip().replace("\\", "/")
        if not normalized:
            return True
        if normalized in {'.', '..'} or normalized.startswith(('./', '../', '/')):
            return True

        cache = getattr(self, "_cpp_local_include_cache", None)
        if cache is None:
            cache = {}
            self._cpp_local_include_cache = cache

        cache_key = (importer_file, normalized)
        if cache_key in cache:
            return cache[cache_key]

        importer_dir = self.repo_path / Path(importer_file).parent
        candidates = [importer_dir / normalized, self.repo_path / normalized]
        is_local = any(candidate.exists() for candidate in candidates)
        cache[cache_key] = is_local
        return is_local

    def _repo_name_aliases(self) -> Set[str]:
        """Generate normalized aliases for repository name matching."""
        repo_name = self.repo_path.name.lower()
        aliases = {
            repo_name,
            repo_name.replace('-', '_'),
            repo_name.replace('_', '-'),
            re.sub(r'[^a-z0-9]', '', repo_name),
        }
        return {alias for alias in aliases if alias}

    def _get_go_module_name(self) -> str:
        """Read module name from go.mod once and cache it."""
        cached = getattr(self, "_go_module_name_cache", None)
        if cached is not None:
            return cached

        module_name = ""
        go_mod_path = self.repo_path / "go.mod"
        if go_mod_path.exists():
            try:
                with open(go_mod_path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        stripped = line.strip()
                        if stripped.startswith('module '):
                            parts = stripped.split(None, 1)
                            if len(parts) == 2:
                                module_name = parts[1].strip()
                            break
            except Exception:
                module_name = ""

        self._go_module_name_cache = module_name
        return module_name
    
    
