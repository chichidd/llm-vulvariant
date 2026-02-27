"""Repository Analyzer - a CodeQL-based static analysis tool.

Capabilities:
1. Call graph analysis: extract inter-function call relationships
2. Data flow analysis: track data flows from sources to sinks
3. Program slicing: extract code relevant to a specific line
4. Dependency analysis: analyze third-party library dependencies
5. Entry point detection: identify HTTP endpoints, CLI entries, etc.

Example:
    analyzer = RepoAnalyzer("/path/to/repo", language="python")

    # Get call graph
    call_graph = analyzer.call_graph

    # Get code context around a specific line
    context = analyzer.get_code_context("main.py", 42, window=20)

    # Program slicing: find all code that influences line 42
    slice_result = analyzer.backward_slice("main.py", 42, max_depth=3)
"""

import os
import pickle
import re
from pathlib import Path
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field, asdict
from collections import defaultdict

from utils.codeql_native import CodeQLAnalyzer, load_codeql_config, CallGraphEdge
from utils.git_utils import get_git_commit

from pathlib import Path
from typing import Dict, Any, Optional

from utils.logger import get_logger

logger = get_logger(__name__)


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
    name: str
    file: str
    start_line: int
    end_line: int
    parameters: List[str] = field(default_factory=list)
    calls: List[str] = field(default_factory=list)  # Functions called by this function
    called_by: List[str] = field(default_factory=list)  # Functions that call this function
    
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


@dataclass
class SliceResult:
    """Program slicing result."""
    target: CodeLocation
    related_locations: List[Dict[str, Any]] = field(default_factory=list)
    data_flow_paths: List[List[str]] = field(default_factory=list)
    files_involved: Set[str] = field(default_factory=set)
    depth: int = 0
    
    def to_dict(self):
        """Convert to a dict (for serialization)."""
        return {
            "target": {
                "file": self.target.file,
                "line": self.target.line,
                "code": self.target.code
            },
            "related_locations": self.related_locations,
            "data_flow_paths": self.data_flow_paths,
            "files_involved": list(self.files_involved),
            "depth": self.depth
        }
    
    def to_markdown(self) -> str:
        """Convert to Markdown (for human reading)."""
        md = f"## Program Slicing Result\n\n"
        md += f"**Target location**: `{self.target.file}:{self.target.line}`\n\n"
        
        if self.target.code:
            md += f"```{self.language if hasattr(self, 'language') else 'python'}\n{self.target.code}\n```\n\n"
        
        md += f"**Analysis depth**: {self.depth}\n"
        md += f"**Files involved**: {len(self.files_involved)}\n"
        md += f"**Related code locations**: {len(self.related_locations)}\n\n"
        
        if self.data_flow_paths:
            md += "### Data Flow Paths\n\n"
            for i, path in enumerate(self.data_flow_paths, 1):
                md += f"{i}. {' → '.join(path)}\n"
            md += "\n"
        
        if self.related_locations:
            md += "### Related Code\n\n"
            for loc in self.related_locations[:10]:  # Only show the first 10
                md += f"#### {loc['file']}:{loc['start_line']}-{loc['end_line']}\n"
                md += f"**Relationship**: {loc['relationship']}\n\n"
                if loc.get('code'):
                    lang_hint = getattr(self, 'language', 'python') if hasattr(self, 'language') else 'python'
                    md += f"```{lang_hint}\n{loc['code']}\n```\n\n"
        
        return md


# ========== Main class ==========

class RepoAnalyzer:
    """
    Repository analyzer - deep static analysis using CodeQL.

    Features:
    - Automatic language detection (supports Python, C/C++)
    - Commit-hash-based caching
    - Call graph, data flow, and program slicing
    - Dependency analysis, entry point detection, and sensitive data tracking

    Args:
        repo_path: Repository path
        language: Language (auto, python, cpp)
        cache_dir: Cache directory
        max_slice_depth: Max program slice depth (default: 3)
        max_slice_files: Max number of files in a slice (default: 10)
    """
    

    def __init__(
        self,
        repo_path: str,
        language: str = "auto",
        cache_dir: Optional[str] = None,
        max_slice_depth: int = 3,
        max_slice_files: int = 10,
        rebuild_cache: bool = False
    ):
        """Initialize the analyzer."""
        self.repo_path = Path(repo_path).resolve()
        if not self.repo_path.exists():
            raise ValueError(f"Repository path does not exist: {repo_path}")
        
        self.max_slice_depth = max_slice_depth
        self.max_slice_files = max_slice_files
        
        # Auto-detect language
        if language == "auto":
            self.language = self._detect_language()
        else:
            self.language = language
        
        logger.info(f"Detected language: {self.language}")
        
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
        
        # Data storage
        self._call_graph_edges: List[CallGraphEdge] = []
        self._functions: Dict[str, FunctionInfo] = {}
        self._dependencies: Dict[str, DependencyInfo] = {}

        # Load or build analysis data
        self._load_or_build(rebuild_cache)
    
    def get_info(self):
        info = {
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
                    'callee': edge.callee_name,
                    'callee_file': edge.callee_file,
                    'callee_line': edge.callee_line,
                    'call_site_line': edge.call_site_line
                }
                for edge in call_graph
            ]
            logger.info(f"Extracted {len(info['call_graph_edges'])} call graph edges")
        
        functions = self._functions
        if functions:
            info['functions'] = [
                {
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
    
    def _detect_language(self) -> str:
        """Auto-detect the repository's primary language."""
        from utils.language import detect_language
        return detect_language(self.repo_path)
    

    def _load_or_build(self, rebuild: bool = False, cache_path: Optional[Path] = None):
        """Load cache or rebuild analysis data."""
        if cache_path is None:
            cache_path = self.cache_dir / f"{self.repo_path.name}-{self.commit_hash[:8]}-{self.language}.pkl"
        
        # Try loading cache
        if not rebuild and cache_path.exists():
            try:
                logger.info(f"Loading cache from {cache_path}")
                with open(cache_path, 'rb') as f:
                    cache_data = pickle.load(f)
                
                self._call_graph_edges = cache_data['call_graph_edges']
                self._functions = cache_data['functions']
                self._dependencies = cache_data['dependencies']

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
        try:
            cache_data = {
                'call_graph_edges': self._call_graph_edges,
                'functions': self._functions,
                'dependencies': self._dependencies,
            }
            with open(cache_path, 'wb') as f:
                pickle.dump(cache_data, f)
            logger.info(f"Cache saved to {cache_path}")
        except Exception as e:
            logger.warning(f"Failed to save cache: {e}")
    
    def _build_analysis(self):
        """Build the full analysis dataset."""
        # Step 1: Create CodeQL database
        logger.info("[1/4] Creating CodeQL database...")
        db_name = f"{self.repo_path.name}-{self.commit_hash[:8]}-{self.language}"
        success, db_path = self.codeql_analyzer.create_database(
            source_path=str(self.repo_path),
            language=self.language,
            database_name=db_name,
            overwrite=False
        )
        
        if not success:
            raise RuntimeError(f"Failed to create CodeQL database: {db_path}")
        
        self.db_path = db_path
        logger.info(f"    Database created: {db_path}")
        
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
        try:
            logger.info(f"Building call graph with CodeQL for database: {self.db_path}")
            self._call_graph_edges = self.codeql_analyzer._build_call_graph(
                self.db_path,
                self.language
            )
            logger.info(f"CodeQL returned {len(self._call_graph_edges)} call graph edges")
        except Exception as e:
            logger.warning(f"Failed to build call graph via CodeQL: {e}")
            import traceback
            logger.debug(traceback.format_exc())
            self._call_graph_edges = []
    

    
    def _extract_functions(self):
        """Extract function information from the call graph.
        
        Only includes functions with resolved file paths (excludes builtins,
        standard library, third-party packages, and unresolved dynamic calls).
        """
        # Extract functions from call graph edges
        seen_functions = set()
        skipped_unresolved = 0
        
        for edge in self._call_graph_edges:
            # Add caller (always has valid file since it's in user code)
            if edge.caller_name not in seen_functions and edge.caller_file:
                func = FunctionInfo(
                    name=edge.caller_name,
                    file=edge.caller_file,
                    start_line=edge.caller_line,
                    end_line=edge.caller_line  # Simplification
                )
                self._functions[edge.caller_name] = func
                seen_functions.add(edge.caller_name)
            
            # Add callee only if it has a valid file path
            # Skip builtins, stdlib, third-party, and unresolved dynamic calls
            if edge.callee_name not in seen_functions:
                if edge.callee_file and edge.callee_line > 0:
                    func = FunctionInfo(
                        name=edge.callee_name,
                        file=edge.callee_file,
                        start_line=edge.callee_line,
                        end_line=edge.callee_line
                    )
                    self._functions[edge.callee_name] = func
                    seen_functions.add(edge.callee_name)
                else:
                    skipped_unresolved += 1
            
            # Build call relationships (only for resolved functions)
            if edge.caller_name in self._functions:
                self._functions[edge.caller_name].calls.append(edge.callee_name)
            if edge.callee_name in self._functions:
                self._functions[edge.callee_name].called_by.append(edge.caller_name)
        
        if skipped_unresolved > 0:
            logger.debug(f"Skipped {skipped_unresolved} unresolved callee references (builtins/stdlib/third-party)")
    
    def _analyze_dependencies(self):
        """Analyze third-party library dependencies."""
        from utils.language import get_extensions, ALL_SOURCE_EXTENSIONS

        # Build set of extensions to scan for this language
        lang_exts = get_extensions(self.language)

        # Regex patterns for import extraction per extension group
        import_patterns = {
            '.py': re.compile(r'^\s*(import |from )'),
            '.go': re.compile(r'^\s*import\s'),
            '.java': re.compile(r'^\s*import\s'),
            '.rs': re.compile(r'^\s*(use |extern crate )'),
            '.rb': re.compile(r'^\s*require'),
        }
        # C/C++ headers
        c_family = {'.c', '.cpp', '.cc', '.cxx', '.h', '.hpp', '.hh'}
        # JS/TS
        js_family = {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'}

        for root, dirs, files in os.walk(self.repo_path):
            dirs[:] = [d for d in dirs if d not in {'.git', '__pycache__', 'node_modules'}]

            for file in files:
                ext = Path(file).suffix.lower()
                if ext not in lang_exts:
                    continue

                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_path, self.repo_path)

                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        for line_num, line in enumerate(f, 1):
                            stripped = line.strip()
                            # Python
                            if ext == '.py' and (stripped.startswith('import ') or stripped.startswith('from ')):
                                self._extract_import(stripped, rel_path, line_num)
                            # C/C++
                            elif ext in c_family and stripped.startswith('#include'):
                                self._extract_import(stripped, rel_path, line_num)
                            # Go / Java
                            elif ext in {'.go', '.java'} and stripped.startswith('import '):
                                self._extract_import(stripped, rel_path, line_num)
                            # JS/TS
                            elif ext in js_family and ('require(' in stripped or 'import ' in stripped):
                                self._extract_import(stripped, rel_path, line_num)
                            # Rust
                            elif ext == '.rs' and (stripped.startswith('use ') or stripped.startswith('extern crate ')):
                                self._extract_import(stripped, rel_path, line_num)
                            # Ruby
                            elif ext == '.rb' and stripped.startswith('require'):
                                self._extract_import(stripped, rel_path, line_num)
                except Exception:
                    continue
    
    def _extract_import(self, line: str, file: str, line_num: int):
        """Extract dependencies from an import statement."""
        try:
            # Simple import parsing
            if line.startswith('import '):
                modules = line[7:].split(',')
            elif line.startswith('from '):
                parts = line.split('import')
                if len(parts) >= 2:
                    modules = [parts[0][5:].split()[0]]
                else:
                    return
            else:
                return
            
            for module in modules:
                module = module.strip().split()[0].split('.')[0]
                
                if module not in self._dependencies:
                    # Determine whether this is a built-in module
                    import sys
                    is_builtin = module in sys.builtin_module_names or \
                                 module in {'os', 'sys', 'json', 'time', 're', 'math'}
                    
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
    
    # ========== Public properties ==========
    
    @property
    def call_graph(self) -> List[CallGraphEdge]:
        """Get the call graph."""
        return self._call_graph_edges
    
    @property
    def functions(self) -> Dict[str, FunctionInfo]:
        """Get all function information."""
        return self._functions
    
    @property
    def dependencies(self) -> Dict[str, DependencyInfo]:
        """Get dependency information."""
        return self._dependencies
    

    # ========== Public methods ==========
    
    def get_function_callers(self, func_name: str) -> List[FunctionInfo]:
        """Get all functions that call the specified function."""
        if func_name not in self._functions:
            return []
        
        caller_names = self._functions[func_name].called_by
        return [self._functions[name] for name in caller_names if name in self._functions]
    
    def get_function_callees(self, func_name: str) -> List[FunctionInfo]:
        """Get all functions called by the specified function."""
        if func_name not in self._functions:
            return []
        
        callee_names = self._functions[func_name].calls
        return [self._functions[name] for name in callee_names if name in self._functions]
    
    def get_code_context(
        self,
        file: str,
        line: int,
        window: int = 20
    ) -> str:
        """
        Get code context around a specific location.
        
        Args:
            file: File path (relative to the repository root)
            line: Line number
            window: Context window size (lines before/after)
        
        Returns:
            Code snippet (with line numbers)
        """
        file_path = self.repo_path / file
        if not file_path.exists():
            return f"File not found: {file}"
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            start = max(0, line - window - 1)
            end = min(len(lines), line + window)
            
            context_lines = []
            for i in range(start, end):
                line_num = i + 1
                marker = ">>>" if line_num == line else "   "
                context_lines.append(f"{marker} {line_num:4d} | {lines[i].rstrip()}")
            
            return "\n".join(context_lines)
        except Exception as e:
            return f"Error reading file: {e}"
    
    def backward_slice(
        self,
        file: str,
        line: int,
        max_depth: Optional[int] = None,
        max_files: Optional[int] = None
    ) -> SliceResult:
        """
        Backward program slicing: find all code that influences a given line.
        
        Args:
            file: File path
            line: Line number
            max_depth: Maximum tracing depth (None uses default)
            max_files: Maximum number of files (None uses default)
        
        Returns:
            A SliceResult
        """
        if max_depth is None:
            max_depth = self.max_slice_depth
        if max_files is None:
            max_files = self.max_slice_files
        
        target = CodeLocation(file=file, line=line)
        
        # Read target line code
        code = self._read_line(file, line)
        target.code = code
        
        # Find functions affecting this line
        affected_functions = self._find_functions_in_file(file, line)
        
        # Trace the call chain backwards
        related_locations = []
        data_flow_paths = []
        files_involved = {file}
        
        for func in affected_functions:
            # Get callers
            callers = self.get_function_callers(func.name)
            
            for depth in range(1, max_depth + 1):
                if len(files_involved) >= max_files:
                    break
                
                for caller in callers:
                    files_involved.add(caller.file)
                    
                    # Extract caller code
                    caller_code = self.get_code_context(caller.file, caller.start_line, window=10)
                    
                    related_locations.append({
                        "file": caller.file,
                        "start_line": caller.start_line,
                        "end_line": caller.end_line,
                        "code": caller_code,
                        "relationship": f"caller (depth {depth})",
                        "function_name": caller.name
                    })
                    
                    # Build a data-flow path
                    path = [f"{caller.file}:{caller.start_line}", f"{file}:{line}"]
                    data_flow_paths.append(path)
                
                # Continue tracing upwards
                next_callers = []
                for caller in callers:
                    next_callers.extend(self.get_function_callers(caller.name))
                callers = next_callers
                
                if not callers:
                    break
        
        result = SliceResult(
            target=target,
            related_locations=related_locations,
            data_flow_paths=data_flow_paths,
            files_involved=files_involved,
            depth=max_depth
        )
        
        return result
    
    def forward_slice(
        self,
        file: str,
        line: int,
        max_depth: Optional[int] = None,
        max_files: Optional[int] = None
    ) -> SliceResult:
        """
        Forward program slicing: find all code influenced by a given line.
        
        Args:
            file: File path
            line: Line number
            max_depth: Maximum tracing depth
            max_files: Maximum number of files
        
        Returns:
            A SliceResult
        """
        if max_depth is None:
            max_depth = self.max_slice_depth
        if max_files is None:
            max_files = self.max_slice_files
        
        target = CodeLocation(file=file, line=line)
        code = self._read_line(file, line)
        target.code = code
        
        # Find the function containing this line
        affected_functions = self._find_functions_in_file(file, line)
        
        # Trace the call chain forwards
        related_locations = []
        data_flow_paths = []
        files_involved = {file}
        
        for func in affected_functions:
            # Get callees
            callees = self.get_function_callees(func.name)
            
            for depth in range(1, max_depth + 1):
                if len(files_involved) >= max_files:
                    break
                
                for callee in callees:
                    files_involved.add(callee.file)
                    
                    # Extract callee code
                    callee_code = self.get_code_context(callee.file, callee.start_line, window=10)
                    
                    related_locations.append({
                        "file": callee.file,
                        "start_line": callee.start_line,
                        "end_line": callee.end_line,
                        "code": callee_code,
                        "relationship": f"callee (depth {depth})",
                        "function_name": callee.name
                    })
                    
                    # Build a data-flow path
                    path = [f"{file}:{line}", f"{callee.file}:{callee.start_line}"]
                    data_flow_paths.append(path)
                
                # Continue tracing downwards
                next_callees = []
                for callee in callees:
                    next_callees.extend(self.get_function_callees(callee.name))
                callees = next_callees
                
                if not callees:
                    break
        
        result = SliceResult(
            target=target,
            related_locations=related_locations,
            data_flow_paths=data_flow_paths,
            files_involved=files_involved,
            depth=max_depth
        )
        
        return result
    
    def search_pattern(self, pattern: str) -> List[CodeLocation]:
        """
        Search for a code pattern (simple text search).
        
        Args:
            pattern: Search pattern (regular expression)
        
        Returns:
            List of matching code locations
        """
        import re
        
        results = []
        regex = re.compile(pattern, re.IGNORECASE)
        
        for root, dirs, files in os.walk(self.repo_path):
            dirs[:] = [d for d in dirs if d not in {'.git', '__pycache__'}]
            
            for file in files:
                if file.endswith(('.py', '.c', '.cpp', '.h')):
                    file_path = os.path.join(root, file)
                    rel_path = os.path.relpath(file_path, self.repo_path)
                    
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            for line_num, line in enumerate(f, 1):
                                if regex.search(line):
                                    loc = CodeLocation(
                                        file=rel_path,
                                        line=line_num,
                                        code=line.strip()
                                    )
                                    results.append(loc)
                    except Exception:
                        continue
        
        return results
    
    
    # ========== Helper methods ==========
    
    def _read_line(self, file: str, line: int) -> str:
        """Read the specified line from a file."""
        file_path = self.repo_path / file
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for i, l in enumerate(f, 1):
                    if i == line:
                        return l.strip()
        except Exception as e:
            logger.debug(f"Failed to read line {line} from {file}: {e}")
        return ""
    
    def _find_functions_in_file(self, file: str, line: int) -> List[FunctionInfo]:
        """Find functions in a file that contain the specified line."""
        results = []
        
        for func in self._functions.values():
            if func.file == file and func.start_line <= line <= func.end_line:
                results.append(func)
        
        return results
    