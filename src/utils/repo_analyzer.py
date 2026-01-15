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
import json
import hashlib
import pickle
from pathlib import Path
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field, asdict
from collections import defaultdict, deque
import logging

from .codeql_native import CodeQLAnalyzer, load_codeql_config, CallGraphEdge, CodeQLFinding
from .git_utils import get_git_commit
from .logger import get_logger

# Initialize logger for this module
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
    is_entry_point: bool = False  # Whether it is an entry point (main, HTTP handler, etc.)
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
            md += f"```python\n{self.target.code}\n```\n\n"
        
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
                    md += f"```python\n{loc['code']}\n```\n\n"
        
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
    
    @classmethod
    def _load_entry_point_patterns(cls, config_path: Optional[Path] = None) -> Dict[str, List[str]]:
        """Load entry point detection rules.
        
        Args:
            config_path: Config file path; defaults to config/repo_analyzer_rules.yaml
            
        Returns:
            A dict of entry point patterns
        """
        import yaml
        
        if config_path is None:
            # Default to config/repo_analyzer_rules.yaml under project root
            project_root = Path(__file__).parent.parent.parent
            config_path = project_root / "config" / "repo_analyzer_rules.yaml"
        
        try:
            if config_path.exists():
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = yaml.safe_load(f)
                return config.get('entry_point_patterns', {})
            else:
                logger.warning(f"Config file not found: {config_path}, using default patterns")
        except Exception as e:
            logger.error(f"Failed to load entry point patterns: {e}, using defaults")
        
        # Default patterns (if config file loading fails)
        return {
            "python": ["main", "__main__"],
            "cpp": ["main"],
        }
    
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
        self._entry_points: List[FunctionInfo] = []
        self._findings: List[CodeQLFinding] = []
        
        # Load or build analysis data
        self._load_or_build(rebuild_cache)
    
    def _detect_language(self) -> str:
        """Auto-detect the repository's primary language."""
        # Count file extensions
        extensions = defaultdict(int)
        
        for root, dirs, files in os.walk(self.repo_path):
            # Skip common ignored directories
            dirs[:] = [d for d in dirs if d not in {'.git', 'node_modules', '__pycache__', 'build', 'dist'}]
            
            for file in files:
                ext = Path(file).suffix.lower()
                if ext in {'.py', '.c', '.cpp', '.cc', '.h', '.hpp'}:
                    extensions[ext] += 1
        
        # Decide primary language
        total_py = extensions.get('.py', 0)
        total_cpp = extensions.get('.cpp', 0) + extensions.get('.cc', 0) + \
                    extensions.get('.c', 0) + extensions.get('.h', 0) + extensions.get('.hpp', 0)
        
        if total_py > total_cpp:
            return "python"
        elif total_cpp > 0:
            return "cpp"
        else:
            return "python"  # Default
    
    def _get_cache_key(self) -> str:
        """Generate a cache key (based on repo path and commit hash)."""
        key_str = f"{self.repo_path}:{self.commit_hash}:{self.language}"
        return hashlib.md5(key_str.encode()).hexdigest()
    
    def _get_cache_path(self) -> Path:
        """Get the cache file path."""
        cache_key = self._get_cache_key()
        return self.cache_dir / f"{cache_key}.pkl"
    
    def _load_or_build(self, rebuild: bool = False):
        """Load cache or rebuild analysis data."""
        cache_path = self._get_cache_path()
        
        # Try loading cache
        if not rebuild and cache_path.exists():
            try:
                logger.info(f"Loading cache from {cache_path}")
                with open(cache_path, 'rb') as f:
                    cache_data = pickle.load(f)
                
                self._call_graph_edges = cache_data['call_graph_edges']
                self._functions = cache_data['functions']
                self._dependencies = cache_data['dependencies']
                self._entry_points = cache_data['entry_points']
                self._findings = cache_data.get('findings', [])
                
                logger.info(f"Cache loaded successfully")
                logger.info(f"  - Functions: {len(self._functions)}")
                logger.info(f"  - Call graph edges: {len(self._call_graph_edges)}")
                logger.info(f"  - Dependencies: {len(self._dependencies)}")
                logger.info(f"  - Entry points: {len(self._entry_points)}")
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
                'entry_points': self._entry_points,
                'findings': self._findings,
            }
            with open(cache_path, 'wb') as f:
                pickle.dump(cache_data, f)
            logger.info(f"Cache saved to {cache_path}")
        except Exception as e:
            logger.warning(f"Failed to save cache: {e}")
    
    def _build_analysis(self):
        """Build the full analysis dataset."""
        # Step 1: Create CodeQL database
        logger.info("[1/5] Creating CodeQL database...")
        db_name = f"{self.repo_path.name}-{self.commit_hash[:8]}-{self.language}-db"
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
        logger.info("[2/5] Building call graph...")
        self._build_call_graph()
        
        # Step 3: Extract function info
        logger.info("[3/5] Extracting function information...")
        self._extract_functions()
        
        # Step 4: Analyze dependencies
        logger.info("[4/5] Analyzing dependencies...")
        self._analyze_dependencies()
        
        # Step 5: Detect entry points
        logger.info("[5/5] Detecting entry points...")
        self._detect_entry_points()
        
        logger.info("[RepoAnalyzer] Analysis complete!")
        logger.info(f"  - Functions: {len(self._functions)}")
        logger.info(f"  - Call graph edges: {len(self._call_graph_edges)}")
        logger.info(f"  - Dependencies: {len(self._dependencies)}")
        logger.info(f"  - Entry points: {len(self._entry_points)}")
    
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
        """Extract function information from the call graph."""
        # Extract functions from call graph edges
        seen_functions = set()
        
        for edge in self._call_graph_edges:
            # Add caller
            if edge.caller_name not in seen_functions:
                func = FunctionInfo(
                    name=edge.caller_name,
                    file=edge.caller_file,
                    start_line=edge.caller_line,
                    end_line=edge.caller_line  # Simplification
                )
                self._functions[edge.caller_name] = func
                seen_functions.add(edge.caller_name)
            
            # Add callee
            if edge.callee_name not in seen_functions:
                func = FunctionInfo(
                    name=edge.callee_name,
                    file=edge.callee_file,
                    start_line=edge.callee_line,
                    end_line=edge.callee_line
                )
                self._functions[edge.callee_name] = func
                seen_functions.add(edge.callee_name)
            
            # Build call relationships
            if edge.caller_name in self._functions:
                self._functions[edge.caller_name].calls.append(edge.callee_name)
            if edge.callee_name in self._functions:
                self._functions[edge.callee_name].called_by.append(edge.caller_name)
    
    def _analyze_dependencies(self):
        """Analyze third-party library dependencies."""
        # Scan import statements
        for root, dirs, files in os.walk(self.repo_path):
            dirs[:] = [d for d in dirs if d not in {'.git', '__pycache__', 'node_modules'}]
            
            for file in files:
                if file.endswith('.py'):
                    file_path = os.path.join(root, file)
                    rel_path = os.path.relpath(file_path, self.repo_path)
                    
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            for line_num, line in enumerate(f, 1):
                                line = line.strip()
                                if line.startswith('import ') or line.startswith('from '):
                                    self._extract_import(line, rel_path, line_num)
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
        except Exception:
            pass
    
    def _detect_entry_points(self):
        """Detect entry point functions."""
        entry_point_patterns = self._load_entry_point_patterns()
        patterns = entry_point_patterns.get(self.language, [])
        
        for func in self._functions.values():
            # Check whether the function name matches entry point patterns
            func_name_lower = func.name.lower()
            
            for pattern in patterns:
                if pattern in func_name_lower:
                    func.is_entry_point = True
                    self._entry_points.append(func)
                    break
            
            # Special case: functions not called by others may be entry points
            if not func.called_by and len(func.calls) > 0:
                if func not in self._entry_points:
                    func.is_entry_point = True
                    self._entry_points.append(func)
    
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
    
    @property
    def entry_points(self) -> List[FunctionInfo]:
        """Get entry point functions."""
        return self._entry_points
    
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
    
    def find_data_flow(
        self,
        source_pattern: str,
        sink_pattern: str,
        max_paths: int = 10
    ) -> List[List[str]]:
        """
        Find data-flow paths from source to sink.
        
        Args:
            source_pattern: Source function name pattern (substring match)
            sink_pattern: Sink function name pattern (substring match)
            max_paths: Maximum number of paths to return
        
        Returns:
            A list of paths; each path is a list of function names
        """
        # Find matching source and sink functions
        sources = [f for name, f in self._functions.items() 
                   if source_pattern.lower() in name.lower()]
        sinks = [f for name, f in self._functions.items() 
                 if sink_pattern.lower() in name.lower()]
        
        if not sources or not sinks:
            return []
        
        # BFS search for paths
        all_paths = []
        
        for source in sources:
            for sink in sinks:
                paths = self._find_paths_bfs(source.name, sink.name, max_depth=10)
                all_paths.extend(paths)
                
                if len(all_paths) >= max_paths:
                    return all_paths[:max_paths]
        
        return all_paths[:max_paths]
    
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
    
    def get_summary(self) -> Dict[str, Any]:
        """Get an analysis summary."""
        return {
            "repo_path": str(self.repo_path),
            "language": self.language,
            "commit_hash": self.commit_hash,
            "statistics": {
                "total_functions": len(self._functions),
                "call_graph_edges": len(self._call_graph_edges),
                "dependencies": {
                    "total": len(self._dependencies),
                    "third_party": sum(1 for d in self._dependencies.values() if d.is_third_party),
                    "builtin": sum(1 for d in self._dependencies.values() if d.is_builtin),
                },
                "entry_points": len(self._entry_points),
            },
            "entry_points": [
                {"name": ep.name, "file": ep.file, "line": ep.start_line}
                for ep in self._entry_points[:10]  # Only show the first 10
            ],
            "top_dependencies": [
                {"name": name, "import_count": len(dep.import_locations)}
                for name, dep in sorted(
                    self._dependencies.items(),
                    key=lambda x: len(x[1].import_locations),
                    reverse=True
                )[:10]
            ]
        }
    
    # ========== Helper methods ==========
    
    def _read_line(self, file: str, line: int) -> str:
        """Read the specified line from a file."""
        file_path = self.repo_path / file
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for i, l in enumerate(f, 1):
                    if i == line:
                        return l.strip()
        except Exception:
            pass
        return ""
    
    def _find_functions_in_file(self, file: str, line: int) -> List[FunctionInfo]:
        """Find functions in a file that contain the specified line."""
        results = []
        
        for func in self._functions.values():
            if func.file == file and func.start_line <= line <= func.end_line:
                results.append(func)
        
        return results
    
    def _find_paths_bfs(
        self,
        start: str,
        end: str,
        max_depth: int
    ) -> List[List[str]]:
        """BFS search for function call paths."""
        if start not in self._functions or end not in self._functions:
            return []
        
        paths = []
        queue = deque([(start, [start])])
        visited = set()
        
        while queue:
            current, path = queue.popleft()
            
            if len(path) > max_depth:
                continue
            
            if current == end:
                paths.append(path)
                continue
            
            if current in visited:
                continue
            visited.add(current)
            
            # Get called functions
            if current in self._functions:
                for callee in self._functions[current].calls:
                    if callee not in path:  # Avoid cycles
                        queue.append((callee, path + [callee]))
        
        return paths
