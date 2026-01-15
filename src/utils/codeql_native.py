"""A native CodeQL analyzer.

This module provides a wrapper around the GitHub CodeQL CLI, including:
1. Database creation
2. Query execution
3. Result parsing
4. Cross-function / cross-file call graph construction


### Method 1: Use CodeQLAnalyzer (recommended)

```python
from utils.codeql_native import CodeQLAnalyzer
import logging

logger = logging.getLogger(__name__)

# Initialize analyzer
analyzer = CodeQLNativeAnalyzer()

# Create database
success, db_path = analyzer.create_database(
    source_path="/path/to/repo",
    language="python",
    database_name="my_project"
)

logger.info(f"Database path: {db_path}")
```

### Method 2: Use CodeQL CLI directly

```bash
# Set environment variables
export PATH="$HOME/.codeql/codeql-cli/codeql:$PATH"

# Create database
codeql database create my_db --language=python --source-root=/path/to/repo

# Run analysis (requires query packs)
codeql database analyze my_db --format=sarif-latest --output=results.sarif
```
"""

import json
import os
import subprocess
import tempfile
import shutil
from pathlib import Path
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime

from utils.logger import get_logger

# Initialize logger for this module
logger = get_logger(__name__)


def load_codeql_config(config_path: Optional[Path] = None) -> Dict[str, Any]:
    """
    Load CodeQL configuration from a config file.
    
    Args:
        config_path: Config file path; uses the default path if not provided
        
    Returns:
        A dict containing CodeQL configuration
    """
    try:
        import yaml
        from pathlib import Path
        
        # Try importing the config module (to obtain default paths)
        try:
            from config import _path_config
        except ImportError:
            logger.debug("Could not import config module in load_codeql_config")
            _path_config = None
        
        # Default config file path
        if config_path is None:
            config_path = Path(__file__).parent.parent.parent / "config" / "codeql_config.yaml"
        
        config = {}
        
        if config_path.exists():
            with open(config_path, 'r', encoding='utf-8') as f:
                yaml_config = yaml.safe_load(f)
            
            codeql_cli = yaml_config.get('codeql_cli', {})
            config['cli_path'] = codeql_cli.get('cli_path', '')
            config['queries_path'] = codeql_cli.get('queries_path', '')
            config['database_dir'] = codeql_cli.get('database_dir', '')
            config['threads'] = codeql_cli.get('threads', 0)
            config['memory'] = codeql_cli.get('memory', 0)
            config['timeout'] = codeql_cli.get('timeout', 600)
        else:
            # Use defaults
            config = {
                'cli_path': '',
                'queries_path': '',
                'database_dir': '',
                'threads': 0,
                'memory': 0,
                'timeout': 600
            }
        
        logger.debug(f"Loaded CodeQL config: queries_path={config.get('queries_path')}, database_dir={config.get('database_dir')}")
        # If no query path is provided, use the default (.codeql under project root)
        if not config['queries_path']:
            if _path_config:
                config['queries_path'] = os.path.join(str(_path_config['project_root']), ".codeql")
            else:
                # If config cannot be imported, fall back to computing the project root
                project_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
                config['queries_path'] = os.path.join(project_root, ".codeql")
        
        # If no database directory is provided, use the project's configured path
        if not config['database_dir']:
            if _path_config:
                config['database_dir'] = str(_path_config['codeql_db_path'])
            else:
                # If config cannot be imported, fall back to a temp directory
                config['database_dir'] = os.path.join(tempfile.gettempdir(), "codeql-dbs")
        
        # Ensure database directory exists
        os.makedirs(config['database_dir'], exist_ok=True)
        
        return config
        
    except Exception as e:
        # If loading fails, return defaults
        logger.error(f"Failed to load CodeQL config: {e}")
        import traceback
        logger.debug(traceback.format_exc())
        default_config = {
            'cli_path': '',
            'queries_path': os.path.join(os.path.dirname(__file__), "codeql", "queries"),
            'database_dir': os.path.join(tempfile.gettempdir(), "codeql-dbs"),
            'threads': 0,
            'memory': 0,
            'timeout': 600
        }
        os.makedirs(default_config['database_dir'], exist_ok=True)
        return default_config


@dataclass
class CodeQLFinding:
    """A finding reported by CodeQL."""
    rule_id: str
    severity: str
    message: str
    file_path: str
    start_line: int
    end_line: int
    start_column: int
    end_column: int
    cwe_ids: List[str] = field(default_factory=list)
    
    # Data-flow path (for taint analysis results)
    source: Optional[Dict[str, Any]] = None
    sink: Optional[Dict[str, Any]] = None
    path_nodes: List[Dict[str, Any]] = field(default_factory=list)


@dataclass 
class CallGraphEdge:
    """A call graph edge."""
    caller_name: str
    caller_file: str
    caller_line: int
    callee_name: str
    callee_file: str
    callee_line: int
    call_site_line: int


@dataclass
class CodeQLAnalysisResult:
    """CodeQL analysis result."""
    success: bool
    database_path: str
    query_results: Dict[str, List[CodeQLFinding]] = field(default_factory=dict)
    call_graph: List[CallGraphEdge] = field(default_factory=list)
    statistics: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    execution_time: float = 0.0


class CodeQLAnalyzer:
    """
    A native CodeQL analyzer.
    
    Uses the GitHub CodeQL CLI to analyze code. Supports:
    - Creating CodeQL databases
    - Running custom and standard queries
    - Building cross-function / cross-file call graphs
    - Taint analysis
    """
    
    # Supported languages and their aliases
    SUPPORTED_LANGUAGES = {
        "python": ["python", "py"],
        "javascript": ["javascript", "js", "typescript", "ts"],
        "java": ["java"],
        "csharp": ["csharp", "cs", "c#"],
        "cpp": ["cpp", "c++", "c"],
        "go": ["go", "golang"],
        "ruby": ["ruby", "rb"],
    }
    
    # Predefined query suites
    QUERY_SUITES = {
        "security": "codeql/{lang}-queries:codeql-suites/{lang}-security-extended.qls",
        "quality": "codeql/{lang}-queries:codeql-suites/{lang}-code-quality.qls",
        "all": "codeql/{lang}-queries:codeql-suites/{lang}-security-and-quality.qls",
    }
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the CodeQL analyzer.
        
        Args:
            config: CodeQL config dict; if not provided it is loaded from config/codeql_config.yaml
        """
        self.config = config if config is not None else load_codeql_config()
        logger.debug(f"CodeQLAnalyzer initialized with queries_path: {self.config.get('queries_path')}")
        self._codeql_cmd = self._find_codeql()
        self._verify_installation()
    
    def _find_codeql(self) -> str:
        """Locate the CodeQL CLI."""
        if self.config.get('cli_path'):
            return self.config['cli_path']
        
        # Try finding via PATH
        result = shutil.which("codeql")
        if result:
            return result
        
        # Try common installation locations
        common_paths = [
            os.path.expanduser("~/.codeql/codeql-cli/codeql/codeql"),
            "/opt/codeql/codeql",
            "/usr/local/bin/codeql",
        ]
        for path in common_paths:
            if os.path.isfile(path) and os.access(path, os.X_OK):
                return path
        
        return "codeql"  # Assume it is available in PATH
    
    def _verify_installation(self) -> bool:
        """Verify CodeQL installation."""
        try:
            result = subprocess.run(
                [self._codeql_cmd, "version", "--format=json"],
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode == 0:
                version_info = json.loads(result.stdout)
                self._version = version_info.get("version", "unknown")
                return True
        except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
            pass
        
        self._version = None
        return False
    
    @property
    def is_available(self) -> bool:
        """Whether CodeQL is available."""
        return self._version is not None
    
    @property
    def version(self) -> Optional[str]:
        """CodeQL version."""
        return self._version
    
    def _run_codeql(self, args: List[str], timeout: Optional[int] = None) -> Tuple[bool, str, str]:
        """Run a CodeQL command."""
        cmd = [self._codeql_cmd] + args
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout or self.config.get('timeout', 600)
            )
            return result.returncode == 0, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return False, "", "Command timed out"
        except Exception as e:
            return False, "", str(e)
    
    def create_database(
        self,
        source_path: str,
        language: str = "python",
        database_name: Optional[str] = None,
        overwrite: bool = True
    ) -> Tuple[bool, str]:
        """
        Create a CodeQL database.
        
        Args:
            source_path: Source code path
            language: Programming language
            database_name: Database name
            overwrite: Whether to overwrite an existing database
        
        Returns:
            (success, database path or error message)
        """
        source_path = os.path.abspath(source_path)
        
        if not os.path.exists(source_path):
            return False, f"Source path does not exist: {source_path}"
        
        # Normalize language name
        lang_lower = language.lower()
        normalized_lang = None
        for lang, aliases in self.SUPPORTED_LANGUAGES.items():
            if lang_lower in aliases:
                normalized_lang = lang
                break
        
        if not normalized_lang:
            return False, f"Unsupported language: {language}"
        
        # Determine database path
        if not database_name:
            database_name = os.path.basename(source_path) + f"-{normalized_lang}-db"
        
        db_path = os.path.join(self.config['database_dir'], database_name)
        
        # If database already exists
        if os.path.exists(db_path):
            if overwrite:
                shutil.rmtree(db_path)
            else:
                return True, db_path  # Use existing database
        
        # Build command
        args = [
            "database", "create",
            db_path,
            f"--language={normalized_lang}",
            f"--source-root={source_path}",
        ]
        
        if self.config.get('threads', 0) > 0:
            args.append(f"--threads={self.config['threads']}")
        
        # Execute creation
        success, stdout, stderr = self._run_codeql(args, timeout=1800)  # 30-minute timeout
        
        if success:
            return True, db_path
        else:
            return False, f"Failed to create database: {stderr}"
    
    def run_query(
        self,
        database_path: str,
        query: str,
        output_format: str = "sarif-latest"
    ) -> Tuple[bool, Any]:
        """
        Run a CodeQL query.
        
        Args:
            database_path: Database path
            query: Query path or query suite name
            output_format: Output format (sarif-latest, csv, json)
        
        Returns:
            (success, query result or error message)
        """
        if not os.path.exists(database_path):
            return False, f"Database does not exist: {database_path}"
        
        # Determine query path
        query_path = query
        if not os.path.exists(query):
            # Possibly a built-in query suite
            if query in self.QUERY_SUITES:
                # Infer language from database
                lang = self._get_database_language(database_path)
                if lang:
                    query_path = self.QUERY_SUITES[query].format(lang=lang)
            else:
                # Try custom queries directory
                custom_query = os.path.join(self.config['queries_path'], query)
                if os.path.exists(custom_query):
                    query_path = custom_query
        
        # Create a temporary output file
        with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as f:
            output_path = f.name
        
        try:
            logger.debug(f"Running query on database: {database_path}, query: {query_path}")
            args = [
                "database", "analyze",
                database_path,
                query_path,
                f"--format={output_format}",
                f"--output={output_path}",
                "--sarif-add-snippets",
            ]
            
            if self.config.get('threads', 0) > 0:
                args.append(f"--threads={self.config['threads']}")
            
            success, stdout, stderr = self._run_codeql(args)
            
            if success and os.path.exists(output_path):
                with open(output_path, 'r') as f:
                    result = json.load(f)
                return True, result
            else:
                return False, f"Query failed: {stderr}"
        finally:
            if os.path.exists(output_path):
                os.unlink(output_path)
    
    def _get_database_language(self, database_path: str) -> Optional[str]:
        """Get language information from a database."""
        db_info_path = os.path.join(database_path, "codeql-database.yml")
        if os.path.exists(db_info_path):
            try:
                import yaml
                with open(db_info_path) as f:
                    info = yaml.safe_load(f)
                    return info.get("primaryLanguage")
            except:
                pass
        
        # Infer from directory name
        db_name = os.path.basename(database_path)
        for lang in self.SUPPORTED_LANGUAGES:
            if lang in db_name.lower():
                return lang
        
        return "python"  # Default
    
    def analyze(
        self,
        source_path: str,
        language: str = "python",
        queries: Optional[List[str]] = None,
        include_call_graph: bool = True
    ) -> CodeQLAnalysisResult:
        """
        Full analysis workflow.
        
        Args:
            source_path: Source code path
            language: Programming language
            queries: List of queries to run; None means using default security queries
            include_call_graph: Whether to include call graph analysis
        
        Returns:
            CodeQLAnalysisResult
        """
        start_time = datetime.now()
        result = CodeQLAnalysisResult(
            success=False,
            database_path=""
        )
        
        # Check whether CodeQL is available
        if not self.is_available:
            result.errors.append("CodeQL is not installed or not in PATH")
            return result
        
        # Create database
        success, db_path_or_error = self.create_database(source_path, language)
        if not success:
            result.errors.append(db_path_or_error)
            return result
        
        result.database_path = db_path_or_error
        
        # Determine which queries to run
        if queries is None:
            queries = self._get_default_queries(language)
        
        # Run queries
        for query in queries:
            query_success, query_result = self.run_query(result.database_path, query)
            
            if query_success:
                findings = self._parse_sarif_results(query_result)
                query_name = os.path.basename(query).replace(".ql", "")
                result.query_results[query_name] = findings
            else:
                result.errors.append(f"Query '{query}' failed: {query_result}")
        
        # Build call graph
        if include_call_graph:
            call_graph = self._build_call_graph(result.database_path, language)
            result.call_graph = call_graph
        
        # Statistics
        result.statistics = {
            "total_findings": sum(len(f) for f in result.query_results.values()),
            "findings_by_query": {k: len(v) for k, v in result.query_results.items()},
            "call_graph_edges": len(result.call_graph),
        }
        
        result.success = True
        result.execution_time = (datetime.now() - start_time).total_seconds()
        
        return result
    
    def _get_default_queries(self, language: str) -> List[str]:
        """Get the default query list."""
        queries_dir = os.path.join(self.config['queries_path'], language)
        
        if os.path.exists(queries_dir):
            return [
                os.path.join(queries_dir, f)
                for f in os.listdir(queries_dir)
                if f.endswith(".ql")
            ]
        
        # Use built-in security queries
        return ["security"]
    
    def _parse_sarif_results(self, sarif: Dict) -> List[CodeQLFinding]:
        """Parse SARIF-format results."""
        findings = []
        
        for run in sarif.get("runs", []):
            # Collect rule metadata
            rules = {}
            for rule in run.get("tool", {}).get("driver", {}).get("rules", []):
                rules[rule["id"]] = rule
            
            # Parse results
            for result in run.get("results", []):
                rule_id = result.get("ruleId", "")
                rule_info = rules.get(rule_id, {})
                
                # Extract location info
                locations = result.get("locations", [{}])
                if locations:
                    location = locations[0].get("physicalLocation", {})
                    artifact = location.get("artifactLocation", {})
                    region = location.get("region", {})
                    
                    file_path = artifact.get("uri", "")
                    start_line = region.get("startLine", 0)
                    end_line = region.get("endLine", start_line)
                    start_col = region.get("startColumn", 0)
                    end_col = region.get("endColumn", 0)
                else:
                    file_path = ""
                    start_line = end_line = start_col = end_col = 0
                
                # Determine severity
                severity = "warning"
                if "security-severity" in rule_info.get("properties", {}):
                    sec_sev = float(rule_info["properties"]["security-severity"])
                    if sec_sev >= 9.0:
                        severity = "critical"
                    elif sec_sev >= 7.0:
                        severity = "high"
                    elif sec_sev >= 4.0:
                        severity = "medium"
                    else:
                        severity = "low"
                
                # Collect CWE IDs
                cwe_ids = []
                for tag in rule_info.get("properties", {}).get("tags", []):
                    if tag.startswith("external/cwe/cwe-"):
                        cwe_ids.append(tag.replace("external/cwe/", "").upper())
                
                # Parse data-flow path
                source = None
                sink = None
                path_nodes = []
                
                code_flows = result.get("codeFlows", [])
                if code_flows:
                    thread_flows = code_flows[0].get("threadFlows", [])
                    if thread_flows:
                        locations = thread_flows[0].get("locations", [])
                        for i, loc in enumerate(locations):
                            node_info = self._parse_flow_location(loc)
                            if i == 0:
                                source = node_info
                            elif i == len(locations) - 1:
                                sink = node_info
                            else:
                                path_nodes.append(node_info)
                
                finding = CodeQLFinding(
                    rule_id=rule_id,
                    severity=severity,
                    message=result.get("message", {}).get("text", ""),
                    file_path=file_path,
                    start_line=start_line,
                    end_line=end_line,
                    start_column=start_col,
                    end_column=end_col,
                    cwe_ids=cwe_ids,
                    source=source,
                    sink=sink,
                    path_nodes=path_nodes
                )
                findings.append(finding)
        
        return findings
    
    def _parse_flow_location(self, location: Dict) -> Dict[str, Any]:
        """Parse a data-flow location."""
        phys_loc = location.get("location", {}).get("physicalLocation", {})
        artifact = phys_loc.get("artifactLocation", {})
        region = phys_loc.get("region", {})
        
        return {
            "file": artifact.get("uri", ""),
            "line": region.get("startLine", 0),
            "column": region.get("startColumn", 0),
            "snippet": region.get("snippet", {}).get("text", ""),
            "message": location.get("location", {}).get("message", {}).get("text", "")
        }
    
    def _build_call_graph(self, database_path: str, language: str) -> List[CallGraphEdge]:
        """Build a call graph."""
        call_graph_query = os.path.join(
            self.config['queries_path'], language, "call_graph.ql"
        )
        
        logger.info(f"Looking for call graph query at: {call_graph_query}")
        
        if not os.path.exists(call_graph_query):
            logger.warning(f"Call graph query file not found: {call_graph_query}")
            logger.info(f"Queries path: {self.config['queries_path']}")
            return []
        
        logger.info(f"Found call graph query, executing against database: {database_path}")
        
        # Two-step approach: query run + bqrs decode
        # Because database analyze requires @kind metadata
        with tempfile.NamedTemporaryFile(suffix=".bqrs", delete=False) as f:
            bqrs_path = f.name
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            csv_path = f.name
        
        try:
            # Step 1: Run query
            args = [
                "query", "run",
                call_graph_query,
                f"--database={database_path}",
                f"--output={bqrs_path}",
            ]
            
            logger.debug(f"Running CodeQL query: codeql {' '.join(args)}")
            success, stdout, stderr = self._run_codeql(args)
            
            if not success:
                logger.warning(f"CodeQL query run failed. Stderr: {stderr}")
                return []
            
            # Step 2: Decode BQRS to CSV
            args = [
                "bqrs", "decode",
                "--format=csv",
                bqrs_path,
                f"--output={csv_path}",
            ]
            
            logger.debug(f"Decoding BQRS: codeql {' '.join(args)}")
            success, stdout, stderr = self._run_codeql(args)
            
            if not success:
                logger.warning(f"CodeQL bqrs decode failed. Stderr: {stderr}")
                return []
            
            if os.path.exists(csv_path):
                edges = self._parse_call_graph_csv(csv_path)
                logger.info(f"Parsed {len(edges)} call graph edges from CodeQL results")
                return edges
            else:
                logger.warning(f"CodeQL CSV output not found: {csv_path}")
                return []
        except Exception as e:
            logger.error(f"Error building call graph: {e}")
            import traceback
            logger.debug(traceback.format_exc())
            return []
        finally:
            for tmp_file in [bqrs_path, csv_path]:
                if os.path.exists(tmp_file):
                    os.unlink(tmp_file)
        
        return []
    
    def _parse_call_graph_csv(self, csv_path: str) -> List[CallGraphEdge]:
        """Parse call graph CSV."""
        edges = []
        
        with open(csv_path, 'r') as f:
            import csv
            reader = csv.DictReader(f)
            for row in reader:
                try:
                    edge = CallGraphEdge(
                        caller_name=row.get("caller_name", ""),
                        caller_file=row.get("caller_file", ""),
                        caller_line=int(row.get("caller_line", 0)),
                        callee_name=row.get("callee_name", ""),
                        callee_file=row.get("callee_file", ""),
                        callee_line=int(row.get("callee_line", 0)),
                        call_site_line=int(row.get("call_site_line", 0))
                    )
                    edges.append(edge)
                except (ValueError, KeyError):
                    continue
        
        return edges
    
    def find_paths_to_sink(
        self,
        call_graph: List[CallGraphEdge],
        sink_name: str,
        max_depth: int = 10
    ) -> List[List[str]]:
        """
        Find all paths that reach a sink in the call graph.
        
        Args:
            call_graph: List of call graph edges
            sink_name: Target sink function name (substring match)
            max_depth: Maximum search depth
        
        Returns:
            A list of paths; each path is a list of function names
        """
        # Build graphs
        graph = {}  # caller -> [callees]
        reverse_graph = {}  # callee -> [callers]
        
        for edge in call_graph:
            caller = edge.caller_name
            callee = edge.callee_name
            
            if caller not in graph:
                graph[caller] = []
            graph[caller].append(callee)
            
            if callee not in reverse_graph:
                reverse_graph[callee] = []
            reverse_graph[callee].append(caller)
        
        # Find matching sinks
        sinks = [name for name in reverse_graph if sink_name in name]
        
        # Reverse search from sinks
        all_paths = []
        for sink in sinks:
            paths = self._find_paths_bfs(reverse_graph, sink, max_depth)
            all_paths.extend(paths)
        
        return all_paths
    
    def _find_paths_bfs(
        self,
        graph: Dict[str, List[str]],
        start: str,
        max_depth: int
    ) -> List[List[str]]:
        """BFS search for paths."""
        paths = []
        queue = [(start, [start])]
        
        while queue:
            node, path = queue.pop(0)
            
            if len(path) > max_depth:
                continue
            
            if node not in graph or not graph[node]:
                # Reached entry point
                paths.append(list(reversed(path)))
            else:
                for next_node in graph[node]:
                    if next_node not in path:  # Avoid cycles
                        queue.append((next_node, path + [next_node]))
        
        return paths
    


