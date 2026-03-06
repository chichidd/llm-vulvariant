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
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
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

        # Determine the repo root (llm-vulvariant/) for resolving relative paths
        if _path_config and 'repo_root' in _path_config:
            _repo_root = str(_path_config['repo_root'])
        else:
            # __file__ is src/utils/codeql_native.py → go up 3 levels to llm-vulvariant/
            _repo_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))

        # If no query path is provided, use the default (.codeql under repo root)
        if not config['queries_path']:
            config['queries_path'] = os.path.join(_repo_root, ".codeql")
        elif not os.path.isabs(config['queries_path']):
            # Resolve relative queries_path against the repo root, not the CWD
            config['queries_path'] = os.path.join(_repo_root, config['queries_path'])
        
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
class CallGraphEdge:
    """A call graph edge."""
    caller_name: str
    caller_file: str
    caller_line: int
    callee_name: str
    callee_file: str
    callee_line: int
    call_site_line: int


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
        except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError) as e:
            logger.debug(f"Failed to get CodeQL version: {e}")
        
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

    @staticmethod
    def _has_cpp_build_system(source_path: str) -> bool:
        """Return True when common C/C++ build-system indicators are present."""
        root = Path(source_path)
        indicators = {
            "CMakeLists.txt",
            "Makefile",
            "configure",
            "meson.build",
            "build.ninja",
            "compile_commands.json",
        }
        return any((root / marker).exists() for marker in indicators)

    @staticmethod
    def _is_complete_database(db_path: str) -> bool:
        """Check whether a CodeQL database directory looks complete.
        
        A valid database must have both the metadata YAML and the actual
        dataset directory (db-{language}).  An incomplete/failed creation
        may leave the YAML without the dataset.
        """
        yml_path = os.path.join(db_path, "codeql-database.yml")
        if not os.path.isfile(yml_path):
            return False
        # Read primary language and verify the dataset directory exists
        try:
            import yaml
            with open(yml_path) as f:
                info = yaml.safe_load(f)
            lang = info.get("primaryLanguage")
            if lang:
                dataset_dir = os.path.join(db_path, f"db-{lang}")
                if not os.path.isdir(dataset_dir):
                    logger.warning(
                        "Database at %s is incomplete: missing dataset directory %s",
                        db_path, dataset_dir,
                    )
                    return False
        except Exception:
            pass  # If we can't parse YAML, fall through to True for backwards compat
        return True

    @staticmethod
    def _format_codeql_error(stdout: str, stderr: str) -> str:
        """Format CodeQL command output for easier debugging."""
        stderr_text = (stderr or "").strip()
        stdout_text = (stdout or "").strip()
        if stderr_text and stdout_text:
            return f"{stderr_text}\n[stdout]\n{stdout_text}"
        if stderr_text:
            return stderr_text
        if stdout_text:
            return stdout_text
        return "Unknown CodeQL error"
    
    def create_database(
        self,
        source_path: str,
        language: str,
        database_name: Optional[str] = None,
        overwrite: bool = True
    ) -> Tuple[bool, str]:
        """
        Create a CodeQL database.
        
        Args:
            source_path: Source code path
            language: Programming language (required – no default)
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
            database_name = os.path.basename(source_path) + f"-{normalized_lang}"
        
        db_path = os.path.join(self.config['database_dir'], database_name)
        
        # If database path already exists
        if os.path.exists(db_path):
            if not overwrite and self._is_complete_database(db_path):
                return True, db_path
            # Remove incomplete database or recreate when overwrite=True.
            shutil.rmtree(db_path, ignore_errors=True)
        
        def _create_db(extra_args: Optional[List[str]] = None) -> Tuple[bool, str, str]:
            args = [
                "database", "create",
                db_path,
                f"--language={normalized_lang}",
                f"--source-root={source_path}",
            ]
            if self.config.get('threads', 0) > 0:
                args.append(f"--threads={self.config['threads']}")
            if extra_args:
                args.extend(extra_args)
            return self._run_codeql(args, timeout=1800)  # 30-minute timeout

        # C/C++ repos frequently have no build metadata at repo root (mixed-language monorepos).
        # In that case, autobuild is expected to fail and only adds noisy errors.
        if normalized_lang == "cpp" and not self._has_cpp_build_system(source_path):
            logger.info(
                "No C/C++ build system detected at %s; using --build-mode=none directly.",
                source_path,
            )
            buildless_success, buildless_stdout, buildless_stderr = _create_db(["--build-mode=none"])
            if buildless_success:
                return True, db_path
            buildless_error = self._format_codeql_error(buildless_stdout, buildless_stderr)
            logger.info(
                "C/C++ buildless mode failed; retrying default build mode. Error: %s",
                buildless_error,
            )
            if os.path.exists(db_path):
                shutil.rmtree(db_path, ignore_errors=True)
            primary_success, primary_stdout, primary_stderr = _create_db()
            if primary_success:
                return True, db_path
            primary_error = self._format_codeql_error(primary_stdout, primary_stderr)
            return False, (
                "Failed to create database. "
                f"Buildless (--build-mode=none) error: {buildless_error}\n"
                f"Default mode error: {primary_error}"
            )

        # Primary attempt (default build mode, usually autobuild for compiled languages)
        success, stdout, stderr = _create_db()
        if success:
            return True, db_path

        primary_error = self._format_codeql_error(stdout, stderr)

        # C/C++ fallback: buildless extraction avoids fragile project-specific autobuilds.
        if normalized_lang == "cpp":
            logger.info(
                "CodeQL database create failed for C/C++ with default build mode; "
                "retrying with --build-mode=none."
            )
            logger.debug("C/C++ default build-mode error: %s", primary_error)
            if os.path.exists(db_path):
                shutil.rmtree(db_path, ignore_errors=True)
            fallback_success, fallback_stdout, fallback_stderr = _create_db(["--build-mode=none"])
            if fallback_success:
                return True, db_path
            fallback_error = self._format_codeql_error(fallback_stdout, fallback_stderr)
            return False, (
                "Failed to create database. "
                f"Default mode error: {primary_error}\n"
                f"Fallback (--build-mode=none) error: {fallback_error}"
            )

        return False, f"Failed to create database: {primary_error}"
    
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
            except Exception as e:
                logger.debug(f"Failed to read database language from {db_info_path}: {e}")
        
        # Infer from directory name
        db_name = os.path.basename(database_path)
        for lang in self.SUPPORTED_LANGUAGES:
            if lang in db_name.lower():
                return lang
        
        return None  # Cannot determine – caller must handle
    
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
    
