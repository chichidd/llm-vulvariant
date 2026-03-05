import json
from typing import List, Dict, Any
from pathlib import Path
from config import _path_config
from .git_utils import (
    checkout_commit,
    get_git_commit,
    get_git_restore_target,
    has_uncommitted_changes,
    restore_git_position,
)
from .logger import get_logger
from utils.llm_utils import extract_function_snippet_based_on_name_with_ast

logger = get_logger(__name__)

def read_vuln_data(index=None, verbose: bool = False, vuln_json_path: str | Path | None = None) -> List[Dict[str, Any]]:
    if verbose:
        logger.info("Reading vulnerability data...")
    source_path = Path(vuln_json_path).expanduser() if vuln_json_path else _path_config['vuln_data_path']
    with open(source_path, 'r', encoding='utf-8') as f:
        rawdata = json.load(f)
    repos = []
    if index is not None:
        rawdata = [rawdata[index]]
    for entry in rawdata:
        data = {}
        data['repo_name'] = entry['repo_name']
        data['commit'] = entry['commit']
        data['cve_id'] = entry.get('cve_id', None)
        repo_path = _path_config['repo_base_path'] / data['repo_name']
        restore_target = get_git_restore_target(str(repo_path))
        switched_commit = False
        if verbose:
            logger.info(f"Processing repository: {data['repo_name']} at commit {data['commit']}")
        try:
            # check the repo has the same commit number as the commit, if not, checkout to that commit
            current_commit = get_git_commit(repo_path)
            if current_commit != data['commit']:
                if has_uncommitted_changes(repo_path):
                    raise RuntimeError(
                        f"Repository {data['repo_name']} has local changes; "
                        f"refuse commit switch to {data['commit']}"
                    )
                if verbose:
                    logger.info(
                        f"Checking out {data['repo_name']} to commit {data['commit']} "
                        f"(current: {current_commit})"
                    )
                if not checkout_commit(repo_path, data['commit']):
                    raise RuntimeError(
                        f"Failed to checkout {data['repo_name']} to commit {data['commit']}"
                    )
                switched_commit = True
            else:
                if verbose:
                    logger.info(f"{data['repo_name']} is already at commit {data['commit']}")

            call_chain_dict = []
            for callsite in entry['call_chain']:
                if '#' in callsite:
                    file_relative_path, function_name = callsite.split('#')

                    code_content = (repo_path / file_relative_path).read_text(encoding='utf-8', errors='ignore')
                    snippet = extract_function_snippet_based_on_name_with_ast(
                            code_content,
                            function_name,
                            with_line_numbers=True,
                            line_number_format="standard"
                        )
                    if verbose:
                        logger.info(f"\n{'-'*40}\nFile: {file_relative_path}, Function: {function_name}\n{'-'*40}")
                        logger.info(snippet)
                    call_chain_dict.append(
                        {
                            'file_path': file_relative_path,
                            'function_name': function_name,
                            'file_content': code_content,
                            'code_snippet': snippet,
                        }
                    )
                else:
                    call_chain_dict.append({'vuln_sink': callsite})
            data['call_chain'] = call_chain_dict
            data['payload'] = entry['payload']
            repos.append(data)
        finally:
            if switched_commit and restore_target:
                restore_git_position(repo_path, restore_target)
    return repos
