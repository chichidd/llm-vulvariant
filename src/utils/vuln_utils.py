import json
from typing import List, Dict, Any
from pathlib import Path
from config import _path_config
from .git_utils import get_git_commit, checkout_commit, restore_to_latest_commit
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
        if verbose:
            logger.info(f"Processing repository: {data['repo_name']} at commit {data['commit']}")
        # check the repo has the same commit number as the commit, if not, checkout to that commit
        current_commit = get_git_commit(repo_path)
        if current_commit != data['commit']:
            if verbose:
                logger.info(f"Checking out {data['repo_name']} to commit {data['commit']} (current: {current_commit})")
            checkout_commit(repo_path, data['commit'])
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
                call_chain_dict.append({'file_path': file_relative_path, 'function_name': function_name, 'file_content': code_content, 'code_snippet': snippet})
            else:
                call_chain_dict.append({'vuln_sink': callsite})
        data['call_chain'] = call_chain_dict
        data['payload'] = entry['payload']
        repos.append(data)
        restore_to_latest_commit(repo_path)
    return repos
