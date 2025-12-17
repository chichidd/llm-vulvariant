import json
from pathlib import Path
from typing import List, Dict, Any, Optional
from core.config import VULN_DATA_PATH, REPO_BASE_PATH
from .git_utils import get_git_commit, checkout_commit

def filter_by_repo(data: List[Dict[str, Any]], repo_name: str) -> List[Dict[str, Any]]:
    """
    Filter vulnerabilities by repository name.
    
    Args:
        data: List of vulnerability entries
        repo_name: Repository name to filter by
        
    Returns:
        Filtered list of entries
    """
    return [entry for entry in data if entry['repo_name'].lower() == repo_name.lower()]


def filter_by_commit(data: List[Dict[str, Any]], commit: str) -> List[Dict[str, Any]]:
    """
    Filter vulnerabilities by commit hash.
    
    Args:
        data: List of vulnerability entries
        commit: Commit hash to filter by (can be partial)
        
    Returns:
        Filtered list of entries
    """
    return [entry for entry in data if entry['commit'].startswith(commit)]


def filter_by_cve(data: List[Dict[str, Any]], cve_id: str) -> Optional[Dict[str, Any]]:
    """
    Find vulnerability by CVE ID.
    
    Args:
        data: List of vulnerability entries
        cve_id: CVE identifier
        
    Returns:
        The entry with matching CVE ID, or None
    """
    for entry in data:
        if entry.get('cve_id') == cve_id:
            return entry
    return None


def get_all_repos(data: List[Dict[str, Any]]) -> List[str]:
    """
    Get list of unique repository names.
    
    Args:
        data: List of vulnerability entries
        
    Returns:
        List of unique repository names
    """
    return list(set(entry['repo_name'] for entry in data))


def get_all_paths(data: List[Dict[str, Any]]) -> List[str]:
    """
    Get list of all unique file paths across all vulnerabilities.
    
    Args:
        data: List of vulnerability entries
        
    Returns:
        List of unique file paths
    """
    all_paths = set()
    for entry in data:
        all_paths.update(entry.get('paths', []))
    return sorted(list(all_paths))


def display_entry(entry: Dict[str, Any], show_payload: bool = True) -> None:
    """
    Display a single vulnerability entry in a readable format.
    
    Args:
        entry: Vulnerability entry dictionary
        show_payload: Whether to show the full payload
    """
    print(f"\n{'='*80}")
    print(f"Repository: {entry['repo_name']}")
    print(f"Commit: {entry['commit']}")
    if entry.get('cve_id'):
        print(f"CVE ID: {entry['cve_id']}")
    
    print(f"\nFile Paths ({len(entry.get('paths', []))}):")
    if entry.get('paths'):
        for path in entry['paths']:
            print(f"  - {path}")
    else:
        print("  (none - module-level calls only)")
    
    print(f"\nCall Chain ({len(entry['call_chain'])} steps):")
    for i, call in enumerate(entry['call_chain'], start=1):
        print(f"  {i}. {call}")
    
    if show_payload:
        print(f"\nPayload:")
        print(f"{'-'*80}")
        print(entry['payload'])
        print(f"{'-'*80}")


def display_summary(data: List[Dict[str, Any]]) -> None:
    """
    Display summary statistics of the vulnerability data.
    
    Args:
        data: List of vulnerability entries
    """
    print(f"\n{'='*80}")
    print("VULNERABILITY DATA SUMMARY")
    print(f"{'='*80}")
    print(f"Total entries: {len(data)}")
    
    repos = get_all_repos(data)
    print(f"\nRepositories ({len(repos)}):")
    for repo in repos:
        count = len(filter_by_repo(data, repo))
        print(f"  - {repo}: {count} vulnerabilities")
    
    cve_entries = [e for e in data if e.get('cve_id')]
    print(f"\nEntries with CVE IDs: {len(cve_entries)}")
    for entry in cve_entries:
        print(f"  - {entry['cve_id']}: {entry['repo_name']}")
    
    all_paths = get_all_paths(data)
    print(f"\nUnique file paths: {len(all_paths)}")
    for path in all_paths:
        print(f"  - {path}")


def read_vuln_data(verbose: bool = False) -> Dict[str, Any]:
    if verbose:
        print("Reading vulnerability data...")
    with open(VULN_DATA_PATH, 'r', encoding='utf-8') as f:
        rawdata = json.load(f)
    repos = []
    for entry in rawdata:
        data = {}
        data['repo_name'] = entry['repo_name']
        data['commit'] = entry['commit']
        repo_path = REPO_BASE_PATH / data['repo_name']
        if verbose:
            print(f"Processing repository: {data['repo_name']} at commit {data['commit']}")
        # check the repo has the same commit number as the commit, if not, checkout to that commit
        current_commit = get_git_commit(repo_path)
        if current_commit != data['commit']:
            if verbose:
                print(f"Checking out {data['repo_name']} to commit {data['commit']} (current: {current_commit})")
            checkout_commit(repo_path, data['commit'])
        else:
            if verbose:
                print(f"{data['repo_name']} is already at commit {data['commit']}")

        call_chain_dict = []
        for callsite in entry['call_chain']:
            if '#' in callsite:

                file_relative_path, function_name = callsite.split('#')
                
                # code_content = (repo_path / file_relative_path).read_text(encoding='utf-8', errors='ignore')
                # snippet = extract_function_snippet_based_on_name_with_ast(code_content, function_name)
                if verbose:
                    print(f"\n{'-'*40}\nFile: {file_relative_path}, Function: {function_name}\n{'-'*40}")
                    print(snippet)
                call_chain_dict.append({'file_path': file_relative_path, 'function_name': function_name,})
            else:
                call_chain_dict.append({'vuln_sink': callsite})
        data['call_chain'] = call_chain_dict
        data['payload'] = entry['payload']
        repos.append(data)
    return repos
