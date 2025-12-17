from utils.vuln_utils import read_vuln_data
import json
from core.software_profile import SoftwareProfile
from core.vuln_profile import VulnEntry
if __name__ == "__main__":
    """Test reading and displaying vulnerability data"""
    repos = read_vuln_data()
    for repo in repos:
        print(f"Repository: {repo['repo_name']}")
        print(f"Commit: {repo['commit']}")
        print(f'Call Chain: {json.dumps(repo["call_chain"], indent=2)}')
        print(f"Payload: {repo['payload']}")
        print("-" * 40)
        vulnentry = VulnEntry.from_dict(repo)
        break
    print(vulnentry)
