from src.utils.vuln_utils import read_vuln_data
import json
from src.profiler import SoftwareProfile

if __name__ == "__main__":
   
    # 测试softwareprofile对象
    with open("repo-profiles/NeMo/2919fedf260120766d8c714749d5e18494dcf67b/software_profile.json", 'r', encoding='utf-8') as f:
        data = json.load(f)
    print(data.keys())
    repo_profile = SoftwareProfile.from_dict(data)
    print(len(repo_profile.modules))
    print(data['basic_info'])
    print(repo_profile.repo_info.keys())
    for k, v in repo_profile.repo_info.items():
        print(f"{k}: {len(v)}")
