from core.software_profile import SoftwareProfiler
from core.llm_client import LLMConfig, create_llm_client
from pathlib import Path
import json
from datetime import datetime
if __name__ == "__main__":
    """Simple test to extract function snippets using AST"""
    
    # Create a simple test file
    # repo_path = str(Path.home() / "vuln/llm-vulvariant")
    repo_path = str(Path.home() / "vuln/data/repos/NeMo")
    llm_config = LLMConfig()
    # llm_config.provider = 'deepseek'
    # llm_config.__post_init__()
    print(llm_config)
    llm_client = create_llm_client(llm_config)
    profiler = SoftwareProfiler(config=None, llm_client=llm_client, output_dir="./repo-profiles/")
    # profile = profiler.generate_profile(repo_path=repo_path, )
    profile = profiler.generate_profile(repo_path=repo_path, force_full_analysis=True, target_version="2919fedf260120766d8c714749d5e18494dcf67b")
    profile = profiler.generate_profile(repo_path=repo_path, force_full_analysis=False, target_version="914c9ce7a54de813e04226dd44277fe159c07a75")


    # timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    # filename = f"profile_nemo_{timestamp}.json"
    
    # with open(filename, 'w', encoding='utf-8') as f:
    #     json.dump(profile.to_dict(), f, indent=2, ensure_ascii=False)
    
    # print(f"Profile saved to {filename}")

