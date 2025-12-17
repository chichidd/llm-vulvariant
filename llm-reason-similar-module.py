

import json
from pathlib import Path
from typing import Optional, Tuple

from core.software_profile import SoftwareProfile
from core.vuln_profile import VulnerabilityProfile, SourceFeature, FlowFeature, SinkFeature
from core.llm_client import create_llm_client
from core.config import LLMConfig, PROJECT_ROOT
from utils.llm_utils import parse_llm_json



def load_software_profile(
    repo_name: str,
    commit_hash: str,
    base_dir: str = "repo-profiles"
) -> Optional[SoftwareProfile]:
    """
    加载软件画像数据
    
    Args:
        repo_name: 仓库名称 (如 "NeMo")
        commit_hash: 提交哈希 (如 "914c9ce7a54de813e04226dd44277fe159c07a75")
        base_dir: 软件画像基础目录路径
        
    Returns:
        SoftwareProfile对象，如果加载失败返回None
        
    Example:
        >>> profile = load_software_profile("NeMo", "914c9ce7a54de813e04226dd44277fe159c07a75")
        >>> print(profile.name, profile.version)
    """
    profile_path = Path(base_dir) / repo_name / commit_hash / "software_profile.json"
    
    if not profile_path.exists():
        print(f"[ERROR] Software profile not found: {profile_path}")
        return None
    
    try:
        with open(profile_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        profile = SoftwareProfile.from_dict(data)
        print(f"[INFO] Loaded software profile: {repo_name}@{commit_hash}")
        return profile
        
    except Exception as e:
        print(f"[ERROR] Failed to load software profile from {profile_path}: {e}")
        return None


def load_vulnerability_profile(
    repo_name: str,
    commit_hash: str,
    cve_id: str,
    base_dir: str = "llm-vulvariant/vuln-profiles"
) -> Optional[VulnerabilityProfile]:
    """
    加载漏洞画像数据
    
    Args:
        repo_name: 仓库名称 (如 "NeMo")
        commit_hash: 提交哈希 (如 "914c9ce7a54de813e04226dd44277fe159c07a75")
        cve_id: CVE标识符 (如 "cve-tencent-nemo1")
        base_dir: 漏洞画像基础目录路径
        
    Returns:
        VulnerabilityProfile对象，如果加载失败返回None
        
    Example:
        >>> vuln = load_vulnerability_profile("NeMo", "914c9ce7a54de813e04226dd44277fe159c07a75", "cve-tencent-nemo1")
        >>> print(vuln.cve_id, vuln.payload)
    """
    profile_path = Path(base_dir) / repo_name / commit_hash / cve_id / "vulnerability_profile.json"
    
    if not profile_path.exists():
        print(f"[ERROR] Vulnerability profile not found: {profile_path}")
        return None
    
    try:
        with open(profile_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # 手动构建VulnerabilityProfile对象，因为可能没有from_dict方法
        print(data)
        profile = VulnerabilityProfile.from_dict(data)
        
        print(f"[INFO] Loaded vulnerability profile: {repo_name}@{commit_hash}/{cve_id}")
        return profile
        
    except Exception as e:
        print(f"[ERROR] Failed to load vulnerability profile from {profile_path}: {e}")
        return None



def find_similar_vulnerable_modules_with_deepseek(
    repo_name: str,
    commit_hash: str,
    cve_id: str,
    software_base_dir: str = "repo-profiles",
    vuln_base_dir: str = "vuln-profiles",
    llm_provider: str = "hku",
    max_tokens: int = 32768,
) -> dict:
    """
    使用LLM 分析软件画像和漏洞画像，并推理可能存在相似漏洞的模块。

    返回结构化的 JSON 字典，包含候选模块、推理依据、置信度、定位建议和验证步骤。
    """

    # 加载画像
    software_profile = load_software_profile(repo_name, commit_hash, software_base_dir)
    vulnerability_profile = load_vulnerability_profile(repo_name, commit_hash, cve_id, vuln_base_dir)

    if not software_profile or not vulnerability_profile:
        return {
            "error": "failed_to_load_profiles",
            "software_profile_loaded": bool(software_profile),
            "vulnerability_profile_loaded": bool(vulnerability_profile),
        }

    # 构造 LLM 客户端
    llm_config = LLMConfig(provider=llm_provider)
    llm_config.max_tokens = max_tokens
    client = create_llm_client(llm_config)

    # 构造精简的 software profile（只包含必要信息）
    software_profile_dict = software_profile.to_dict()
    simplified_software_profile = {
        "basic_info": software_profile_dict.get("basic_info", {}),
        "repo_info": {
            "files": software_profile_dict.get("repo_info", {}).get("files", [])
        },
        "modules": software_profile_dict.get("modules", [])
    }
    
    # 构造 prompt：提供精简的 software profile 与完整的 vulnerability profile
    system_msg = (
        "You are a security-focused assistant specialized in vulnerability pattern analysis. "
        "Given software profile and vulnerability profile, identify modules that are likely to contain similar vulnerabilities. "
        "Provide structured JSON output with detailed reasoning."
    )

    user_prompt = (
        "# 软件画像\n"
        "```json\n" + json.dumps(simplified_software_profile, indent=2, ensure_ascii=False) + "\n```\n\n"
        "**注意**: 上述软件画像中的 `modules` 部分可能存在遗漏或不完整。你需要结合 `repo_info.files` 中的文件列表，"
        "综合分析项目的整体结构、文件命名规律、目录组织等信息，推断可能存在的其他功能模块。\n\n"
        "# 漏洞画像\n"
        "```json\n" + json.dumps(vulnerability_profile.to_dict(), indent=2, ensure_ascii=False) + "\n```\n\n"
        "# 任务要求\n"
        "基于上述软件画像和漏洞画像，完成以下分析任务：\n\n"
        "1. **模块识别**: 列举可能存在于上述漏洞相似漏洞的模块（模块名/文件路径）。请综合考虑：\n"
        "   - `modules` 中已列出的模块\n"
        "   - `repo_info.files` 中暗示的其他潜在模块\n"
        "   - 文件命名和目录结构反映的功能划分\n\n"
        "2. **详细推理**: 对每个候选模块，从以下列出的但是不限于的维度进行分析，并给出推理，确保分析全面：\n"
        "   - **使用场景**: 该模块在软件中的应用场景\n"
        "   - **功能相似性**: 与已知漏洞模块的功能相似之处\n"
        "   - **入口点**: 可能的数据入口点（API、用户输入、文件读取等）\n"
        "   - **数据流相似性**: 是否具有相似的 source → sink 数据流模式\n"
        "   - **依赖相似性**: 是否使用了相同或类似的危险函数/库\n\n"
        "# 输出格式\n"
        "请严格按照以下 JSON 格式输出（**只输出 JSON，不要任何额外说明文字**）：\n\n"
        "```json\n"
        "{\n"
        '  "vulnerability_analysis": "对漏洞进行系统分析，思考漏洞特征，用于推理可能存在这一特征漏洞的相似软件模块",\n'
        '  "candidates": [\n'
        "    {\n"
        '      "reasoning": "详细的推理过程，说明为什么这个模块可能存在相似漏洞",\n'
        '      "folder_paths": ["相关文件夹路径1", "相关文件夹路径2"],\n'
        "    }\n"
        "  ],\n"
        "}\n"
        "```\n"
        "注意：回复必须是可解析的 JSON，仅输出 JSON，不要额外的说明文本。"
    )

    messages = [
        {"role": "system", "content": system_msg},
        {"role": "user", "content": user_prompt},
    ]

    try:
        response_text = client.chat(messages, temperature=0.0, max_tokens=max_tokens)
    except Exception as e:
        return {"error": "llm_call_failed", "exception": str(e)}

    # 尝试解析 JSON
    return parse_llm_json(response_text), vulnerability_profile
    

    
    



if __name__ == "__main__":
    # 示例用法
    print("=== 加载NeMo软件画像和漏洞画像 ===\n")
    
    # 方法1: 使用通用函数
    # software_profile, vuln_profile = load_profiles(
    #     repo_name="NeMo",
    #     commit_hash="914c9ce7a54de813e04226dd44277fe159c07a75",
    #     cve_id="cve-tencent-nemo1"
    # )
    llm_provider = "deepseek"

    repo_name = "NeMo"
    # commit_hash = "914c9ce7a54de813e04226dd44277fe159c07a75"
    commit_hash = "2919fedf260120766d8c714749d5e18494dcf67b"
    # cve_id = "cve-tencent-nemo1"
    cve_id = "CVE-2025-23361"
    results, vuln_profile = find_similar_vulnerable_modules_with_deepseek(repo_name=repo_name,
        commit_hash=commit_hash,
        cve_id=cve_id,
        llm_provider=llm_provider)
    print(f"\n=== {llm_provider} 分析结果 ===")
    print(json.dumps(results, indent=2, ensure_ascii=False))
    results['vulnerability_profile'] = vuln_profile.to_dict()
    # save the results to a json file
    # make a saving directory
    save_dir = Path(f"scan-results/{repo_name}_{commit_hash}_{cve_id}/")
    save_dir.mkdir(parents=True, exist_ok=True)
    with open(save_dir / f"{llm_provider}_find_similar_modules.json", "w", encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
