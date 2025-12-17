import json
import tempfile
import os
import subprocess
import shutil
from core.codeql_native import CodeQLAnalyzer, CodeQLConfig
from core.config import REPO_BASE_PATH, CODEQL_DB_PATH, LLMConfig, PROJECT_ROOT
from core.llm_client import create_llm_client
from utils.git_utils import get_git_commit, checkout_commit
from pathlib import Path


def save_verification_results(results: dict, output_file: str = "nemo_deepseek_results.json"):
    """
    保存验证结果到 JSON 文件
    
    Args:
        results: 包含验证结果的字典
        output_file: 输出文件路径
    """
    try:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"[INFO] Results saved to: {output_file}")
        return True
    except Exception as e:
        print(f"[ERROR] Failed to save results: {e}")
        return False


def generate_codeql_query_from_vuln_profile(vulnerability_profile: dict, llm_client, max_retries: int = 3) -> tuple[bool, str, str]:
    """
    根据漏洞画像生成 CodeQL 查询
    
    Args:
        vulnerability_profile: 漏洞画像字典
        llm_client: LLM 客户端
        max_retries: 最大重试次数（用于修复语法错误）
        
    Returns:
        (成功与否, CodeQL查询代码, 错误信息)
    """
    system_msg = (
        "You are a CodeQL expert. Generate valid CodeQL queries based on vulnerability profiles. "
        "Output ONLY the CodeQL query code without any explanation or markdown formatting."
    )
    
    # 提取关键信息
    sink_type = vulnerability_profile.get("sink_features", {}).get("type", "code_execution")
    sink_function = vulnerability_profile.get("sink_features", {}).get("function", "")
    source_type = vulnerability_profile.get("source_features", {}).get("data_type", "user_input")
    vuln_desc = vulnerability_profile.get("vuln_description", "")
    
    user_prompt = (
        "# 漏洞画像\n"
        f"- Sink类型: {sink_type}\n"
        f"- Sink函数: {sink_function}\n"
        f"- Source类型: {source_type}\n"
        f"- 漏洞描述: {vuln_desc[:200]}\n\n"
        "# 任务要求\n"
        "生成一个简单可靠的 CodeQL 查询来检测此类漏洞。\n\n"
        "**关键要求**:\n"
        "1. **必须**在查询开头添加 CodeQL 元数据注释（使用 /** ... */ 格式）\n"
        "2. 元数据必须包含 `@kind problem` 或 `@kind path-problem`\n"
        "3. 必须使用正确的导入语句：`import python`\n"
        "4. 使用 Python AST 类：`Call`, `Name`, `Attribute`, `Expr`\n"
        "5. 使用以下**经过验证的模板**：\n\n"
        "**模板A - 查找特定函数名的调用**:\n"
        "```\n"
        "/**\n"
        " * @name Dangerous function detection\n"
        " * @description Detects calls to dangerous functions\n"
        " * @kind problem\n"
        " * @id custom/dangerous-function\n"
        " * @problem.severity warning\n"
        " */\n\n"
        "import python\n\n"
        "from Call call, Name func\n"
        "where\n"
        "  call.getFunc() = func and\n"
        "  func.getId() = \"dangerous_function\"\n"
        "select call, \"Found dangerous function call\"\n"
        "```\n\n"
        "**模板B - 查找多个危险函数**:\n"
        "```\n"
        "/**\n"        " * @name Dangerous method call\n"
        " * @description Detects calls to dangerous methods\n"
        " * @kind problem\n"
        " * @id custom/dangerous-method\n"
        " * @problem.severity warning\n"
        " */\n\n"
        "import python\n\n"
        "from Call call, Attribute attr, Name base\n"
        "where\n"
        "  call.getFunc() = attr and\n"
        "  attr.getObject() = base and\n"
        "  base.getId() = \"subprocess\" and\n"
        "  attr.getName() = \"run\"\n"
        "select call, \"Found dangerous method call: subprocess.run\"\n"
        "```\n\n"
        "**模板D - 查找多个危险函数**:\n"
        "```\n"
        "/**\n"        " * @name Multiple dangerous functions\n"
        " * @description Detects calls to multiple dangerous functions\n"
        " * @kind problem\n"
        " * @id custom/multiple-dangerous\n"
        " * @problem.severity error\n"
        " */\n\n"
        "import python\n\n"
        "from Call call, Name func\n"
        "where\n"
        "  call.getFunc() = func and\n"
        "  func.getId() in [\"eval\", \"exec\", \"compile\"]\n"
        "select call, \"Found dangerous call: \" + func.getId()\n"
        "```\n\n"
        f"根据漏洞画像（Sink函数: {sink_function}, Sink类型: {sink_type}），选择最合适的模板并填入具体的函数名。\n"
        "**重要**: 必须包含完整的元数据注释块，尤其是 `@kind problem`！\n"
        "**只输出完整的 CodeQL 代码，不要有任何解释或 markdown 标记**。"
    )
    
    last_error = None
    for attempt in range(max_retries):
        try:
            if attempt == 0:
                # 首次生成
                messages = [
                    {"role": "system", "content": system_msg},
                    {"role": "user", "content": user_prompt}
                ]
            else:
                # 重新生成，提供错误信息
                messages.append({
                    "role": "assistant",
                    "content": codeql_query
                })
                messages.append({
                    "role": "user", 
                    "content": (
                        f"The previous query has CodeQL errors:\n\n"
                        f"```\n{last_error}\n```\n\n"
                        f"Common issues to check:\n"
                        f"- Use 'Call' not 'CallNode'\n"
                        f"- Use 'call.getFunc()' not 'call.getFunction()'\n"
                        f"- For Attribute, use 'attr.getObject()' not 'attr.getQualifier()'\n"
                        f"- For Attribute, use 'attr.getName()' to get attribute name\n"
                        f"- Import only 'import python' (no submodules)\n"
                        f"- Ensure proper 'from-where-select' structure\n"
                        f"- Must include metadata with '@kind problem'\n\n"
                        f"Use this CORRECTED template for attribute calls:\n"
                        f"```\n"
                        f"from Call call, Attribute attr, Name base\n"
                        f"where\n"
                        f"  call.getFunc() = attr and\n"
                        f"  attr.getObject() = base and\n"
                        f"  base.getId() = \"subprocess\" and\n"
                        f"  attr.getName() = \"run\"\n"
                        f"```\n\n"
                        f"Please output ONLY the corrected query code (no explanations):"
                    )
                })
            
            response = llm_client.chat(messages, temperature=0.0)
            
            print(f"\n[DEBUG] LLM Response (attempt {attempt + 1}):")
            print("=" * 60)
            print(response[:500])
            print("=" * 60)
            
            # 清理响应（移除可能的 markdown 标记）
            codeql_query = response.strip()
            
            # 移除 markdown 代码块标记
            if codeql_query.startswith("```"):
                lines = codeql_query.split("\n")
                # 移除第一行（```ql 或 ```）和最后一行（```）
                if len(lines) > 2:
                    codeql_query = "\n".join(lines[1:-1])
                    # 再次检查是否还有嵌套的代码块
                    if codeql_query.startswith("```"):
                        codeql_query = "\n".join(codeql_query.split("\n")[1:-1])
            
            codeql_query = codeql_query.strip()
            
            # 基本语法验证（必须包含 @kind 元数据）
            has_kind = "@kind" in codeql_query
            has_import = "import python" in codeql_query.lower()
            has_select = "select" in codeql_query.lower()
            
            if has_kind and has_import and has_select:
                print(f"[DEBUG] Query validation passed")
                return True, codeql_query, ""
            else:
                missing = []
                if not has_kind:
                    missing.append("@kind metadata")
                if not has_import:
                    missing.append("'import python'")
                if not has_select:
                    missing.append("'select' statement")
                last_error = f"Query missing: {', '.join(missing)}"
                print(f"[DEBUG] Validation failed: {last_error}")
                continue
                
        except Exception as e:
            last_error = str(e)
            continue
    
    return False, "", f"Failed to generate valid query after {max_retries} attempts. Last error: {last_error}"


if __name__ == "__main__":
    # 配置：漏洞画像来源（已知漏洞）
    scan_llm = "deepseek"
    codeql_llm_provider = "deepseek"
    repo_name = "NeMo"
    
    # 漏洞画像的 commit（用于加载漏洞profile和已识别的相似模块）
    vuln_commit = "2919fedf260120766d8c714749d5e18494dcf67b"
    cve_id = "CVE-2025-23361"
    
    # 待测试的 commit（在此commit上运行CodeQL查询）
    # 如果为 None，则使用漏洞 commit；否则使用指定的待测试 commit
    # 示例：测试较旧的 commit "6489229cb"
    target_commit = "6489229cb"  # None 表示使用漏洞 commit
    
    # 如果没有指定待测试 commit，使用漏洞 commit
    if target_commit is None:
        target_commit = vuln_commit
    
    # 从漏洞 commit 的扫描结果中加载漏洞画像
    save_dir = Path(f"scan-results/{repo_name}_{vuln_commit}_{cve_id}/")
    with open(save_dir / f"{scan_llm}_find_similar_modules.json", "r", encoding="utf-8") as f:
        results = json.load(f)
    
    # 提取漏洞画像
    vulnerability_profile = results.get("vulnerability_profile", {})
    if not vulnerability_profile:
        print("[ERROR] No vulnerability_profile found in nemo_deepseek_results.json")
        exit(1)
    
    print("[INFO] Vulnerability profile loaded successfully")
    print(f"  - CVE ID: {vulnerability_profile.get('cve_id', 'N/A')}")
    print(f"  - Vulnerability Commit: {vuln_commit[:12]}")
    print(f"  - Target Commit (for testing): {target_commit[:12]}")
    if vuln_commit != target_commit:
        print(f"  - Mode: Testing on newer commit")
    else:
        print(f"  - Mode: Testing on same commit as vulnerability")
    print(f"  - Description: {vulnerability_profile.get('vuln_description', 'N/A')[:100]}...")
    
    # 初始化 LLM 客户端
    llm_config = LLMConfig(provider=codeql_llm_provider)
    llm_client = create_llm_client(llm_config)
    print(f"\n[INFO] Using LLM: {llm_config.provider} - {llm_config.model}")
    
    # Step 1: 生成 CodeQL 查询
    print("\n[STEP 1] Generating CodeQL query from vulnerability profile...")
    success, codeql_query, error = generate_codeql_query_from_vuln_profile(
        vulnerability_profile, 
        llm_client,
        max_retries=3
    )
    
    if not success:
        print(f"[ERROR] Failed to generate CodeQL query: {error}")
        exit(1)
    
    print("[SUCCESS] CodeQL query generated:")
    print("=" * 80)
    print(codeql_query)
    print("=" * 80)
    
    # 如果测试不同的 commit，保存到新的目录
    if vuln_commit != target_commit:
        output_dir = Path(f"scan-results/{repo_name}_{target_commit}_{cve_id}_from_{vuln_commit[:12]}/")
        print(f"\n[INFO] Testing on different commit, results will be saved to:")
        print(f"  {output_dir}")
    else:
        output_dir = save_dir
    
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # 使用固定的查询目录
    query_dir = os.path.join(output_dir, ".codeql", "queries", "vuln-verify")
    os.makedirs(query_dir, exist_ok=True)
    
    qlpack_file = os.path.join(query_dir, "qlpack.yml")
    qlpack_lock_file = os.path.join(query_dir, "codeql-pack.lock.yml")
    query_path = os.path.join(query_dir, "generated_query.ql")
    
    # 检查是否需要初始化包（检查 lock 文件而不是 qlpack.yml）
    need_setup = not os.path.exists(qlpack_lock_file)
    
    if need_setup:
        print("[INFO] Initializing CodeQL query pack (lock file not found)...")
        
        # 创建 qlpack.yml（即使已存在也重新创建以确保一致性）
        qlpack_content = """name: vuln-verify-queries
version: 1.0.0
dependencies:
  codeql/python-all: "*"
"""
        with open(qlpack_file, 'w') as f:
            f.write(qlpack_content)
        
        # 安装依赖包（使用绝对路径）
        print("[INFO] Installing CodeQL pack dependencies...")
        abs_query_dir = os.path.abspath(query_dir)
        install_result = subprocess.run(
            ["codeql", "pack", "install", abs_query_dir],
            capture_output=True,
            text=True
        )
        if install_result.returncode != 0:
            print(f"[ERROR] Package install failed!")
            print(f"STDERR: {install_result.stderr}")
            print(f"STDOUT: {install_result.stdout}")
            exit(1)
        
        # 验证 lock 文件是否生成
        if os.path.exists(qlpack_lock_file):
            print("[SUCCESS] Dependencies installed successfully")
        else:
            print(f"[ERROR] Lock file not created at {qlpack_lock_file}")
            exit(1)
    else:
        print("[INFO] Using existing query pack directory with installed dependencies")
    
    print(f"[INFO] Query directory: {query_dir}")
    
    # 保存查询到固定目录
    with open(query_path, 'w') as f:
        f.write(codeql_query)
    
    # 同时保存调试副本到当前目录
    debug_query_path = "generated_codeql_query.ql"
    with open(debug_query_path, 'w') as f:
        f.write(codeql_query)
    
    print(f"[INFO] Query saved to: {query_path}")
    print(f"[INFO] Debug copy saved to: {debug_query_path}")
    
    # 初始化 CodeQL 分析器
    config = CodeQLConfig()
    analyzer = CodeQLAnalyzer(config=config)
    
    # 检查 CodeQL 是否可用
    if not analyzer.is_available:
        print("[ERROR] CodeQL is not available. Please install CodeQL CLI.")
        print("Visit: https://github.com/github/codeql-cli-binaries/releases")
        exit(1)
    
    print(f"[INFO] Using CodeQL version: {analyzer.version}")
    
    # NeMo 仓库路径
    repo_path = REPO_BASE_PATH / repo_name
    
    # 确保仓库在正确的 commit（待测试的 commit）
    current_commit = get_git_commit(str(repo_path))
    if current_commit != target_commit:
        print(f"[INFO] Checking out {repo_name} to target commit {target_commit[:12]}...")
        if not checkout_commit(str(repo_path), target_commit):
            print(f"[ERROR] Failed to checkout to {target_commit}")
            exit(1)
    else:
        print(f"[INFO] Repository already at target commit {target_commit[:12]}")
    
    # 使用基于待测试 commit 的 CodeQL 数据库路径
    db_name = f"{repo_name}-{target_commit[:12]}-python-db"
    db_path = CODEQL_DB_PATH / db_name
    
    if not db_path.exists():
        print(f"[INFO] Creating CodeQL database for {repo_name} at commit {target_commit[:12]}...")
        success, db_result = analyzer.create_database(
            source_path=str(repo_path),
            language="python",
            database_name=db_name,
            overwrite=False
        )
        if not success:
            print(f"[ERROR] Failed to create database: {db_result}")
            exit(1)
        db_path = Path(db_result)
    else:
        print(f"[INFO] Using existing database: {db_path}")
    
    # 清除旧的查询结果缓存（避免使用旧结果）
    results_cache = db_path / "results"
    if results_cache.exists():
        print(f"[INFO] Clearing query results cache...")
        shutil.rmtree(results_cache)
    
    # Step 2: 运行 CodeQL 查询（一次性在整个数据库上运行）
    print(f"\n[STEP 2] Running CodeQL query on database...\n")
    
    max_query_retries = 3
    query_retry_count = 0
    query_success = False
    query_result = None
    
    while not query_success and query_retry_count < max_query_retries:
        print("!!!", query_path, str(db_path))
        success, result = analyzer.run_query(
            database_path=str(db_path),
            query=query_path,
            output_format="sarif-latest"
        )
        
        if not success:
            error_msg = str(result)
            
            print(f"\n[ERROR] Query execution failed!")
            print("=" * 80)
            print("Full error message:")
            print(error_msg)
            print("=" * 80)
            
            # 检查是否是 CodeQL 查询语法错误
            if any(keyword in error_msg.lower() for keyword in 
                   ["syntax error", "parse error", "compilation error", "invalid query", "expected", 
                    "could not resolve", "not found", "undefined"]):
                print(f"\n[WARN] Detected CodeQL query error. Regenerating query...")
                print(f"Attempt {query_retry_count + 1}/{max_query_retries}")
                
                query_retry_count += 1
                
                # 重新生成查询
                regenerate_success, new_query, regen_error = generate_codeql_query_from_vuln_profile(
                    vulnerability_profile,
                    llm_client,
                    max_retries=1
                )
                
                if regenerate_success:
                    print("[INFO] New query generated, retrying...")
                    print("=" * 80)
                    print(new_query)
                    print("=" * 80)
                    # 保存新查询到固定目录
                    with open(query_path, 'w') as f:
                        f.write(new_query)
                    with open(debug_query_path, 'w') as f:
                        f.write(new_query)
                    codeql_query = new_query
                else:
                    print(f"[ERROR] Failed to regenerate query: {regen_error}")
                    break
            else:
                print(f"[ERROR] Query execution failed: {error_msg}")
                break
        else:
            query_success = True
            query_result = result
    
    # Step 3: 解析结果并按候选模块过滤

    print(f"\n[STEP 3] Filtering results for {len(results.get('candidates', []))} candidate modules...\n")
    
    # 收集所有发现
    all_findings = []
    if isinstance(query_result, dict):
        runs = query_result.get("runs", [])
        for run in runs:
            results_list = run.get("results", [])
            all_findings.extend(results_list)
    
    print(f"[INFO] Total findings from query: {len(all_findings)}")

    # 遍历每个候选模块
    candidates = results.get("candidates", [])
    
    # 初始化验证结果字段
    for candidate in candidates:
        candidate["codeql_verification"] = {
            "codeql_found": False,
            "vulnerabilities": []
        }
    
    for idx, candidate in enumerate(candidates, 1):

        folder_paths = candidate.get("folder_paths", [])
        
        print(f"\n{'='*80}")
        print(f"[{idx}/{len(candidates)}]")
        print(f"{'='*80}")
        
        if not folder_paths:
            print(f"[WARN] No folder paths specified for {idx}")
            continue
        
        # 对每个文件夹路径过滤结果
        for folder_path in folder_paths:
            print(f"\n[INFO] Checking folder: {folder_path}")
            
            # 过滤与当前文件夹路径相关的结果
            relevant_findings = []
            for finding in all_findings:
                locations = finding.get("locations", [])
                for loc in locations:
                    uri = loc.get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "")
                    # 检查文件路径是否在指定的文件夹下
                    if folder_path in uri or uri.startswith(folder_path):
                        relevant_findings.append(finding)
                        break
            
            if relevant_findings:
                print(f"\n[FOUND] {len(relevant_findings)} vulnerabilities in {folder_path}:")
                
                # 标记为已验证
                candidate["codeql_verification"]["codeql_found"] = True
                
                for finding in relevant_findings:
                    rule_id = finding.get("ruleId", "custom-vuln-query")
                    message = finding.get("message", {}).get("text", "No message")
                    level = finding.get("level", "warning")
                    
                    locations = finding.get("locations", [])
                    if locations:
                        loc = locations[0].get("physicalLocation", {})
                        uri = loc.get("artifactLocation", {}).get("uri", "")
                        region = loc.get("region", {})
                        start_line = region.get("startLine", "?")
                        
                        print(f"  - [{level.upper()}] {rule_id}")
                        print(f"    File: {uri}")
                        print(f"    Line {start_line}: {message}")
                        
                        # 添加到验证结果中
                        candidate["codeql_verification"]["vulnerabilities"].append({
                            "rule_id": rule_id,
                            "message": message,
                            "level": level,
                            "file": uri,
                            "line": start_line,
                            "folder_path": folder_path
                        })
            else:
                print(f"[INFO] No vulnerabilities found in {folder_path}")
    
    print(f"\n{'='*80}")
    print("[INFO] Analysis complete!")
    print(f"[INFO] Total query regenerations: {query_retry_count}")
    print(f"{'='*80}")
    
    # 保存验证结果
    results["codeql_query"] = codeql_query
    results["total_findings"] = len(all_findings)
    results["target_commit"] = target_commit
    results["vulnerability_commit"] = vuln_commit
    
    # 统计验证成功的候选模块
    codeql_found_count = sum(1 for c in candidates if c["codeql_verification"]["codeql_found"])
    results["verification_summary"] = {
        "total_candidates": len(candidates),
        "codeql_found_vulnerable": codeql_found_count,
        "query_regenerations": query_retry_count,
        "tested_on_different_commit": (vuln_commit != target_commit)
    }
    
    save_verification_results(results, output_file=output_dir / f"{codeql_llm_provider}_codeql_verification.json")
    
    print(f"\n[SUMMARY]")
    print(f"  - Total candidates analyzed: {len(candidates)}")
    print(f"  - Confirmed vulnerable: {codeql_found_count}")
    print(f"  - Total vulnerabilities found: {len(all_findings)}")
    
    # 保留查询目录供后续使用
    print(f"\n[INFO] Query files retained in: {query_dir}")
    print(f"[INFO] You can manually inspect: {debug_query_path}")