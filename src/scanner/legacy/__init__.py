"""LLM-powered CodeQL scanning utilities."""

from .query_generator import CodeQLQueryGenerator, CodeQLQueryValidator, QueryGenerationResult
from .profile_query import generate_codeql_query_from_vuln_profile
from .scan_runner import run_codeql_scan

__all__ = [
    "CodeQLQueryGenerator",
    "CodeQLQueryValidator",
    "QueryGenerationResult",
    "generate_codeql_query_from_vuln_profile",
    "run_codeql_scan",
    "verify_exploitability_for_results",
]


# results = run_codeql_scan(
#         repo_name=args.repo,
#         vuln_commit=args.vuln_commit,
#         target_commit=target_commit,
#         cve_id=args.cve,
#         scan_llm=args.scan_llm,
#         codeql_llm_provider=args.codeql_provider,
#         vulnerability_profile=vulnerability_profile,
#         candidates=candidates,
#         llm_client=llm_client,
#     )

#     if not args.verify_exploitability:
#         logger.info("Scan complete (exploitability verification skipped)")
#         return

#     output_dir = (
#         Path(f"scan-results/{args.repo}_{target_commit}_{args.cve}_from_{args.vuln_commit[:12]}/")
#         if args.vuln_commit != target_commit
#         else Path(f"scan-results/{args.repo}_{args.vuln_commit}_{args.cve}")
#     )
#     exploitability_results = verify_exploitability_for_results(
#         results,
#         repo_name=args.repo,
#         commit=target_commit,
#         llm_provider=args.codeql_provider,
#         project_root=_path_config["repo_base_path"],
#     )
#     output_file = save_exploitability_results(
#         exploitability_results, output_dir, args.codeql_provider