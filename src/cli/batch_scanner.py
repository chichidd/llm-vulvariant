#!/usr/bin/env python3
"""Batch vulnerability scanning pipeline for all entries in vuln.json."""

from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from config import _path_config
from llm import LLMConfig, create_llm_client
from profiler import SoftwareProfiler, VulnerabilityProfiler, VulnEntry
from scanner.agent import load_software_profile, load_vulnerability_profile
from scanner.similarity import (
    ProfileRef,
    SimilarProfileCandidate,
    build_text_retriever,
    compute_profile_similarity,
)
from utils.git_utils import get_git_commit
from utils.logger import get_logger
from utils.vuln_utils import read_vuln_data

try:
    from cli import agent_scanner
    from cli.common import setup_logging
except ImportError:  # pragma: no cover - direct script execution fallback
    import agent_scanner
    from common import setup_logging

logger = get_logger(__name__)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Batch pipeline: ensure profiles, select similar latest repos by similarity threshold, "
            "and scan all vuln entries from vuln.json."
        )
    )
    parser.add_argument(
        "--vuln-json",
        type=str,
        default=str(_path_config["vuln_data_path"]),
        help="Path to vuln.json (default from config/paths.yaml)",
    )
    parser.add_argument(
        "--repos-root",
        type=str,
        default=str(_path_config["repo_base_path"]),
        help="Root directory of target repositories (default: data/repos)",
    )
    parser.add_argument(
        "--repo-profiles-dir",
        type=str,
        default=str(_path_config["repo_root"] / "repo-profiles"),
        help="Directory storing software profiles",
    )
    parser.add_argument(
        "--vuln-profiles-dir",
        type=str,
        default=str(_path_config["repo_root"] / "vuln-profiles"),
        help="Directory storing vulnerability profiles",
    )
    parser.add_argument(
        "--scan-output-dir",
        type=str,
        default="scan-results-batch",
        help="Base output directory for scan results",
    )
    parser.add_argument(
        "--similarity-threshold",
        type=float,
        default=0.7,
        help="Minimum overall profile similarity to keep a target repo (default: 0.7)",
    )
    parser.add_argument(
        "--max-targets",
        type=int,
        default=None,
        help="Optional max number of targets to scan per vulnerability after threshold filtering",
    )
    parser.add_argument(
        "--fallback-top-n",
        type=int,
        default=3,
        help=(
            "If no repository meets similarity-threshold, scan top-N most similar repositories "
            "(default: 3)"
        ),
    )
    parser.add_argument(
        "--include-same-repo",
        action="store_true",
        help="Include same repository as source vulnerability during target selection",
    )
    parser.add_argument(
        "--similarity-model-name",
        type=str,
        default="BAAI--bge-large-en-v1.5",
        help="Embedding model name for text similarity",
    )
    parser.add_argument(
        "--similarity-device",
        type=str,
        default="cpu",
        help="Device used by similarity embedding model",
    )
    parser.add_argument(
        "--llm-provider",
        type=str,
        default="deepseek",
        help="LLM provider used for profile generation and scanning",
    )
    parser.add_argument(
        "--llm-name",
        type=str,
        default=None,
        help="Optional model name override",
    )
    parser.add_argument(
        "--max-iterations-cap",
        type=int,
        default=10,
        help="Iteration cap used with critical-stop mode (default: 10)",
    )
    parser.add_argument(
        "--disable-critical-stop",
        action="store_true",
        help=(
            "Disable priority-1 completion aware stopping behavior."
        ),
    )
    parser.add_argument(
        "--critical-stop-mode",
        type=str,
        choices=["min", "max"],
        default="min",
        help=(
            "When critical stop is enabled: "
            "min => stop at min(max-iterations-cap, X); "
            "max => stop at max(max-iterations-cap, X). Default: min"
        ),
    )
    parser.add_argument(
        "--force-regenerate-profiles",
        action="store_true",
        help="Regenerate software/vulnerability profiles even when cached profile files exist",
    )
    parser.add_argument(
        "--skip-existing-scans",
        action="store_true",
        help="Skip target scan when output file agentic_vuln_findings.json already exists",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Optional limit on number of vuln entries from vuln.json",
    )
    parser.add_argument(
        "--language",
        type=str,
        default=None,
        help="Force scan language, otherwise auto-detect per target repo",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logs")
    return parser.parse_args()


def _validate_args(args: argparse.Namespace) -> bool:
    if not (0.0 <= args.similarity_threshold <= 1.0):
        logger.error("--similarity-threshold must be between 0 and 1")
        return False
    if args.max_targets is not None and args.max_targets <= 0:
        logger.error("--max-targets must be >= 1 when provided")
        return False
    if args.fallback_top_n <= 0:
        logger.error("--fallback-top-n must be >= 1")
        return False
    if args.max_iterations_cap <= 0:
        logger.error("--max-iterations-cap must be >= 1")
        return False
    return True


def _normalize_cve_id(entry: Dict[str, object], index: int) -> str:
    cve_id = str(entry.get("cve_id") or "").strip()
    return cve_id if cve_id else f"vuln-{index}"


def _load_vuln_entries(vuln_json: Path, limit: Optional[int] = None) -> List[Tuple[int, Dict[str, object]]]:
    raw_entries = json.loads(vuln_json.read_text(encoding="utf-8"))
    indexed = list(enumerate(raw_entries))
    if limit is not None:
        indexed = indexed[:limit]
    return indexed


def _ensure_software_profile(
    *,
    repo_name: str,
    commit_hash: str,
    repos_root: Path,
    repo_profiles_dir: Path,
    llm_client,
    force_regenerate: bool,
    cache: Dict[Tuple[str, str], object],
) -> Optional[object]:
    key = (repo_name, commit_hash)
    if key in cache:
        return cache[key]

    profile_path = repo_profiles_dir / repo_name / commit_hash / "software_profile.json"
    if force_regenerate and profile_path.exists():
        profile_path.unlink()

    profile = load_software_profile(repo_name, commit_hash, base_dir=repo_profiles_dir)
    if profile:
        cache[key] = profile
        return profile

    repo_path = repos_root / repo_name
    if not repo_path.exists():
        logger.error(f"Repository not found for software profile generation: {repo_path}")
        return None

    logger.info(f"[Profile] Generating software profile: {repo_name}@{commit_hash[:12]}")
    profiler = SoftwareProfiler(
        llm_client=llm_client,
        output_dir=str(repo_profiles_dir),
    )
    profiler.generate_profile(
        repo_path=str(repo_path),
        force_full_analysis=False,
        target_version=commit_hash,
    )

    profile = load_software_profile(repo_name, commit_hash, base_dir=repo_profiles_dir)
    if profile:
        cache[key] = profile
    return profile


def _ensure_vulnerability_profile(
    *,
    vuln_index: int,
    repo_name: str,
    commit_hash: str,
    cve_id: str,
    repos_root: Path,
    repo_profiles_dir: Path,
    vuln_profiles_dir: Path,
    llm_client,
    force_regenerate: bool,
    software_cache: Dict[Tuple[str, str], object],
    cache: Dict[Tuple[str, str], object],
    verbose: bool,
    vuln_json_path: Optional[str] = None,
) -> Optional[object]:
    key = (repo_name, cve_id)
    if key in cache:
        return cache[key]

    profile_path = vuln_profiles_dir / repo_name / cve_id / "vulnerability_profile.json"
    if force_regenerate and profile_path.exists():
        profile_path.unlink()

    profile = load_vulnerability_profile(repo_name, cve_id, base_dir=vuln_profiles_dir)
    if profile:
        cache[key] = profile
        return profile

    source_profile = _ensure_software_profile(
        repo_name=repo_name,
        commit_hash=commit_hash,
        repos_root=repos_root,
        repo_profiles_dir=repo_profiles_dir,
        llm_client=llm_client,
        force_regenerate=force_regenerate,
        cache=software_cache,
    )
    if not source_profile:
        return None

    selected = read_vuln_data(vuln_index, verbose=verbose, vuln_json_path=vuln_json_path)
    if not selected:
        logger.error(f"Failed to read vulnerability entry index={vuln_index}")
        return None
    vuln_data = selected[0]
    call_chain_str = " -> ".join(
        f"{call.get('file_path', '')}#{call.get('function_name', call.get('vuln_sink', 'unknown'))}"
        for call in vuln_data["call_chain"]
    )
    vuln_entry = VulnEntry(
        repo_name=repo_name,
        commit=commit_hash,
        call_chain=vuln_data["call_chain"],
        call_chain_str=call_chain_str,
        payload=vuln_data.get("payload"),
        cve_id=cve_id,
    )
    logger.info(f"[Profile] Generating vulnerability profile: {repo_name}@{cve_id}")
    vuln_profiler = VulnerabilityProfiler(
        llm_client=llm_client,
        repo_profile=source_profile,
        vuln_entry=vuln_entry,
        output_dir=str(vuln_profiles_dir),
    )
    vuln_profiler.generate_vulnerability_profile(str(repos_root / repo_name), save_results=True)

    profile = load_vulnerability_profile(repo_name, cve_id, base_dir=vuln_profiles_dir)
    if profile:
        cache[key] = profile
    return profile


def _discover_latest_repo_refs(
    *,
    repos_root: Path,
    repo_profiles_dir: Path,
    llm_client,
    force_regenerate_profiles: bool,
    software_cache: Dict[Tuple[str, str], object],
) -> Dict[str, ProfileRef]:
    refs: Dict[str, ProfileRef] = {}
    for repo_dir in sorted(repos_root.iterdir()):
        if not repo_dir.is_dir():
            continue
        repo_name = repo_dir.name
        commit_hash = get_git_commit(str(repo_dir))
        if not commit_hash:
            logger.warning(f"Skip non-git or unreadable repo: {repo_name}")
            continue
        profile = _ensure_software_profile(
            repo_name=repo_name,
            commit_hash=commit_hash,
            repos_root=repos_root,
            repo_profiles_dir=repo_profiles_dir,
            llm_client=llm_client,
            force_regenerate=force_regenerate_profiles,
            cache=software_cache,
        )
        if not profile:
            logger.warning(f"Skip repo without software profile: {repo_name}@{commit_hash[:12]}")
            continue
        refs[repo_name] = ProfileRef(repo_name=repo_name, commit_hash=commit_hash, profile=profile)
    return refs


def _rank_similar_candidates(
    *,
    source_ref: ProfileRef,
    candidate_refs: Sequence[ProfileRef],
    text_retriever,
) -> List[SimilarProfileCandidate]:
    ranked: List[SimilarProfileCandidate] = []
    for candidate in candidate_refs:
        metrics = compute_profile_similarity(
            source_profile=source_ref.profile,
            target_profile=candidate.profile,
            text_retriever=text_retriever,
        )
        ranked.append(SimilarProfileCandidate(profile_ref=candidate, metrics=metrics))

    ranked.sort(
        key=lambda item: (
            item.metrics.overall_sim,
            item.metrics.module_dependency_import_sim,
            item.metrics.module_jaccard_sim,
        ),
        reverse=True,
    )
    return ranked


def _select_similar_targets(
    *,
    ranked_candidates: Sequence[SimilarProfileCandidate],
    similarity_threshold: float,
    max_targets: Optional[int],
    fallback_top_n: int,
) -> Tuple[List[SimilarProfileCandidate], bool]:
    passed = [
        candidate
        for candidate in ranked_candidates
        if candidate.metrics.overall_sim >= similarity_threshold
    ]
    if passed:
        if max_targets is not None:
            passed = passed[:max_targets]
        return passed, False

    fallback = list(ranked_candidates[:fallback_top_n])
    return fallback, bool(fallback)


def _run_target_scan(
    *,
    batch_args: argparse.Namespace,
    repo_profiles_dir: Path,
    cve_id: str,
    vulnerability_profile,
    llm_client,
    target: SimilarProfileCandidate,
) -> bool:
    scan_args = argparse.Namespace(
        cve=cve_id,
        output=str(batch_args.scan_output_dir),
        language=batch_args.language,
        max_iterations=batch_args.max_iterations_cap,
        stop_when_critical_complete=not batch_args.disable_critical_stop,
        critical_stop_mode=batch_args.critical_stop_mode,
        verbose=batch_args.verbose,
        repo_profiles_dir=repo_profiles_dir,
    )
    scan_target = agent_scanner.ScanTarget(
        repo_name=target.profile_ref.repo_name,
        commit_hash=target.profile_ref.commit_hash,
        similarity=target,
    )
    output_dir = agent_scanner.resolve_output_dir(
        cve_id=cve_id,
        target_repo=scan_target.repo_name,
        target_commit=scan_target.commit_hash,
        output_base=scan_args.output,
    )
    findings_path = output_dir / "agentic_vuln_findings.json"
    if batch_args.skip_existing_scans and findings_path.exists():
        logger.info(f"[Skip] Existing scan result: {findings_path}")
        return True

    return agent_scanner._run_single_target_scan(
        args=scan_args,
        vulnerability_profile=vulnerability_profile,
        llm_client=llm_client,
        target=scan_target,
    )


def main() -> int:
    args = parse_args()
    setup_logging(args.verbose)
    if not _validate_args(args):
        return 1

    vuln_json = Path(args.vuln_json).expanduser()
    repos_root = Path(args.repos_root).expanduser()
    repo_profiles_dir = Path(args.repo_profiles_dir).expanduser()
    vuln_profiles_dir = Path(args.vuln_profiles_dir).expanduser()
    scan_output_dir = Path(args.scan_output_dir).expanduser()
    args.scan_output_dir = str(scan_output_dir)

    if not vuln_json.exists():
        logger.error(f"vuln.json not found: {vuln_json}")
        return 1
    if not repos_root.exists():
        logger.error(f"repos root not found: {repos_root}")
        return 1

    entries = _load_vuln_entries(vuln_json, limit=args.limit)
    if not entries:
        logger.warning("No vulnerability entries found")
        return 0

    logger.info(f"Loaded {len(entries)} vulnerabilities from {vuln_json}")
    profile_llm = create_llm_client(LLMConfig(provider=args.llm_provider, model=args.llm_name))
    scan_llm = create_llm_client(LLMConfig(provider=args.llm_provider, model=args.llm_name))
    text_retriever = build_text_retriever(
        model_name=args.similarity_model_name,
        device=args.similarity_device,
    )

    software_cache: Dict[Tuple[str, str], object] = {}
    vulnerability_cache: Dict[Tuple[str, str], object] = {}

    logger.info("Ensuring latest software profiles for candidate repositories...")
    latest_repo_refs = _discover_latest_repo_refs(
        repos_root=repos_root,
        repo_profiles_dir=repo_profiles_dir,
        llm_client=profile_llm,
        force_regenerate_profiles=args.force_regenerate_profiles,
        software_cache=software_cache,
    )
    logger.info(f"Candidate repositories with latest profiles: {len(latest_repo_refs)}")

    summary = {
        "started_at": datetime.now().isoformat(),
        "vuln_json": str(vuln_json),
        "similarity_threshold": args.similarity_threshold,
        "max_iterations_cap": args.max_iterations_cap,
        "critical_stop_enabled": not args.disable_critical_stop,
        "critical_stop_mode": args.critical_stop_mode,
        "entries": [],
    }

    total_scans = 0
    success_scans = 0

    for vuln_index, entry in entries:
        repo_name = str(entry.get("repo_name", ""))
        commit_hash = str(entry.get("commit", ""))
        cve_id = _normalize_cve_id(entry, vuln_index)
        if not repo_name or not commit_hash:
            logger.warning(f"[{vuln_index}] Skip malformed vuln entry: missing repo_name/commit")
            continue

        logger.info("")
        logger.info("=" * 100)
        logger.info(f"[Vuln {vuln_index}] {repo_name}@{commit_hash[:12]} {cve_id}")
        logger.info("=" * 100)

        source_profile = _ensure_software_profile(
            repo_name=repo_name,
            commit_hash=commit_hash,
            repos_root=repos_root,
            repo_profiles_dir=repo_profiles_dir,
            llm_client=profile_llm,
            force_regenerate=args.force_regenerate_profiles,
            cache=software_cache,
        )
        vulnerability_profile = _ensure_vulnerability_profile(
            vuln_index=vuln_index,
            repo_name=repo_name,
            commit_hash=commit_hash,
            cve_id=cve_id,
            repos_root=repos_root,
            repo_profiles_dir=repo_profiles_dir,
            vuln_profiles_dir=vuln_profiles_dir,
            llm_client=profile_llm,
            force_regenerate=args.force_regenerate_profiles,
            software_cache=software_cache,
            cache=vulnerability_cache,
            verbose=args.verbose,
            vuln_json_path=str(vuln_json),
        )

        if not source_profile or not vulnerability_profile:
            logger.error(f"[Vuln {vuln_index}] Missing required profiles, skip")
            summary["entries"].append(
                {
                    "index": vuln_index,
                    "repo_name": repo_name,
                    "commit_hash": commit_hash,
                    "cve_id": cve_id,
                    "status": "failed_profile_generation",
                }
            )
            continue

        source_ref = ProfileRef(repo_name=repo_name, commit_hash=commit_hash, profile=source_profile)
        candidate_refs = [
            ref
            for cand_repo, ref in latest_repo_refs.items()
            if args.include_same_repo or cand_repo != repo_name
        ]
        ranked_candidates = _rank_similar_candidates(
            source_ref=source_ref,
            candidate_refs=candidate_refs,
            text_retriever=text_retriever,
        )
        logger.info(f"[Vuln {vuln_index}] Similarity details ({len(ranked_candidates)} candidates):")
        for i, candidate in enumerate(ranked_candidates, 1):
            metrics = candidate.metrics
            threshold_flag = "PASS" if metrics.overall_sim >= args.similarity_threshold else "BELOW"
            logger.info(
                f"  {i}. {candidate.profile_ref.label} "
                f"overall={metrics.overall_sim:.4f} [{threshold_flag}] "
                f"(desc={metrics.description_sim:.4f}, apps={metrics.target_application_sim:.4f}, "
                f"users={metrics.target_user_sim:.4f}, module={metrics.module_jaccard_sim:.4f}, "
                f"dep/import={metrics.module_dependency_import_sim:.4f})"
            )
        similar_targets, fallback_used = _select_similar_targets(
            ranked_candidates=ranked_candidates,
            similarity_threshold=args.similarity_threshold,
            max_targets=args.max_targets,
            fallback_top_n=args.fallback_top_n,
        )

        logger.info(
            f"[Vuln {vuln_index}] Selected {len(similar_targets)} targets "
            f"(threshold={args.similarity_threshold:.3f})"
        )
        if fallback_used:
            logger.warning(
                f"[Vuln {vuln_index}] No target reached threshold {args.similarity_threshold:.3f}; "
                f"fallback to top-{args.fallback_top_n}"
            )
        for i, candidate in enumerate(similar_targets, 1):
            logger.info(
                f"  {i}. {candidate.profile_ref.label} overall={candidate.metrics.overall_sim:.4f} "
                f"(module={candidate.metrics.module_jaccard_sim:.4f}, "
                f"dep/import={candidate.metrics.module_dependency_import_sim:.4f})"
            )

        vuln_record = {
            "index": vuln_index,
            "repo_name": repo_name,
            "commit_hash": commit_hash,
            "cve_id": cve_id,
            "selection_mode": "fallback_top_n" if fallback_used else "threshold",
            "selected_targets": [candidate.to_dict() for candidate in similar_targets],
            "scan_results": [],
        }

        for candidate in similar_targets:
            total_scans += 1
            ok = _run_target_scan(
                batch_args=args,
                repo_profiles_dir=repo_profiles_dir,
                cve_id=cve_id,
                vulnerability_profile=vulnerability_profile,
                llm_client=scan_llm,
                target=candidate,
            )
            success_scans += int(ok)
            vuln_record["scan_results"].append(
                {
                    "repo_name": candidate.profile_ref.repo_name,
                    "commit_hash": candidate.profile_ref.commit_hash,
                    "overall_similarity": candidate.metrics.overall_sim,
                    "status": "ok" if ok else "failed",
                }
            )

        summary["entries"].append(vuln_record)

    summary["finished_at"] = datetime.now().isoformat()
    summary["total_scans"] = total_scans
    summary["successful_scans"] = success_scans

    scan_output_dir.mkdir(parents=True, exist_ok=True)
    summary_path = scan_output_dir / f"batch-summary-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
    summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")

    logger.info(f"Batch summary saved to: {summary_path}")
    logger.info(f"Finished: {success_scans}/{total_scans} target scans succeeded")
    return 0 if success_scans > 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
