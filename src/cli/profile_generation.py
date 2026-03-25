"""Shared helpers for CLI profile generation flows."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional

from llm import LLMConfig, create_llm_client
from profiler import (
    SoftwareProfile,
    SoftwareProfiler,
    VulnerabilityProfiler,
    VulnerabilityProfile,
    VulnEntry,
)


def create_profile_llm_client(llm_provider: str, llm_name: Optional[str]) -> Any:
    """Create the LLM client used by profile-generation commands.

    Args:
        llm_provider: Configured provider name.
        llm_name: Optional model override.

    Returns:
        Initialized LLM client.
    """
    llm_config = LLMConfig(provider=llm_provider, model=llm_name)
    llm_config.enable_thinking = True
    return create_llm_client(llm_config)


def build_vulnerability_entry(vuln_data: Dict[str, Any]) -> VulnEntry:
    """Construct a ``VulnEntry`` from one vuln.json record.

    Args:
        vuln_data: Raw vulnerability record.

    Returns:
        Normalized ``VulnEntry`` instance.
    """
    call_chain = vuln_data["call_chain"]
    call_chain_str = " -> ".join(
        f"{call.get('file_path', '')}#{call.get('function_name', call.get('vuln_sink', 'unknown'))}"
        for call in call_chain
    )
    return VulnEntry(
        repo_name=vuln_data["repo_name"],
        commit=vuln_data["commit"],
        call_chain=call_chain,
        call_chain_str=call_chain_str,
        payload=vuln_data.get("payload"),
        cve_id=vuln_data.get("cve_id"),
    )


def run_software_profile_generation(
    *,
    repo_path: Path,
    output_dir: Path,
    llm_client: Any,
    force_regenerate: bool,
    target_version: Optional[str],
) -> SoftwareProfile:
    """Run software profile generation for one repository version.

    Args:
        repo_path: Repository path to analyze.
        output_dir: Software profile root directory.
        llm_client: Initialized LLM client.
        force_regenerate: Whether to ignore cached outputs.
        target_version: Optional version or commit override.

    Returns:
        Generated software profile.
    """
    profiler = SoftwareProfiler(
        llm_client=llm_client,
        output_dir=str(output_dir),
    )
    return profiler.generate_profile(
        repo_path=str(repo_path),
        force_regenerate=force_regenerate,
        target_version=target_version,
    )


def run_vulnerability_profile_generation(
    *,
    repo_path: Path,
    output_dir: Path,
    llm_client: Any,
    repo_profile: SoftwareProfile,
    vuln_entry: VulnEntry,
    force_regenerate: bool = False,
) -> VulnerabilityProfile:
    """Run vulnerability profile generation for one vuln.json entry.

    Args:
        repo_path: Repository path containing the vulnerable code.
        output_dir: Vulnerability profile root directory.
        llm_client: Initialized LLM client.
        repo_profile: Preloaded software profile for the source repository.
        vuln_entry: Vulnerability record to profile.
        force_regenerate: Whether to bypass cached final vulnerability profiles.

    Returns:
        Generated vulnerability profile.
    """
    profiler = VulnerabilityProfiler(
        llm_client=llm_client,
        repo_profile=repo_profile,
        vuln_entry=vuln_entry,
        output_dir=str(output_dir),
    )
    return profiler.generate_vulnerability_profile(
        str(repo_path),
        save_results=True,
        force_regenerate=force_regenerate,
    )
