"""Profile generation module.

Provides generators for software profiles and vulnerability profiles.
"""

# Software profiling (backward compatible)
from .software import (
    SoftwareProfiler,
    SoftwareProfile,
    ModuleInfo,
    DataFlowPattern,
)

# Vulnerability profiling (backward compatible)
from .vulnerability import (
    VulnerabilityProfiler,
    VulnerabilityProfile,
    VulnEntry,
    SourceFeature,
    FlowFeature,
    SinkFeature,
)

# Storage manager
from .profile_storage import ProfileStorageManager

# Keep backward compatibility from legacy locations (gradually deprecating)
# from .software_profile import SoftwareProfiler  # Moved to software/analyzer.py
# from .vuln_profile import VulnerabilityProfiler  # Moved to vulnerability/analyzer.py

__all__ = [
    # Software profiling
    "SoftwareProfiler",
    "SoftwareProfile",
    "ModuleInfo",
    "DataFlowPattern",
    # Vulnerability profiling
    "VulnerabilityProfiler",
    "VulnerabilityProfile",
    "VulnEntry",
    "SourceFeature",
    "FlowFeature",
    "SinkFeature",
    # Storage
    "ProfileStorageManager",
]
