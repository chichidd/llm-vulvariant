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
