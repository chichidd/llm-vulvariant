"""Module priority calculator for vulnerability scanning."""

from typing import Any, Dict, Set, Tuple

from utils.logger import get_logger

logger = get_logger(__name__)


def calculate_module_priorities(
    software_profile: Any,
    vulnerability_profile: Any,
) -> Tuple[Dict[str, int], Dict[str, str]]:
    """Calculate module priorities based on affected modules.
    
    Args:
        software_profile: Target software profile with modules
        vulnerability_profile: Vulnerability profile with affected_modules
        
    Returns:
        Tuple of:
        - module_priorities: {module_name: priority (1=affected, 2=related, 3=other)}
        - file_to_module: {file_path: module_name}
    """
    # Get affected modules from vuln profile
    # Format: {file_path: module_category} or List[str]
    affected_modules = getattr(vulnerability_profile, 'affected_modules', {}) or {}
    
    if isinstance(affected_modules, dict):
        affected_categories = set(affected_modules.values())
    elif isinstance(affected_modules, list):
        affected_categories = set(affected_modules)
    else:
        affected_categories = set()
    
    logger.info(f"Affected categories: {affected_categories}")
    
    # Get modules from software profile
    modules = []
    if hasattr(software_profile, 'modules'):
        modules = software_profile.modules or []
    elif isinstance(software_profile, dict):
        modules = software_profile.get('modules', [])
    
    # Build module info map
    module_info = {}  # {name: {files, calls, called_by}}
    for m in modules:
        if hasattr(m, 'name'):
            name = m.name
            files = getattr(m, 'files', []) or []
            calls = set(getattr(m, 'calls_modules', []) or [])
            called_by = set(getattr(m, 'called_by_modules', []) or [])
        elif isinstance(m, dict):
            name = m.get('name', '')
            files = m.get('files', [])
            calls = set(m.get('calls_modules', []))
            called_by = set(m.get('called_by_modules', []))
        else:
            continue
        
        module_info[name] = {
            'files': files,
            'calls': calls,
            'called_by': called_by,
        }
    
    # Calculate priorities
    module_priorities = {}
    file_to_module = {}
    
    for name, info in module_info.items():
        # Priority 1: Directly affected (same category)
        if name in affected_categories:
            priority = 1
        # Priority 2: Related (calls or called by affected)
        elif _is_related(info, affected_categories):
            priority = 2
        # Priority 3: Other
        else:
            priority = 3
        
        module_priorities[name] = priority
        
        # Map files to module
        for f in info['files']:
            file_to_module[f] = name
    
    # Log stats
    p1 = sum(1 for p in module_priorities.values() if p == 1)
    p2 = sum(1 for p in module_priorities.values() if p == 2)
    p3 = sum(1 for p in module_priorities.values() if p == 3)
    logger.info(f"Module priorities: {p1} affected, {p2} related, {p3} other")
    logger.info(f"Total files mapped: {len(file_to_module)}")
    
    return module_priorities, file_to_module


def _is_related(module_info: Dict, affected: Set[str]) -> bool:
    """Check if module is related to affected modules."""
    # Check if it calls or is called by affected modules
    calls = module_info.get('calls', set())
    called_by = module_info.get('called_by', set())
    return bool((calls & affected) or (called_by & affected))
