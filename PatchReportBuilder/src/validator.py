import re
import logging
from typing import List, Tuple

logger = logging.getLogger(__name__)

# Strict CVE regex validator
CVE_STRICT_PATTERN = re.compile(r'^CVE-\d{4}-\d{4,7}$', re.IGNORECASE)

def is_valid_cve(cve_id: str) -> bool:
    """
    Returns True if the cve_id matches the standard CVE format (e.g. CVE-2024-3400).
    """
    if not cve_id or not isinstance(cve_id, str):
        return False
    return bool(CVE_STRICT_PATTERN.match(cve_id.strip()))

def clean_cve(cve_id: str) -> str:
    """
    Normalizes a CVE ID: strips whitespace and converts to uppercase.
    """
    if not cve_id:
        return ""
    return cve_id.strip().upper()

def validate_cves(cve_list: List[str]) -> Tuple[List[str], List[str]]:
    """
    Validates a list of CVE strings.
    Returns a tuple of (valid_cves, invalid_cves).
    Valid CVEs will be normalized (uppercase, trimmed) and deduplicated.
    """
    valid_set = set()
    invalid_list = []
    
    for cve in cve_list:
        if not cve or not isinstance(cve, str):
            continue
            
        cleaned = clean_cve(cve)
        if is_valid_cve(cleaned):
            valid_set.add(cleaned)
        else:
            invalid_list.append(cve)
            
    # Sort valid list to maintain deterministic order
    valid_list = sorted(list(valid_set))
    
    if invalid_list:
        logger.warning(f"Detected {len(invalid_list)} invalid CVE identifiers: {invalid_list}")
        
    return valid_list, invalid_list
