import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

def categorize_severity(score: float) -> str:
    """
    Categorizes severity strictly based on CVSS score:
    Critical: CVSS >= 9.0
    High: CVSS >= 7.0
    Medium: CVSS >= 4.0
    Low: CVSS < 4.0
    """
    if score >= 9.0:
        return "Critical"
    elif score >= 7.0:
        return "High"
    elif score >= 4.0:
        return "Medium"
    else:
        return "Low"

def rank_vulnerabilities(cve_details_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Ranks vulnerabilities by CVSS score in descending order.
    Uses CVE ID descending as a secondary sorting key for tie-breaking.
    Updates the Severity field in each item to maintain consistency.
    """
    ranked_list = []
    for item in cve_details_list:
        # Clone to avoid mutating original list in-place unexpectedly
        cve_copy = item.copy()
        
        # Recalculate/normalize Severity based on CVSS score
        score = cve_copy.get("CVSS_Score", 0.0)
        cve_copy["Severity"] = categorize_severity(score)
        ranked_list.append(cve_copy)
        
    # Sort: CVSS score descending, then CVE ID descending
    ranked_list.sort(key=lambda x: (x.get("CVSS_Score", 0.0), x.get("CVE_ID", "")), reverse=True)
    
    return ranked_list

def get_top_vulnerabilities(ranked_list: List[Dict[str, Any]], limit: int = 20) -> List[Dict[str, Any]]:
    """
    Returns the top N vulnerabilities.
    Adds a 'Rank' field (1-indexed) to each item.
    """
    top_list = []
    for rank, item in enumerate(ranked_list[:limit], start=1):
        cve_copy = item.copy()
        cve_copy["Rank"] = rank
        top_list.append(cve_copy)
    return top_list

def calculate_statistics(cve_details_list: List[Dict[str, Any]]) -> Dict[str, int]:
    """
    Calculates summary statistics: total and severity counts.
    """
    stats = {
        "Total": len(cve_details_list),
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0
    }
    
    for item in cve_details_list:
        score = item.get("CVSS_Score", 0.0)
        severity = categorize_severity(score)
        
        if severity == "Critical":
            stats["Critical"] += 1
        elif severity == "High":
            stats["High"] += 1
        elif severity == "Medium":
            stats["Medium"] += 1
        elif severity == "Low":
            stats["Low"] += 1
            
    return stats
