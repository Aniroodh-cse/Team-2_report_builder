import csv
import json
import logging
import re
from typing import List, Union, IO, Any

logger = logging.getLogger(__name__)

# Compile CVE regex pattern for scanning
CVE_PATTERN = re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.IGNORECASE)

def extract_cves_from_text(text: str) -> List[str]:
    """
    Extracts all potential CVE IDs from a raw block of text using regular expressions.
    """
    if not text:
        return []
    matches = CVE_PATTERN.findall(text)
    # Return normalized (uppercase) CVE IDs
    return [match.upper() for match in matches]

def parse_json(file_content: Union[str, bytes, IO[Any]]) -> List[str]:
    """
    Parses a JSON file or content string and extracts potential CVE IDs.
    Supports a list of objects or a dict structure, searching key names and text.
    """
    cve_ids: List[str] = []
    
    # Resolve content to string
    if hasattr(file_content, "read"):
        content_str = file_content.read()
        if isinstance(content_str, bytes):
            content_str = content_str.decode("utf-8", errors="ignore")
    elif isinstance(file_content, bytes):
        content_str = file_content.decode("utf-8", errors="ignore")
    else:
        content_str = str(file_content)
        
    try:
        data = json.loads(content_str)
        # Traverse JSON structure to look for typical CVE keys
        cve_ids = _extract_from_json_data(data)
        
        # If no CVEs were found via structured key matching, fallback to regex scanning
        if not cve_ids:
            logger.debug("No CVEs found through structured JSON keys; falling back to regex scanning.")
            cve_ids = extract_cves_from_text(content_str)
            
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse JSON file content: {e}")
        # Fallback to regex scanning even if JSON is slightly malformed
        cve_ids = extract_cves_from_text(content_str)
        
    return cve_ids

def _extract_from_json_data(data: Any) -> List[str]:
    """
    Recursively searches JSON data structures for CVE IDs.
    Looks for keys containing 'cve', 'cve_id', 'vulnerability_id', etc.
    """
    cves = []
    cve_keys = {"cve", "cve_id", "cveid", "vulnerability", "vulnerability_id", "id"}
    
    if isinstance(data, list):
        for item in data:
            cves.extend(_extract_from_json_data(item))
    elif isinstance(data, dict):
        for key, value in data.items():
            # If key matches CVE patterns, collect the value
            if key.lower() in cve_keys and isinstance(value, str):
                cves.append(value.strip())
            else:
                cves.extend(_extract_from_json_data(value))
    elif isinstance(data, str):
        # If a string value matches the CVE pattern directly
        if CVE_PATTERN.match(data.strip()):
            cves.append(data.strip())
            
    return cves

def parse_csv(file_content: Union[str, bytes, IO[Any]]) -> List[str]:
    """
    Parses a CSV file or content string and extracts potential CVE IDs.
    Looks for column headers matching 'cve' or parses rows.
    """
    cve_ids: List[str] = []
    
    # Resolve content to string lines
    if hasattr(file_content, "read"):
        content_str = file_content.read()
        if isinstance(content_str, bytes):
            content_str = content_str.decode("utf-8", errors="ignore")
    elif isinstance(file_content, bytes):
        content_str = file_content.decode("utf-8", errors="ignore")
    else:
        content_str = str(file_content)
        
    lines = content_str.splitlines()
    if not lines:
        return []
        
    try:
        reader = list(csv.reader(lines))
        if not reader:
            return []
            
        first_row = reader[0]
        
        # Check if first row is a header.
        # If any element matches a CVE pattern directly, it's a data row, not a header row.
        is_header = False
        for cell in first_row:
            if CVE_PATTERN.match(cell.strip()):
                is_header = False
                break
        else:
            # If no element matches CVE pattern, check if any looks like standard headers
            for cell in first_row:
                cell_lower = cell.lower().strip()
                if "cve" in cell_lower or cell_lower == "id" or "vulnerability" in cell_lower:
                    is_header = True
                    break

        if is_header:
            headers = first_row
            data_rows = reader[1:]
            
            # Find indices of columns that look like CVE IDs
            cve_indices = []
            for idx, header in enumerate(headers):
                h_lower = header.lower().strip()
                if "cve" in h_lower or h_lower == "id" or "vulnerability" in h_lower:
                    cve_indices.append(idx)
                    
            if cve_indices:
                for row in data_rows:
                    for idx in cve_indices:
                        if idx < len(row):
                            val = row[idx].strip()
                            if val:
                                cve_ids.append(val)
            else:
                # If no headers matched, scan every cell in data rows for CVE patterns
                for row in data_rows:
                    for cell in row:
                        cve_ids.extend(extract_cves_from_text(cell))
        else:
            # First row is data. Scan all rows (including first row) for CVE patterns
            for row in reader:
                for cell in row:
                    cve_ids.extend(extract_cves_from_text(cell))
            
    except Exception as e:
        logger.error(f"Failed to parse CSV file content: {e}")
        cve_ids = extract_cves_from_text(content_str)
        
    return cve_ids
