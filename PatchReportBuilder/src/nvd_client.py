import os
import time
import random
import json
import logging
import requests
from typing import Dict, Any, Optional, List

logger = logging.getLogger(__name__)

CACHE_FILE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
    "input", 
    "nvd_cache.json"
)

class NVDClient:
    def __init__(self, api_key: Optional[str] = None, cache_path: str = CACHE_FILE_PATH):
        self.api_key = api_key or os.getenv("NVD_API_KEY")
        self.cache_path = cache_path
        self.cache = self._load_cache()
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def _load_cache(self) -> Dict[str, Any]:
        """Loads NVD data cache from a local JSON file."""
        if os.path.exists(self.cache_path):
            try:
                with open(self.cache_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Error reading cache file {self.cache_path}: {e}")
        # Ensure directory exists
        os.makedirs(os.path.dirname(self.cache_path), exist_ok=True)
        return {}

    def _save_cache(self) -> None:
        """Saves current cache to file."""
        try:
            os.makedirs(os.path.dirname(self.cache_path), exist_ok=True)
            with open(self.cache_path, "w", encoding="utf-8") as f:
                json.dump(self.cache, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving cache file {self.cache_path}: {e}")

    def get_cve_details(self, cve_id: str, force_refresh: bool = False) -> Dict[str, Any]:
        """
        Retrieves CVE details from the cache or the NVD API.
        Implements retries with exponential backoff and jitter for API requests.
        """
        cve_id = cve_id.strip().upper()
        
        if not force_refresh and cve_id in self.cache:
            logger.info(f"Loaded {cve_id} from cache.")
            return self.cache[cve_id]
            
        logger.info(f"Fetching {cve_id} from NVD API...")
        
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key

        params = {"cveId": cve_id}
        
        max_retries = 5
        base_delay = 1.0  # seconds
        
        for attempt in range(max_retries):
            try:
                response = requests.get(
                    self.base_url, 
                    headers=headers, 
                    params=params, 
                    timeout=15
                )
                
                # NVD API rate limits return 403 or 429
                if response.status_code in (403, 429):
                    delay = base_delay * (2 ** attempt) + random.uniform(0.1, 1.0)
                    logger.warning(
                        f"NVD API rate limit (status={response.status_code}) on attempt {attempt+1}. "
                        f"Retrying in {delay:.2f} seconds..."
                    )
                    time.sleep(delay)
                    continue
                    
                # Handle other bad statuses
                if response.status_code >= 500:
                    delay = base_delay * (2 ** attempt) + random.uniform(0.1, 1.0)
                    logger.warning(
                        f"NVD API Server Error (status={response.status_code}) on attempt {attempt+1}. "
                        f"Retrying in {delay:.2f} seconds..."
                    )
                    time.sleep(delay)
                    continue
                    
                response.raise_for_status()
                data = response.json()
                
                parsed_cve = self._parse_nvd_response(cve_id, data)
                
                # Only cache if we successfully retrieved or confirmed it is missing
                self.cache[cve_id] = parsed_cve
                self._save_cache()
                return parsed_cve
                
            except requests.RequestException as e:
                delay = base_delay * (2 ** attempt) + random.uniform(0.1, 1.0)
                logger.error(
                    f"Network error on attempt {attempt+1} fetching {cve_id}: {e}. "
                    f"Retrying in {delay:.2f} seconds..."
                )
                time.sleep(delay)
                
        # If all retries failed, return a fallback object (do not cache so we can try again next time)
        logger.error(f"Failed to fetch details for {cve_id} after {max_retries} attempts.")
        return self._generate_fallback_cve(cve_id, "API_FAILURE", "Failed to fetch details due to network/API failure.")

    def _parse_nvd_response(self, cve_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parses the JSON response from NVD API v2.0.
        """
        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            logger.warning(f"{cve_id} not found in NVD database.")
            return self._generate_fallback_cve(cve_id, "MISSING", "CVE not found in NVD database.")
            
        cve_data = vulnerabilities[0].get("cve", {})
        
        # 1. Extract Description
        description = "No description available."
        descriptions = cve_data.get("descriptions", [])
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break
        if description == "No description available." and descriptions:
            description = descriptions[0].get("value", "")
            
        # 2. Extract CVSS Score and Severity
        cvss_score = 0.0
        severity = "Unknown"
        metrics = cve_data.get("metrics", {})
        
        # Try CVSS v3.1, then v3.0, then v2
        cvss_found = False
        
        for v31 in metrics.get("cvssMetricV31", []):
            cvss_data = v31.get("cvssData", {})
            cvss_score = cvss_data.get("baseScore", 0.0)
            severity = cvss_data.get("baseSeverity", "Unknown").capitalize()
            cvss_found = True
            break
            
        if not cvss_found:
            for v30 in metrics.get("cvssMetricV30", []):
                cvss_data = v30.get("cvssData", {})
                cvss_score = cvss_data.get("baseScore", 0.0)
                severity = cvss_data.get("baseSeverity", "Unknown").capitalize()
                cvss_found = True
                break
                
        if not cvss_found:
            for v2 in metrics.get("cvssMetricV2", []):
                cvss_data = v2.get("cvssData", {})
                cvss_score = cvss_data.get("baseScore", 0.0)
                # CVSS v2 uses 'severity' on the wrapper metric block rather than cvssData
                severity = v2.get("severity", "Unknown").capitalize()
                cvss_found = True
                break

        # If CVSS was found but severity is missing or unknown, infer it
        if cvss_score > 0.0 and (severity == "Unknown" or not severity):
            severity = self._infer_severity(cvss_score)
            
        # 3. Extract Published Date
        published_date = cve_data.get("published", "")
        # Normalize date format if it's long: e.g. '2024-04-12T14:15:08.313' -> '2024-04-12'
        if published_date and "T" in published_date:
            published_date = published_date.split("T")[0]
            
        # 4. Extract References
        references = []
        for ref in cve_data.get("references", []):
            url = ref.get("url")
            if url:
                references.append(url)

        return {
            "CVE_ID": cve_id,
            "Description": description,
            "CVSS_Score": cvss_score,
            "Severity": severity,
            "Published_Date": published_date,
            "References": references,
            "Status": "Enriched"
        }

    def _infer_severity(self, score: float) -> str:
        if score >= 9.0:
            return "Critical"
        elif score >= 7.0:
            return "High"
        elif score >= 4.0:
            return "Medium"
        elif score > 0.0:
            return "Low"
        return "Unknown"

    def _generate_fallback_cve(self, cve_id: str, status: str, description: str) -> Dict[str, Any]:
        """Generates a structured fallback CVE details block when NVD fetch fails or is empty."""
        return {
            "CVE_ID": cve_id,
            "Description": description,
            "CVSS_Score": 0.0,
            "Severity": "Unknown",
            "Published_Date": "",
            "References": [],
            "Status": status
        }
