import os
import json
import logging
from typing import Dict, Any, List, Optional
import google.generativeai as genai
from src.prompts import CVE_ANALYSIS_PROMPT_TEMPLATE, EXECUTIVE_SUMMARY_PROMPT_TEMPLATE

logger = logging.getLogger(__name__)

class AISummaryEngine:
    def __init__(self, api_key: Optional[str] = None, model_name: str = "gemini-1.5-flash"):
        self.api_key = api_key or os.getenv("GEMINI_API_KEY")
        self.model_name = model_name or os.getenv("GEMINI_MODEL", "gemini-1.5-flash")
        self.initialized = False
        
        # Check if we have a valid key (avoid dummy/empty keys)
        if self.api_key and not self.api_key.startswith("your_") and len(self.api_key) > 10:
            try:
                genai.configure(api_key=self.api_key)
                self.model = genai.GenerativeModel(self.model_name)
                self.initialized = True
                logger.info(f"Gemini API initialized with model {self.model_name}")
            except Exception as e:
                logger.error(f"Failed to configure Gemini API: {e}")
        else:
            logger.warning("Gemini API key is missing, invalid or placeholder. Running in Mock/Fallback mode.")

    def analyze_cve(self, cve_data: Dict[str, Any]) -> Dict[str, str]:
        """
        Generates Business Impact, Executive-Friendly Explanation, Remediation,
        and Priority Justification for a CVE using Gemini.
        Falls back to rule-based mock response if API is offline/unconfigured.
        """
        cve_id = cve_data.get("CVE_ID", "Unknown CVE")
        cvss_score = cve_data.get("CVSS_Score", 0.0)
        severity = cve_data.get("Severity", "Unknown")
        description = cve_data.get("Description", "No description available.")
        published_date = cve_data.get("Published_Date", "Unknown date")

        if not self.initialized:
            logger.info(f"Using mock analysis for {cve_id} (Gemini API not configured)")
            return self._generate_mock_analysis(cve_id, cvss_score, severity, description)

        prompt = CVE_ANALYSIS_PROMPT_TEMPLATE.format(
            cve_id=cve_id,
            cvss_score=cvss_score,
            severity=severity,
            description=description,
            published_date=published_date
        )

        try:
            # Set response type to JSON
            generation_config = {
                "response_mime_type": "application/json"
            }
            
            response = self.model.generate_content(
                prompt,
                generation_config=generation_config
            )
            
            result = json.loads(response.text)
            
            # Validate required keys are present
            required_keys = ["business_impact", "executive_explanation", "remediation", "priority_justification"]
            for key in required_keys:
                if key not in result:
                    result[key] = f"Information not generated for {key}."
            
            return result
            
        except Exception as e:
            logger.error(f"Error calling Gemini for {cve_id}: {e}")
            return self._generate_mock_analysis(cve_id, cvss_score, severity, description)

    def generate_executive_summary(self, stats: Dict[str, int], top_risks: List[Dict[str, Any]]) -> str:
        """
        Generates an overall executive summary based on vulnerability counts and top risks.
        Falls back to rule-based markdown text if API is offline.
        """
        # Format top risks into readable summary text for the prompt
        top_risks_text = ""
        for item in top_risks[:5]:
            top_risks_text += (
                f"- **{item.get('CVE_ID')}** (CVSS: {item.get('CVSS_Score', 0.0)} - {item.get('Severity')}): "
                f"{item.get('Description', '')[:120]}...\n"
            )

        if not self.initialized:
            logger.info("Using mock executive summary (Gemini API not configured)")
            return self._generate_mock_executive_summary(stats, top_risks_text)

        prompt = EXECUTIVE_SUMMARY_PROMPT_TEMPLATE.format(
            total=stats.get("Total", 0),
            critical=stats.get("Critical", 0),
            high=stats.get("High", 0),
            medium=stats.get("Medium", 0),
            low=stats.get("Low", 0),
            top_risks_text=top_risks_text
        )

        try:
            response = self.model.generate_content(prompt)
            return response.text
        except Exception as e:
            logger.error(f"Error calling Gemini for Executive Summary: {e}")
            return self._generate_mock_executive_summary(stats, top_risks_text)

    def _generate_mock_analysis(self, cve_id: str, score: float, severity: str, desc: str) -> Dict[str, str]:
        """Generates realistic, professional cybersecurity analysis values for testing."""
        return {
            "business_impact": (
                f"Exploitation of {cve_id} could lead to operational disruption. "
                f"Given the {severity} severity, this poses a notable threat to business continuity, "
                f"potentially exposing sensitive data or creating entry points for ransomware."
            ),
            "executive_explanation": (
                f"A vulnerability exists that affects systems. An attacker could exploit this to bypass "
                f"security measures or execute unauthorized actions. (Original Description: {desc[:150]}...)"
            ),
            "remediation": (
                f"Apply vendor-released security patches immediately. If patches are not feasible, "
                f"implement firewall ingress rules to restrict network access, and enable logging to detect exploit attempts."
            ),
            "priority_justification": (
                f"Classified as {severity} (CVSS: {score}). This should be prioritized for remediation in line with "
                f"standard SLA guidelines (e.g., within 14 days for high risk, 30 days for medium)."
            )
        }

    def _generate_mock_executive_summary(self, stats: Dict[str, int], top_risks_text: str) -> str:
        """Generates a professional markdown summary when LLM is unavailable."""
        return f"""# Cybersecurity Vulnerability & Patch Report (Static Fallback)

## Executive Summary

This report provides a high-level summary of the vulnerability scan data. A total of **{stats.get('Total')}** vulnerabilities were analyzed, ranging from Low to Critical risk profiles.

### Risk Distribution
- **Critical (CVSS >= 9.0)**: {stats.get('Critical')}
- **High (7.0 <= CVSS < 9.0)**: {stats.get('High')}
- **Medium (4.0 <= CVSS < 7.0)**: {stats.get('Medium')}
- **Low (CVSS < 4.0)**: {stats.get('Low')}

### High-Level Cyber Posture Review
The scan indicates active exposures across several systems. Immediate remediation focus should be dedicated to resolving Critical and High severity findings, which represent the path of least resistance for potential threat actors.

## Key Strategic Recommendations

1. **Immediate Remediation Campaign**: Prioritize patching of the top risk vectors listed below.
2. **Implement Compensating Controls**: Where patching is delayed due to system dependency constraints, restrict network access.
3. **Enhance Patch Cycle SLAs**: Establish a vulnerability management policy with strict SLAs (e.g., 48 hours for Criticals).

## Top Risks Under Analysis
{top_risks_text}
"""
