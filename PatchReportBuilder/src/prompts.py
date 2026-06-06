# LLM Prompts Configuration

CVE_ANALYSIS_PROMPT_TEMPLATE = """You are an expert Cybersecurity Incident Responder and IT Risk Analyst.
Analyze the following vulnerability detail fetched from the National Vulnerability Database (NVD):

CVE ID: {cve_id}
CVSS Score: {cvss_score}
Severity: {severity}
Description: {description}
Published Date: {published_date}

Generate a detailed risk analysis in JSON format. The JSON must contain exactly these keys and no others:
{{
  "business_impact": "An executive-level explanation of the business risk (financial, operational, reputational, legal) if this vulnerability is exploited.",
  "executive_explanation": "A simplified, jargon-free explanation of what the vulnerability is and how an attacker could exploit it, suitable for non-technical executives.",
  "remediation": "Clear, actionable remediation steps (e.g., patches, configuration changes, workarounds, or mitigating controls).",
  "priority_justification": "A justification of the remediation priority based on the CVSS score, exploitability, and typical enterprise exposure."
}}

Response:"""

EXECUTIVE_SUMMARY_PROMPT_TEMPLATE = """You are a Chief Information Security Officer (CISO) writing a report for the board of directors and senior executives.
Provide an executive-friendly vulnerability summary and strategic recommendations based on the following scan statistics and top risk items:

Vulnerability Statistics:
- Total Vulnerabilities: {total}
- Critical Severity (CVSS >= 9.0): {critical}
- High Severity (7.0 <= CVSS < 9.0): {high}
- Medium Severity (4.0 <= CVSS < 7.0): {medium}
- Low Severity (CVSS < 4.0): {low}

Top 5 Highest-Risk Vulnerabilities:
{top_risks_text}

Generate a professional, compelling Executive Summary. Focus on:
1. High-level state of security posture implied by these numbers.
2. Immediate business risks (e.g., ransomware exposure, data exfiltration).
3. Strategic and tactical recommendations for patch management and defense-in-depth.
4. Clear timeline expectations for remediation (e.g. Critical in 24-48 hours, High in 14 days, etc.).

Format your response in professional Markdown. Use clear headings, bullet points, and highlight key takeaways. Do not include introductory or concluding conversational text outside of the report.

Response:"""
