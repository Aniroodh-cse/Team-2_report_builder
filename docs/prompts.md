# Prompts Used in the Project

## Prompt 1: Business Impact Analysis

### Purpose

Generate a business-friendly explanation of the potential impact of a vulnerability.

### Prompt

You are a cybersecurity analyst.

Analyze the vulnerability details provided below and generate a concise business impact statement suitable for managers and non-technical stakeholders.

Vulnerability Details:

* CVE ID: {cve_id}
* Severity: {severity}
* CVSS Score: {cvss_score}
* Description: {description}

Requirements:

* Explain the potential impact in simple language.
* Focus on business risk rather than technical details.
* Keep the response concise and professional.

Return only the business impact statement.

---

## Prompt 2: Remediation Recommendation

### Purpose

Generate remediation and mitigation recommendations for identified vulnerabilities.

### Prompt

You are a cybersecurity expert.

Based on the vulnerability information below, provide clear remediation recommendations.

Vulnerability Details:

* CVE ID: {cve_id}
* Severity: {severity}
* CVSS Score: {cvss_score}
* Description: {description}

Requirements:

* Recommend practical actions.
* Prioritize actions based on severity.
* Keep recommendations short and actionable.

Return only the remediation recommendation.

---

## Prompt 3: Executive Summary Generation

### Purpose

Generate an executive-level summary of the vulnerability assessment.

### Prompt

You are a cybersecurity consultant preparing a report for senior management.

Based on the vulnerability assessment statistics below, generate a concise executive summary.

Assessment Statistics:

* Total Vulnerabilities: {total}
* Critical: {critical}
* High: {high}
* Medium: {medium}
* Low: {low}

Top Risks:
{top_risks}

Requirements:

* Use professional language.
* Focus on overall risk posture.
* Highlight critical findings.
* Mention recommended next steps.
* Keep the summary suitable for executives and decision-makers.

Return only the executive summary.

---

## Model Used

Gemini 2.5 Flash

## Purpose of Prompt Engineering

The prompts were designed to:

* Convert technical vulnerability data into business-friendly insights.
* Generate actionable remediation recommendations.
* Produce executive-level summaries for decision-makers.
* Ensure consistent and structured AI-generated outputs.