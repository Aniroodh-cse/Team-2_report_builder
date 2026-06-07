An AI-powered vulnerability analysis and reporting platform that transforms raw vulnerability scan exports into executive-friendly security reports.

The application accepts CSV and JSON scan files, enriches CVE data using the NVD API, prioritizes vulnerabilities based on CVSS scores, and uses Gemini AI to generate business impact analysis, remediation recommendations, and executive summaries.

Features
Upload vulnerability scan files (CSV/JSON)
CVE enrichment using NVD API
Risk ranking and Top-20 vulnerability prioritization
AI-generated business impact analysis
Executive summary generation
Interactive dashboard with charts and statistics
Markdown and PDF report export
Tech Stack
Frontend: Streamlit
Backend: Python
AI: Gemini 2.5 Flash
API: NVD API
Visualization: Plotly
Testing: Pytest
How It Works
Upload a vulnerability scan file.
Extract CVE identifiers.
Fetch vulnerability details from NVD API.
Rank vulnerabilities by CVSS score.
Generate AI-powered insights and recommendations.
Download the final executive report.
Project Goal

To help security teams and decision-makers quickly understand, prioritize, and remediate vulnerabilities without manually analyzing large vulnerability reports.