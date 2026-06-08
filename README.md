# Patch/Vulnerability Report Builder

An AI-powered cybersecurity reporting platform that transforms raw vulnerability scan exports into executive-friendly security reports. The system reads vulnerability scan data from JSON or CSV files, enriches CVE information using the National Vulnerability Database (NVD) API, prioritizes vulnerabilities based on CVSS scores, and leverages Gemini AI to generate business impact assessments, remediation recommendations, and executive summaries.

The platform helps security teams and decision-makers quickly identify critical risks and prioritize remediation efforts without manually analyzing lengthy vulnerability reports.

## Features

### Vulnerability Scan Processing

* Upload vulnerability scan exports in JSON or CSV format.
* Automatic extraction and validation of CVE identifiers.
* Support for batch processing of vulnerability records.

### NVD API Enrichment

* Fetches real-time vulnerability information from the National Vulnerability Database.
* Retrieves:

  * CVE Description
  * CVSS Score
  * Severity Level
  * Published Date
  * Reference Information

### AI-Powered Analysis

* Business Impact Assessment
* Remediation Recommendations
* Executive Summary Generation
* Risk Prioritization Insights

### Interactive Dashboard

* Built using Streamlit.
* Vulnerability statistics and metrics.
* Severity distribution charts.
* Top-20 risk-ranked vulnerabilities.
* Detailed CVE analysis view.

### Report Generation

* Generate downloadable reports in:

  * Markdown (.md)
  * PDF (.pdf)
* Includes executive summary, risk analysis, and recommendations.

### Testing & Validation

* Happy-path test cases using Pytest.
* Validation for file parsing, risk ranking, report generation, and vulnerability processing.

---

## Folder Structure

```text
PatchReportBuilder/
│
├── docs/
│   ├── AI_USAGE_NOTE.md
│   ├── prompts.md
│   └── architecture.md
│
├── input/
│   ├── sample_scan.json
│   └── nvd_cache.json
│
├── output/
│   ├── report.md
│   ├── report.pdf
│   └── sample_report.md
│
├── src/
│
├── tests/
│   ├── test_parser.py
│   ├── test_nvd_client.py
│   ├── test_risk_ranker.py
│   ├── test_report_generator.py
│   └── test_validator.py
│
├── app.py
├── requirements.txt
├── .env.example
└── README.md
```

---

## Installation Steps

### Clone Repository

```bash
git clone <repository-url>
cd PatchReportBuilder
```

### Create Virtual Environment

```bash
python -m venv venv
```

Windows:

```bash
venv\Scripts\activate
```

Linux/macOS:

```bash
source venv/bin/activate
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

---

## Environment Variables

Create a `.env` file in the project root:

```env
GEMINI_API_KEY=your_gemini_api_key
NVD_API_KEY=your_nvd_api_key
```

---

## Usage Instructions

Run the application:

```bash
streamlit run app.py
```

The application will launch locally and open the dashboard in your browser.

### Workflow

1. Enter Gemini API Key.
2. Enter NVD API Key.
3. Upload a vulnerability scan file (JSON/CSV).
4. Click Analyze.
5. System enriches vulnerabilities using NVD API.
6. Vulnerabilities are ranked based on CVSS severity.
7. Gemini AI generates:

   * Business Impact Analysis
   * Remediation Recommendations
   * Executive Summary
8. Dashboard displays results.
9. Download generated reports in Markdown or PDF format.

---

## Sample Input

```json
{
  "scan_name": "Quarterly Security Assessment",
  "vulnerabilities": [
    {
      "asset_name": "Web Server",
      "cve_id": "CVE-2024-3400"
    }
  ]
}
```

---

## Dashboard Output

The dashboard provides:

* Vulnerability Severity Distribution
* Top 20 Risk Metrics
* Detailed CVE Deep Dive
* Executive Summary
* Security Posture Overview
* Downloadable Reports

---

## Sample Report Output

Generated reports contain:

* Executive Summary
* Vulnerability Statistics
* Risk Rankings
* Business Impact Analysis
* Remediation Recommendations
* Security Posture Review

---

## Technology Stack

* Python
* Streamlit
* Gemini 2.5 Flash
* NVD API
* Pandas
* Plotly
* Pytest

---

## Future Enhancements

* Support for Nessus and OpenVAS exports.
* Historical vulnerability tracking.
* Multi-user authentication.
* Email report delivery.
* Integration with ticketing systems.
* Local LLM support using Ollama.

---

## Team

**Team 2**

Project: **Patch/Vulnerability Report Builder**

Developed as part of an AI-powered cybersecurity automation challenge.
