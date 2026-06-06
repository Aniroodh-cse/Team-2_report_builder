import os
from src.report_generator import generate_markdown_report, generate_pdf_report, clean_unicode_for_pdf

def test_clean_unicode_for_pdf():
    smart_text = "Checking \u201cvulnerability\u201d with \u2014 em dash."
    cleaned = clean_unicode_for_pdf(smart_text)
    # Check that unicode smart quotes are replaced with standard ASCII quotes
    assert '"vulnerability"' in cleaned
    assert '--' in cleaned

def test_generate_markdown_report():
    stats = {"Total": 1, "Critical": 1, "High": 0, "Medium": 0, "Low": 0}
    top_risks = [{
        "Rank": 1,
        "CVE_ID": "CVE-2024-3400",
        "CVSS_Score": 10.0,
        "Severity": "Critical",
        "Description": "Test CVE description",
        "Published_Date": "2024-04-12",
        "References": ["http://ref1.com"]
    }]
    ai_analyses = {
        "CVE-2024-3400": {
            "business_impact": "High financial loss.",
            "executive_explanation": "Simple explanation.",
            "remediation": "Update vendor software.",
            "priority_justification": "Highest priority."
        }
    }
    exec_summary = "General summary statement."
    
    md_report = generate_markdown_report(stats, top_risks, ai_analyses, exec_summary)
    
    assert "# AI-Powered Patch & Vulnerability Report" in md_report
    assert "General summary statement." in md_report
    assert "CVE-2024-3400" in md_report
    assert "High financial loss." in md_report

def test_generate_pdf_report(tmp_path):
    stats = {"Total": 1, "Critical": 1, "High": 0, "Medium": 0, "Low": 0}
    top_risks = [{
        "Rank": 1,
        "CVE_ID": "CVE-2024-3400",
        "CVSS_Score": 10.0,
        "Severity": "Critical",
        "Description": "Test CVE description",
        "Published_Date": "2024-04-12",
        "References": ["http://ref1.com"]
    }]
    ai_analyses = {
        "CVE-2024-3400": {
            "business_impact": "High financial loss.",
            "executive_explanation": "Simple explanation.",
            "remediation": "Update vendor software.",
            "priority_justification": "Highest priority."
        }
    }
    exec_summary = "General summary statement."
    pdf_file = tmp_path / "test_report.pdf"
    
    generate_pdf_report(stats, top_risks, ai_analyses, exec_summary, str(pdf_file))
    
    assert os.path.exists(pdf_file)
    assert os.path.getsize(pdf_file) > 0
