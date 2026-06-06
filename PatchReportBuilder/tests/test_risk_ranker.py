from src.risk_ranker import categorize_severity, rank_vulnerabilities, get_top_vulnerabilities, calculate_statistics

def test_categorize_severity():
    assert categorize_severity(10.0) == "Critical"
    assert categorize_severity(9.0) == "Critical"
    assert categorize_severity(8.9) == "High"
    assert categorize_severity(7.0) == "High"
    assert categorize_severity(6.9) == "Medium"
    assert categorize_severity(4.0) == "Medium"
    assert categorize_severity(3.9) == "Low"
    assert categorize_severity(0.0) == "Low"

def test_rank_vulnerabilities():
    cves = [
        {"CVE_ID": "CVE-2021-0001", "CVSS_Score": 5.0},
        {"CVE_ID": "CVE-2024-0002", "CVSS_Score": 9.8},
        {"CVE_ID": "CVE-2022-0003", "CVSS_Score": 7.5},
        {"CVE_ID": "CVE-2023-0004", "CVSS_Score": 7.5} # Duplicate score
    ]
    
    ranked = rank_vulnerabilities(cves)
    
    # Assert CVSS Score descending
    assert ranked[0]["CVE_ID"] == "CVE-2024-0002"
    assert ranked[0]["Severity"] == "Critical"
    
    # Assert tie breaking (CVE-2023-0004 vs CVE-2022-0003) - older or lexicographically higher first since reverse=True
    # Wait, 'CVE-2023-0004' > 'CVE-2022-0003' and reverse=True, so CVE-2023-0004 should be index 1
    assert ranked[1]["CVE_ID"] == "CVE-2023-0004"
    assert ranked[1]["Severity"] == "High"
    assert ranked[2]["CVE_ID"] == "CVE-2022-0003"
    assert ranked[2]["Severity"] == "High"
    
    assert ranked[3]["CVE_ID"] == "CVE-2021-0001"
    assert ranked[3]["Severity"] == "Medium"

def test_get_top_vulnerabilities():
    ranked = [
        {"CVE_ID": f"CVE-2024-{i:04d}", "CVSS_Score": 10.0 - (i * 0.1)}
        for i in range(30)
    ]
    
    top = get_top_vulnerabilities(ranked, limit=20)
    assert len(top) == 20
    assert top[0]["Rank"] == 1
    assert top[19]["Rank"] == 20
    assert top[19]["CVE_ID"] == "CVE-2024-0019"

def test_calculate_statistics():
    cves = [
        {"CVSS_Score": 10.0}, # Critical
        {"CVSS_Score": 9.2},  # Critical
        {"CVSS_Score": 7.2},  # High
        {"CVSS_Score": 5.5},  # Medium
        {"CVSS_Score": 2.1},  # Low
        {"CVSS_Score": 0.0}   # Low
    ]
    
    stats = calculate_statistics(cves)
    assert stats["Total"] == 6
    assert stats["Critical"] == 2
    assert stats["High"] == 1
    assert stats["Medium"] == 1
    assert stats["Low"] == 2
