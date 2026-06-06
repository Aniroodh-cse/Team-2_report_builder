import json
from src.parser import parse_json, parse_csv, extract_cves_from_text

def test_extract_cves_from_text():
    raw_text = "Checking vulnerability CVE-2024-3400 and maybe CVE-2021-12345 or some random CVE-ABC-123."
    results = extract_cves_from_text(raw_text)
    assert "CVE-2024-3400" in results
    assert "CVE-2021-12345" in results
    assert len(results) == 2

def test_parse_json_structured():
    json_data = [
        {"CVE_ID": "CVE-2024-3400"},
        {"cve": "cve-2021-44228"}
    ]
    json_str = json.dumps(json_data)
    results = parse_json(json_str)
    assert len(results) == 2
    assert "CVE-2024-3400" in results
    assert "cve-2021-44228" in results

def test_parse_json_raw_fallback():
    # Malformed JSON or JSON that doesn't match standard keys but contains CVEs
    json_str = '{"notes": "Vulnerability CVE-2023-1111 found in secondary module."}'
    results = parse_json(json_str)
    assert len(results) == 1
    assert "CVE-2023-1111" in results

def test_parse_json_invalid_decode():
    malformed_json = '{"notes": "CVE-2023-1111", invalid json here }'
    results = parse_json(malformed_json)
    # Even if JSON is invalid, regex fallback should extract it!
    assert "CVE-2023-1111" in results

def test_parse_csv_structured():
    csv_str = "CVE_ID,Severity,Status\nCVE-2024-3400,Critical,Enriched\nCVE-2022-22965,High,Enriched"
    results = parse_csv(csv_str)
    assert len(results) == 2
    assert "CVE-2024-3400" in results
    assert "CVE-2022-22965" in results

def test_parse_csv_no_headers():
    csv_str = "CVE-2024-3400,Some value\nCVE-2021-44228,Another value"
    results = parse_csv(csv_str)
    assert len(results) == 2
    assert "CVE-2024-3400" in results
    assert "CVE-2021-44228" in results
