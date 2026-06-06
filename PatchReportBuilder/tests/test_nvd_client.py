import os
import requests
import pytest
from src.nvd_client import NVDClient

@pytest.fixture
def mock_nvd_response():
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2024-3400",
                    "descriptions": [
                        {"lang": "en", "value": "A critical command injection vulnerability in GlobalProtect."}
                    ],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "version": "3.1",
                                    "baseScore": 10.0,
                                    "baseSeverity": "CRITICAL"
                                }
                            }
                        ]
                    },
                    "published": "2024-04-12T14:15:08.313",
                    "references": [
                        {"url": "https://nvd.nist.gov/vuln/detail/CVE-2024-3400"}
                    ]
                }
            }
        ]
    }

def test_nvd_client_cache(tmp_path, mocker, mock_nvd_response):
    cache_file = tmp_path / "nvd_cache.json"
    client = NVDClient(api_key="fake_key", cache_path=str(cache_file))
    
    # Assert cache is empty initially
    assert client.cache == {}
    
    # Mock requests.get
    mock_get = mocker.patch("requests.get")
    mock_resp = mocker.Mock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = mock_nvd_response
    mock_get.return_value = mock_resp
    
    # Fetch CVE
    details = client.get_cve_details("CVE-2024-3400")
    
    # Verify values
    assert details["CVE_ID"] == "CVE-2024-3400"
    assert details["CVSS_Score"] == 10.0
    assert details["Severity"] == "Critical"
    assert details["Published_Date"] == "2024-04-12"
    assert "https://nvd.nist.gov/vuln/detail/CVE-2024-3400" in details["References"]
    assert details["Status"] == "Enriched"
    
    # Assert request was made to NVD
    mock_get.assert_called_once()
    
    # Assert it was cached
    assert "CVE-2024-3400" in client.cache
    assert os.path.exists(cache_file)
    
    # Fetch again (should load from cache, not API)
    mock_get.reset_mock()
    cached_details = client.get_cve_details("CVE-2024-3400")
    assert cached_details == details
    mock_get.assert_not_called()

def test_nvd_client_missing_cve(tmp_path, mocker):
    cache_file = tmp_path / "nvd_cache.json"
    client = NVDClient(cache_path=str(cache_file))
    
    mock_get = mocker.patch("requests.get")
    mock_resp = mocker.Mock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"vulnerabilities": []} # Empty results
    mock_get.return_value = mock_resp
    
    details = client.get_cve_details("CVE-2024-9999")
    assert details["Status"] == "MISSING"
    assert details["CVSS_Score"] == 0.0
    assert details["Severity"] == "Unknown"

def test_nvd_client_api_failure(tmp_path, mocker):
    cache_file = tmp_path / "nvd_cache.json"
    client = NVDClient(cache_path=str(cache_file))
    
    # Force requests to fail with ConnectionError
    mock_get = mocker.patch("requests.get", side_effect=requests.RequestException("Connection timed out"))
    # Speed up sleep/retry times in test
    mocker.patch("time.sleep")
    
    details = client.get_cve_details("CVE-2024-8888")
    assert details["Status"] == "API_FAILURE"
    assert details["CVSS_Score"] == 0.0
    assert mock_get.call_count == 5 # Maximum retries
