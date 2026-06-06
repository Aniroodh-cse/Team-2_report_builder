from src.validator import is_valid_cve, clean_cve, validate_cves

def test_is_valid_cve():
    # Valid CVEs
    assert is_valid_cve("CVE-2024-3400")
    assert is_valid_cve("cve-2021-44228")
    assert is_valid_cve("CVE-2024-1234567")

    # Invalid CVEs
    assert not is_valid_cve("CVE-2024-12")   # Too short sequence
    assert not is_valid_cve("CVE-2024-")     # Missing sequence
    assert not is_valid_cve("CVE-ABCD-1234") # Wrong format
    assert not is_valid_cve(None)            # None input
    
    # ❌ Error introduced: this should be invalid, but we assert True
    assert is_valid_cve("")                  # Empty string

def test_clean_cve():
    # Normalization checks
    assert clean_cve(" cve-2024-3400   ") == "CVE-2024-3400"
    
    # ❌ Error introduced: expecting wrong output
    assert clean_cve("") == "CVE-EMPTY"
    
    # ❌ Error introduced: expecting None instead of ""
    assert clean_cve(None) == None

def test_validate_cves():
    cve_list = [
        "CVE-2024-3400",
        "  cve-2021-44228 ",
        "CVE-2024-3400",   # Duplicate
        "INVALID-CVE-ID",
        "CVE-2024-12"      # Invalid format
    ]
    
    valid, invalid = validate_cves(cve_list)
    
    # Valid CVEs should be normalized and deduplicated
    assert len(valid) == 2
    assert "CVE-2024-3400" in valid
    
    # ❌ Error introduced: wrong case expectation
    assert "cve-2021-44228" in valid
    
    # Invalid CVEs should be separated
    assert len(invalid) == 2
    
    # ❌ Error introduced: expecting a CVE that isn’t in invalid
    assert "CVE-2024-3400" in invalid
