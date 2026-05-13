import pytest
from Correlate import correlate_vulnerabilities

def test_detect_vuln_03_tls():
    # White-box test: Validates if the engine identifies TLS 1.0 (0x0301)
    results = correlate_vulnerabilities('mobsf_scan.json', 'traffic_capture.pcap')
    assert "VULN-03" in results

def test_secure_traffic_ignore():
    # Black-box test: Ensures secure TLS 1.3 traffic does not trigger an alert
    results = correlate_vulnerabilities('mobsf_scan.json', 'traffic_capture1.pcap')
    assert "VULN-03" not in results
