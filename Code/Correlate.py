import json
import pyshark

def correlate_vulnerabilities(mobsf_report_path, pcap_file_path):
    # Load MobSF static analysis findings
    with open(mobsf_report_path, 'r') as file:
        mobsf_data = json.load(file)
    
    # Load Wireshark packet capture
    capture = pyshark.FileCapture(pcap_file_path, display_filter='http or tls')
    
    correlated_findings = []
    
    # Check for VULN-02: Hardcoded API Keys in MobSF
    if "hardcoded_secrets" in mobsf_data:
        print("[ALERT] VULN-02: Hardcoded API Keys detected in binary.")
        
    # Check for VULN-01 & VULN-03: Unencrypted HTTP or Insecure TLS
    for packet in capture:
        if hasattr(packet, 'http'):
            print(f"[ALERT] VULN-01: Unencrypted HTTP Call detected to {packet.ip.dst}")
            correlated_findings.append("VULN-01")
        elif hasattr(packet, 'tls'):
            if packet.tls.record_version in ['0x0301', '0x0302']: # TLS 1.0/1.1
                print(f"[ALERT] VULN-03: Insecure TLS Version detected.")
                correlated_findings.append("VULN-03")
                
    return correlated_findings

# Execute Correlation
correlate_vulnerabilities('mobsf_scan.json', 'traffic_capture.pcap')