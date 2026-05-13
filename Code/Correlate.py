import json
import pyshark

def correlate_vulnerabilities(mobsf_report_path, pcap_file_path):
    # Load MobSF static analysis findings [cite: 187]
    with open(mobsf_report_path, 'r') as file:
        mobsf_data = json.load(file) [cite: 189]
    
    # Use context manager to ensure resources are safely released [cite: 244]
    with pyshark.FileCapture(pcap_file_path, display_filter='http or tls') as capture: [cite: 191]
        
        correlated_findings = []
        
        # Check for VULN-02: Hardcoded API Keys in MobSF [cite: 193]
        if "hardcoded_secrets" in mobsf_data: [cite: 194]
            print("[ALERT] VULN-02: Hardcoded API Keys detected in binary.") [cite: 195]
            
        # Check for VULN-01 & VULN-03: Unencrypted HTTP or Insecure TLS [cite: 196]
        for packet in capture: [cite: 197]
            if hasattr(packet, 'http'): [cite: 198]
                print(f"[ALERT] VULN-01: Unencrypted HTTP Call detected to {packet.ip.dst}") [cite: 199]
                correlated_findings.append("VULN-01") [cite: 200]
            
            elif hasattr(packet, 'tls'): [cite: 201]
                # Safely check for record_version to prevent AttributeError [cite: 202]
                tls_version = getattr(packet.tls, 'record_version', None)
                if tls_version in ['0x0301', '0x0302']: # TLS 1.0/1.1
                    print(f"[ALERT] VULN-03: Insecure TLS Version detected.") [cite: 203]
                    correlated_findings.append("VULN-03") [cite: 204]
                    
    return correlated_findings [cite: 205]

# Execute Correlation with local files [cite: 206]
try:
    correlate_vulnerabilities('mobsf_scan.json', 'traffic_capture1.pcap') [cite: 207]
except Exception as e:
    print(f"[ERROR] Application crashed: {e}")
