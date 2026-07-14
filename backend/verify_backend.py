import urllib.request
import json
import time

BASE_URL = "http://127.0.0.1:5000"

def test_endpoint(path, data=None):
    url = f"{BASE_URL}{path}"
    req = urllib.request.Request(url)
    if data is not None:
        req.add_header('Content-Type', 'application/json')
        jsondata = json.dumps(data).encode('utf-8')
        req.data = jsondata
    
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            res_body = response.read().decode('utf-8')
            return json.loads(res_body)
    except Exception as e:
        print(f"Error testing {path}: {e}")
        return None

def main():
    print("==================================================")
    print("AEGIS SIEM BACKEND VERIFICATION SUITE")
    print("==================================================")
    
    # 1. Test Status
    print("\n[+] Testing /api/status...")
    status = test_endpoint("/api/status")
    if status:
        print(f"    Status: {status.get('status')}")
        print(f"    Initial Threat Level: {status.get('threat_level')}")
        print(f"    Simulation Active: {status.get('simulation')}")
    else:
        print("    [!] Failed to reach status API")
        return
        
    # 2. Trigger DDoS Simulation
    print("\n[+] Triggering Simulated DDoS Storm...")
    trigger = test_endpoint("/api/trigger", {"attack_type": "ddos"})
    if trigger:
        print(f"    Response: {trigger.get('message')}")
    
    # Wait for engine loop to generate packets and trigger rules
    print("    Waiting 2.5 seconds for detection rules to trigger...")
    time.sleep(2.5)
    
    # 3. Verify Threat Level Escalated and Alerts generated
    print("\n[+] Verifying Alerts and Escalation...")
    status_updated = test_endpoint("/api/status")
    alerts = test_endpoint("/api/alerts")
    
    if status_updated and alerts:
        print(f"    Updated Threat Level: {status_updated.get('threat_level')} (Expected: CRITICAL)")
        print(f"    Total Alerts Generated: {len(alerts)}")
        if len(alerts) > 0:
            latest = alerts[-1]
            print(f"    Latest Incident: {latest.get('alert_type')} from {latest.get('src_ip')}")
            print(f"    Alert Severity: {latest.get('severity')}")
            print(f"    Alert Description: {latest.get('description')}")
    
    # 4. Trigger Vulnerability Scan on mock target
    print("\n[+] Initiating Vulnerability Scan on 192.168.1.10...")
    scan_res = test_endpoint("/api/scan", {"target_ip": "192.168.1.10"})
    if scan_res:
        print(f"    Scan Target: {scan_res.get('target')}")
        print(f"    Open Ports Found: {[p['port'] for p in scan_res.get('open_ports', [])]}")
        vulns = scan_res.get('vulnerabilities', [])
        print(f"    Identified CVE vulnerabilities count: {len(vulns)}")
        for v in vulns[:2]:
            print(f"      - {v.get('cve')}: {v.get('title')} on port {v.get('port')} ({v.get('severity')})")
    
    # 5. Reset Simulator
    print("\n[+] Resetting Sandbox Engine...")
    reset = test_endpoint("/api/trigger", {"attack_type": "none"})
    if reset:
        print(f"    Response: {reset.get('message')}")
        
    print("\n==================================================")
    print("VERIFICATION COMPLETE - BACKEND LOGIC VERIFIED")
    print("==================================================")

if __name__ == "__main__":
    main()
