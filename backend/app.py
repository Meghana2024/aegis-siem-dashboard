import time
import json
from flask import Flask, jsonify, request, Response
from flask_cors import CORS
from threat_engine import ThreatEngine
from vuln_scanner import VulnerabilityScanner

app = Flask(__name__)
CORS(app)  # Enable Cross-Origin Resource Sharing for the frontend

# Initialize our cybersecurity engines
threat_engine = ThreatEngine()
threat_engine.start_simulation()
vuln_scanner = VulnerabilityScanner()

# Keep track of count of processed packets
total_packets_processed = 0

@app.route('/api/status', methods=['GET'])
def get_status():
    global total_packets_processed
    with threat_engine.lock:
        packets_len = len(threat_engine.packets)
        alerts_len = len(threat_engine.alerts)
        rules = threat_engine.rules.copy()
        active_attack = threat_engine.active_attack_type
    
    # Calculate overall threat status
    threat_level = "LOW"
    critical_alerts = sum(1 for a in threat_engine.alerts if a["severity"] == "Critical")
    high_alerts = sum(1 for a in threat_engine.alerts if a["severity"] == "High")
    
    if critical_alerts > 0 or active_attack == "ddos":
        threat_level = "CRITICAL"
    elif high_alerts > 2 or active_attack in ["port_scan", "brute_force"]:
        threat_level = "HIGH"
    elif high_alerts > 0 or len(threat_engine.alerts) > 5:
        threat_level = "MEDIUM"
        
    return jsonify({
        "status": "online",
        "threat_level": threat_level,
        "packets_processed": total_packets_processed + packets_len,
        "alerts_count": alerts_len,
        "rules": rules,
        "active_attack": active_attack,
        "simulation": threat_engine.simulation_active
    })

@app.route('/api/packets', methods=['GET'])
def get_packets():
    with threat_engine.lock:
        pkts = list(threat_engine.packets)
    return jsonify(pkts)

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    with threat_engine.lock:
        alrts = list(threat_engine.alerts)
    return jsonify(alrts)

@app.route('/api/config', methods=['POST'])
def update_config():
    data = request.json
    if not data:
        return jsonify({"error": "No configuration data provided"}), 400
        
    # Update rules dynamically
    if "ddos_threshold" in data:
        threat_engine.rules["ddos_threshold"] = int(data["ddos_threshold"])
    if "port_scan_threshold" in data:
        threat_engine.rules["port_scan_threshold"] = int(data["port_scan_threshold"])
    if "brute_force_threshold" in data:
        threat_engine.rules["brute_force_threshold"] = int(data["brute_force_threshold"])
    if "enabled_signatures" in data:
        for k, v in data["enabled_signatures"].items():
            if k in threat_engine.rules["enabled_signatures"]:
                threat_engine.rules["enabled_signatures"][k] = bool(v)
                
    return jsonify({"status": "success", "rules": threat_engine.rules})

@app.route('/api/trigger', methods=['POST'])
def trigger_attack():
    data = request.json or {}
    attack_type = data.get("attack_type")
    
    valid_attacks = ["ddos", "port_scan", "sqli", "brute_force", "none"]
    if attack_type not in valid_attacks:
        return jsonify({"error": f"Invalid attack type. Choose from {valid_attacks}"}), 400
        
    if attack_type == "none":
        threat_engine.active_attack_type = None
        return jsonify({"status": "success", "message": "Cleared active simulated attack"})
    else:
        threat_engine.trigger_attack(attack_type)
        return jsonify({"status": "success", "message": f"Simulating {attack_type} attack pattern..."})

@app.route('/api/scan', methods=['POST'])
def run_scan():
    data = request.json or {}
    target_ip = data.get("target_ip", "127.0.0.1").strip()
    
    if not target_ip:
        return jsonify({"error": "IP address is required"}), 400
        
    # Run scan
    results = vuln_scanner.run_scan(target_ip)
    return jsonify(results)

@app.route('/api/stream')
def sse_stream():
    """Server-Sent Events endpoint to stream live packets and alerts to the UI."""
    def event_generator():
        global total_packets_processed
        last_packet_idx = 0
        last_alert_idx = 0
        
        # Capture current sizes to start differential push
        with threat_engine.lock:
            last_packet_idx = len(threat_engine.packets)
            last_alert_idx = len(threat_engine.alerts)
            
        while True:
            time.sleep(0.3)  # Interval updates
            
            with threat_engine.lock:
                current_packets = list(threat_engine.packets)
                current_alerts = list(threat_engine.alerts)
            
            new_packets = []
            new_alerts = []
            
            # Since deque size resets/caps, compare indices and gather additions
            # If current queue length is less than our last checked index (wrap around/clears), reset index
            if len(current_packets) < last_packet_idx:
                last_packet_idx = 0
            if len(current_alerts) < last_alert_idx:
                last_alert_idx = 0
                
            if len(current_packets) > last_packet_idx:
                new_packets = current_packets[last_packet_idx:]
                last_packet_idx = len(current_packets)
                total_packets_processed += len(new_packets)
                
            if len(current_alerts) > last_alert_idx:
                new_alerts = current_alerts[last_alert_idx:]
                last_alert_idx = len(current_alerts)
                
            if new_packets or new_alerts:
                payload = {
                    "packets": new_packets,
                    "alerts": new_alerts,
                    "threat_level": get_threat_level_val()
                }
                yield f"data: {json.dumps(payload)}\n\n"
                
    return Response(event_generator(), mimetype="text/event-stream")

def get_threat_level_val():
    threat_level = "LOW"
    critical_alerts = sum(1 for a in threat_engine.alerts if a["severity"] == "Critical")
    high_alerts = sum(1 for a in threat_engine.alerts if a["severity"] == "High")
    active_attack = threat_engine.active_attack_type
    
    if critical_alerts > 0 or active_attack == "ddos":
        threat_level = "CRITICAL"
    elif high_alerts > 2 or active_attack in ["port_scan", "brute_force"]:
        threat_level = "HIGH"
    elif high_alerts > 0 or len(threat_engine.alerts) > 5:
        threat_level = "MEDIUM"
    return threat_level

if __name__ == '__main__':
    print("--------------------------------------------------")
    print("Aegis Guardian SIEM Engine Dashboard - Online")
    print("API listening on http://127.0.0.1:5000")
    print("--------------------------------------------------")
    app.run(host='127.0.0.1', port=5000, debug=False)
