import time
import random
import re
import threading
from collections import deque

class ThreatEngine:
    def __init__(self):
        # Configuration & Rules
        self.rules = {
            "ddos_threshold": 30,       # Packets per 5 seconds from same IP
            "port_scan_threshold": 10,  # Distinct ports in 5 seconds from same IP
            "brute_force_threshold": 5, # Port 22/21 connections in 5 seconds
            "enabled_signatures": {
                "sqli": True,
                "xss": True,
                "path_traversal": True,
                "malicious_dns": True
            }
        }
        
        # State tracking (IP -> list of timestamps)
        self.ip_traffic_history = {}
        # State tracking (IP -> set of destination ports scanned)
        self.port_scan_history = {}
        # State tracking (IP -> list of SSH/FTP connection timestamps)
        self.brute_force_history = {}
        
        # Threat Signatures
        self.signatures = {
            "sqli": [
                re.compile(r"UNION\s+SELECT", re.IGNORECASE),
                re.compile(r"'\s*OR\s*'\d+'\s*=\s*'\d+", re.IGNORECASE),
                re.compile(r"admin'\s*--", re.IGNORECASE),
                re.compile(r"UNION\s+ALL\s+SELECT", re.IGNORECASE)
            ],
            "xss": [
                re.compile(r"<script.*?>", re.IGNORECASE),
                re.compile(r"javascript\s*:", re.IGNORECASE),
                re.compile(r"onerror\s*=", re.IGNORECASE),
                re.compile(r"onload\s*=", re.IGNORECASE)
            ],
            "path_traversal": [
                re.compile(r"\.\./\.\./", re.IGNORECASE),
                re.compile(r"/etc/passwd", re.IGNORECASE),
                re.compile(r"boot\.ini", re.IGNORECASE)
            ],
            "malicious_dns": [
                re.compile(r"malware-cnc\.com", re.IGNORECASE),
                re.compile(r"botnet-controller\.org", re.IGNORECASE),
                re.compile(r"exfiltrate-data\.", re.IGNORECASE)
            ]
        }
        
        # Ring buffers for UI data stream (Thread-safe lock)
        self.lock = threading.Lock()
        self.packets = deque(maxlen=200)
        self.alerts = deque(maxlen=100)
        
        # Simulation control
        self.simulation_active = True
        self.active_attack_type = None  # None, "ddos", "port_scan", "sqli", "brute_force"
        self.attack_source_ip = "192.168.1.150"
        self.simulator_thread = None
        
        # Geolocation simulator mapping for IP display
        self.geo_db = {
            "192.168.1.": ("Local Network", 0, 0),
            "10.0.": ("Local Network", 0, 0),
            "185.220.101.": ("Tor Exit Node (Germany)", 52.5200, 13.4050),
            "45.227.254.": ("Known Attacker IP (Russia)", 55.7558, 37.6173),
            "103.88.22.": ("China Unicom (China)", 39.9042, 116.4074),
            "8.8.8.8": ("Google DNS (USA)", 37.751, -97.822),
            "1.1.1.1": ("Cloudflare (USA)", 37.751, -97.822),
            "203.0.113.5": ("Simulated Host (India)", 20.5937, 78.9629),
        }
        
    def start_simulation(self):
        self.simulation_active = True
        self.simulator_thread = threading.Thread(target=self._run_simulator, daemon=True)
        self.simulator_thread.start()
        
    def stop_simulation(self):
        self.simulation_active = False

    def get_geo_info(self, ip):
        for subnet, info in self.geo_db.items():
            if ip.startswith(subnet):
                return info
        # Default random global geo info for realism
        random.seed(ip)
        lat = random.uniform(-60.0, 70.0)
        lon = random.uniform(-120.0, 140.0)
        return ("External IP", lat, lon)

    def trigger_attack(self, attack_type):
        self.active_attack_type = attack_type
        if attack_type == "ddos":
            self.attack_source_ip = random.choice(["45.227.254.12", "103.88.22.89"])
        elif attack_type == "port_scan":
            self.attack_source_ip = random.choice(["185.220.101.44", "192.168.1.201"])
        elif attack_type == "brute_force":
            self.attack_source_ip = "185.220.101.67"
        elif attack_type == "sqli":
            self.attack_source_ip = "45.227.254.91"
        else:
            self.active_attack_type = None

    def log_packet(self, packet):
        with self.lock:
            self.packets.append(packet)
        self.analyze_packet(packet)

    def log_alert(self, alert_type, severity, description, src_ip, dst_ip, src_port, dst_port, protocol, details=None):
        geo_name, lat, lon = self.get_geo_info(src_ip)
        alert = {
            "id": int(time.time() * 1000) + random.randint(0, 999),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "alert_type": alert_type,
            "severity": severity,  # Low, Medium, High, Critical
            "description": description,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "location": geo_name,
            "latitude": lat,
            "longitude": lon,
            "details": details or {}
        }
        with self.lock:
            # Avoid duplicate warnings for the same IP within a 2 second window
            already_exists = False
            for existing in reversed(self.alerts):
                if (existing["alert_type"] == alert_type and 
                    existing["src_ip"] == src_ip and 
                    (time.time() * 1000 - existing["id"]) < 2000):
                    already_exists = True
                    break
            if not already_exists:
                self.alerts.append(alert)
        return alert

    def analyze_packet(self, pkt):
        src_ip = pkt["src_ip"]
        dst_ip = pkt["dst_ip"]
        src_port = pkt["src_port"]
        dst_port = pkt["dst_port"]
        proto = pkt["protocol"]
        payload = pkt.get("payload", "")
        now = time.time()
        
        # 1. DDoS/Traffic Spike Analysis
        if src_ip not in self.ip_traffic_history:
            self.ip_traffic_history[src_ip] = []
        self.ip_traffic_history[src_ip].append(now)
        # Clean history older than 5 seconds
        self.ip_traffic_history[src_ip] = [t for t in self.ip_traffic_history[src_ip] if now - t <= 5]
        
        if len(self.ip_traffic_history[src_ip]) > self.rules["ddos_threshold"]:
            self.log_alert(
                alert_type="DDoS Attack",
                severity="Critical",
                description=f"Traffic threshold exceeded: {len(self.ip_traffic_history[src_ip])} packets/5s from {src_ip}",
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=proto,
                details={"packet_count": len(self.ip_traffic_history[src_ip]), "threshold": self.rules["ddos_threshold"]}
            )

        # 2. Port Scanning Detection
        if src_ip not in self.port_scan_history:
            self.port_scan_history[src_ip] = {}
        # Store port and time
        self.port_scan_history[src_ip][dst_port] = now
        # Clean ports not scanned in the last 5 seconds
        self.port_scan_history[src_ip] = {p: t for p, t in self.port_scan_history[src_ip].items() if now - t <= 5}
        
        if len(self.port_scan_history[src_ip]) > self.rules["port_scan_threshold"]:
            self.log_alert(
                alert_type="Port Scan Detected",
                severity="High",
                description=f"IP {src_ip} scanned {len(self.port_scan_history[src_ip])} distinct ports within 5s",
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=proto,
                details={"scanned_ports": list(self.port_scan_history[src_ip].keys())}
            )

        # 3. Brute Force Detection
        if dst_port in [21, 22]:
            if src_ip not in self.brute_force_history:
                self.brute_force_history[src_ip] = []
            self.brute_force_history[src_ip].append(now)
            self.brute_force_history[src_ip] = [t for t in self.brute_force_history[src_ip] if now - t <= 5]
            
            if len(self.brute_force_history[src_ip]) > self.rules["brute_force_threshold"]:
                service = "SSH" if dst_port == 22 else "FTP"
                self.log_alert(
                    alert_type="Brute Force Attempt",
                    severity="High",
                    description=f"Multiple failed logins detected on {service} (port {dst_port}) from {src_ip}",
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=proto,
                    details={"attempts": len(self.brute_force_history[src_ip]), "service": service}
                )

        # 4. Signature Scans (Payload Inspections)
        if payload:
            # SQLi Check
            if self.rules["enabled_signatures"]["sqli"]:
                for sig in self.signatures["sqli"]:
                    if sig.search(payload):
                        self.log_alert(
                            alert_type="SQL Injection (SQLi)",
                            severity="Critical",
                            description=f"SQL injection signature matched in request payload to port {dst_port}",
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            src_port=src_port,
                            dst_port=dst_port,
                            protocol=proto,
                            details={"matching_payload": payload[:100]}
                        )
                        break

            # XSS Check
            if self.rules["enabled_signatures"]["xss"]:
                for sig in self.signatures["xss"]:
                    if sig.search(payload):
                        self.log_alert(
                            alert_type="Cross-Site Scripting (XSS)",
                            severity="Medium",
                            description=f"Cross-Site Scripting signature matched in request payload",
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            src_port=src_port,
                            dst_port=dst_port,
                            protocol=proto,
                            details={"matching_payload": payload[:100]}
                        )
                        break

            # Path Traversal Check
            if self.rules["enabled_signatures"]["path_traversal"]:
                for sig in self.signatures["path_traversal"]:
                    if sig.search(payload):
                        self.log_alert(
                            alert_type="Directory Traversal",
                            severity="High",
                            description=f"Attempted directory traversal signature detected: {sig.pattern}",
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            src_port=src_port,
                            dst_port=dst_port,
                            protocol=proto,
                            details={"matching_payload": payload[:100]}
                        )
                        break

            # Malicious DNS Check
            if dst_port == 53 and self.rules["enabled_signatures"]["malicious_dns"]:
                for sig in self.signatures["malicious_dns"]:
                    if sig.search(payload):
                        self.log_alert(
                            alert_type="Malicious DNS Query",
                            severity="High",
                            description=f"DNS query resolved to a known malicious command & control (CnC) host: {payload}",
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            src_port=src_port,
                            dst_port=dst_port,
                            protocol=proto,
                            details={"malicious_domain": payload}
                        )
                        break

    def _run_simulator(self):
        """Generates realistic background network activity intermingled with simulated attacks."""
        local_ips = ["192.168.1.10", "192.168.1.11", "192.168.1.25", "192.168.1.102"]
        ext_ips = ["8.8.8.8", "1.1.1.1", "104.244.42.1", "157.240.229.35", "172.217.16.142"]
        protocols = ["TCP", "UDP", "ICMP"]
        
        while self.simulation_active:
            # Check if there is an active attack triggered
            if self.active_attack_type:
                attack = self.active_attack_type
                src = self.attack_source_ip
                dst = "192.168.1.10" # Target local server
                
                if attack == "ddos":
                    # Mass traffic storm
                    for _ in range(15):
                        pkt = {
                            "timestamp": time.time(),
                            "src_ip": src,
                            "dst_ip": dst,
                            "src_port": random.randint(49152, 65535),
                            "dst_port": 80,
                            "protocol": "TCP",
                            "length": random.randint(64, 1500),
                            "payload": "GET / HTTP/1.1\r\nHost: aegis-portal\r\n\r\n",
                            "flags": "SYN"
                        }
                        self.log_packet(pkt)
                        time.sleep(0.02)
                    time.sleep(0.1) # Cool down slightly during ddos loop
                    
                elif attack == "port_scan":
                    # Sequentially scan distinct ports
                    for port in range(1, 150, 5):
                        pkt = {
                            "timestamp": time.time(),
                            "src_ip": src,
                            "dst_ip": dst,
                            "src_port": random.randint(49152, 65535),
                            "dst_port": port,
                            "protocol": "TCP",
                            "length": 40,
                            "payload": "",
                            "flags": "SYN"
                        }
                        self.log_packet(pkt)
                        time.sleep(0.04)
                    # Clear attack status after a single port scan sweep
                    self.active_attack_type = None
                    
                elif attack == "brute_force":
                    # SSH logins
                    pkt = {
                        "timestamp": time.time(),
                        "src_ip": src,
                        "dst_ip": dst,
                        "src_port": random.randint(49152, 65535),
                        "dst_port": 22,
                        "protocol": "TCP",
                        "length": 128,
                        "payload": "SSH-2.0-OpenSSH_8.2p1 failed login",
                        "flags": "PA"
                    }
                    self.log_packet(pkt)
                    time.sleep(0.4)
                    
                elif attack == "sqli":
                    # SQL Injection Payload
                    payloads = [
                        "SELECT * FROM users WHERE username = 'admin' OR '1'='1' --",
                        "GET /search?q=UNION+SELECT+null,username,password+FROM+users HTTP/1.1",
                        "POST /login.php username=admin' OR 1=1; --"
                    ]
                    pkt = {
                        "timestamp": time.time(),
                        "src_ip": src,
                        "dst_ip": dst,
                        "src_port": random.randint(1024, 65535),
                        "dst_port": 8080,
                        "protocol": "TCP",
                        "length": 250,
                        "payload": random.choice(payloads),
                        "flags": "PA"
                    }
                    self.log_packet(pkt)
                    self.active_attack_type = None  # One-shot trigger
                    time.sleep(0.5)
            else:
                # Regular background noise
                src = random.choice(local_ips)
                dst = random.choice(ext_ips)
                dst_port = random.choice([80, 443, 53, 123])
                proto = "UDP" if dst_port in [53, 123] else "TCP"
                
                payload = ""
                if dst_port == 53:
                    domain = random.choice(["google.com", "github.com", "microsoft.com", "reddit.com", "amazon.in"])
                    payload = f"DNS Query: {domain}"
                elif dst_port == 443:
                    payload = "TLS Session Handshake ClientHello"
                elif dst_port == 80:
                    payload = "GET /index.html HTTP/1.1"
                
                pkt = {
                    "timestamp": time.time(),
                    "src_ip": src,
                    "dst_ip": dst,
                    "src_port": random.randint(49152, 65535),
                    "dst_port": dst_port,
                    "protocol": proto,
                    "length": random.randint(40, 1400),
                    "payload": payload,
                    "flags": "FA" if random.random() > 0.8 else "PA"
                }
                self.log_packet(pkt)
                
                # Inbound traffic simulation
                if random.random() > 0.6:
                    pkt_in = {
                        "timestamp": time.time(),
                        "src_ip": dst,
                        "dst_ip": src,
                        "src_port": dst_port,
                        "dst_port": pkt["src_port"],
                        "protocol": proto,
                        "length": random.randint(60, 1500),
                        "payload": "HTTP/1.1 200 OK" if dst_port == 80 else "Data Response",
                        "flags": "A"
                    }
                    self.log_packet(pkt_in)
                
                # Pause between regular packets
                time.sleep(random.uniform(0.3, 1.2))
