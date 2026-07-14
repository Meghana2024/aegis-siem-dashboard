import socket
import threading
import time
import random

# Database of simulated vulnerability details based on banners
VULN_DATABASE = {
    "SSH-2.0-OpenSSH_7.2p1": [
        {
            "cve": "CVE-2016-6210",
            "title": "OpenSSH User Enumeration Vulnerability",
            "cvss": 5.3,
            "severity": "Medium",
            "description": "OpenSSH before 7.3 allows remote attackers to determine valid usernames via timed-response differences in password authentication.",
            "mitigation": "Update OpenSSH to version 7.3 or higher. Disable password authentication and enforce SSH keys."
        },
        {
            "cve": "CVE-2018-15473",
            "title": "OpenSSH Username Enumeration via Public Key",
            "cvss": 5.3,
            "severity": "Medium",
            "description": "OpenSSH through 7.7 contains a username enumeration vulnerability where it premature-fails invalid users under public key authentication.",
            "mitigation": "Apply vendor security patch or upgrade OpenSSH to 7.8+."
        }
    ],
    "vsftpd 2.3.4": [
        {
            "cve": "CVE-2011-2523",
            "title": "vsftpd 2.3.4 Backdoor Command Execution",
            "cvss": 9.8,
            "severity": "Critical",
            "description": "The vsftpd-2.3.4 source code archive contains a backdoor that opens a listener on port 6200 when a username containing a smiley face :) is supplied.",
            "mitigation": "Remove vsftpd 2.3.4 immediately. Install a clean, patched version or switch to SFTP (SSH File Transfer Protocol)."
        }
    ],
    "Apache/2.4.18": [
        {
            "cve": "CVE-2017-9798",
            "title": "Apache Optionsbleed Vulnerability",
            "cvss": 7.5,
            "severity": "High",
            "description": "Apache HTTP Server allows remote attackers to read secret data from process memory due to a use-after-free bug in the Limit directive (Optionsbleed).",
            "mitigation": "Update Apache HTTP Server to version 2.4.27 or newer."
        }
    ],
    "MySQL 5.5.47": [
        {
            "cve": "CVE-2016-6662",
            "title": "MySQL Remote Privilege Escalation / Code Execution",
            "cvss": 8.8,
            "severity": "High",
            "description": "MySQL allows local/remote attackers to execute arbitrary code with root privileges by modifying my.cnf configuration file.",
            "mitigation": "Restrict write permissions to my.cnf/my.ini configurations. Update MySQL daemon or block port 3306 from WAN."
        }
    ],
    "nginx/1.10.3": [
        {
            "cve": "CVE-2018-16843",
            "title": "nginx HTTP/2 Memory Leak / Denial of Service",
            "cvss": 7.5,
            "severity": "High",
            "description": "A memory leak in nginx HTTP/2 implementation allows an attacker to cause excessive memory consumption, leading to a denial of service.",
            "mitigation": "Update nginx to 1.14.1 or 1.15.6. Alternatively, disable HTTP/2 support in configuration files."
        }
    ],
}

MOCK_HOSTS = {
    "127.0.0.1": [
        {"port": 22, "service": "ssh", "state": "open", "banner": "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"},
        {"port": 80, "state": "closed", "service": "http", "banner": ""},
        {"port": 443, "service": "https", "state": "open", "banner": "nginx/1.18.0"},
        {"port": 3306, "state": "closed", "service": "mysql", "banner": ""}
    ],
    "192.168.1.10": [
        {"port": 21, "service": "ftp", "state": "open", "banner": "vsftpd 2.3.4"},
        {"port": 22, "service": "ssh", "state": "open", "banner": "SSH-2.0-OpenSSH_7.2p1"},
        {"port": 80, "service": "http", "state": "open", "banner": "Apache/2.4.18 (Ubuntu)"},
        {"port": 443, "service": "https", "state": "open", "banner": "nginx/1.10.3"},
        {"port": 3306, "service": "mysql", "state": "open", "banner": "MySQL 5.5.47-0ubuntu0.14.04.1"},
        {"port": 8080, "service": "http-alt", "state": "open", "banner": "Apache Tomcat/8.5.5"}
    ],
    "192.168.1.25": [
        {"port": 22, "service": "ssh", "state": "open", "banner": "SSH-2.0-OpenSSH_8.4p1 Debian-5"},
        {"port": 80, "service": "http", "state": "open", "banner": "nginx/1.20.1"},
        {"port": 443, "service": "https", "state": "open", "banner": "nginx/1.20.1"}
    ]
}

class VulnerabilityScanner:
    def __init__(self):
        self.scanning = False
        self.progress = 0
        self.results = {}

    def scan_port(self, target_ip, port, results_list, timeout=0.8):
        """Attempts to connect to a port and perform basic banner grabbing."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((target_ip, port))
            
            if result == 0:
                service = "unknown"
                try:
                    service = socket.getservbyport(port, "tcp")
                except:
                    pass
                
                # Attempt banner grabbing
                banner = ""
                try:
                    if port == 80 or port == 8080:
                        sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                        response = sock.recv(1024).decode('utf-8', errors='ignore')
                        for line in response.split('\r\n'):
                            if line.lower().startswith("server:"):
                                banner = line.split(":", 1)[1].strip()
                                break
                    else:
                        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                except Exception as e:
                    pass
                
                # Deduce service name if empty
                if not service:
                    if port == 21: service = "ftp"
                    elif port == 22: service = "ssh"
                    elif port == 23: service = "telnet"
                    elif port == 25: service = "smtp"
                    elif port == 80: service = "http"
                    elif port == 443: service = "https"
                    elif port == 3306: service = "mysql"
                    
                results_list.append({
                    "port": port,
                    "state": "open",
                    "service": service,
                    "banner": banner
                })
            else:
                # Port is closed
                pass
        except Exception as e:
            pass
        finally:
            sock.close()

    def run_scan(self, target_ip, port_list=[21, 22, 23, 25, 53, 80, 110, 443, 1433, 3306, 8080]):
        self.scanning = True
        self.progress = 0
        self.results = {
            "target": target_ip,
            "status": "completed",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "open_ports": [],
            "vulnerabilities": [],
            "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0}
        }
        
        # Check if the IP is in our simulated environment (mock hosts) for quick demonstration
        if target_ip in MOCK_HOSTS:
            time.sleep(2)  # Simulate scanning delay
            mock_ports = MOCK_HOSTS[target_ip]
            
            for item in mock_ports:
                if item["state"] == "open":
                    self.results["open_ports"].append(item)
                    # Lookup vulnerabilities based on mock banner
                    banner = item["banner"]
                    vulns_found = False
                    for key, vulns in VULN_DATABASE.items():
                        if key in banner:
                            vulns_found = True
                            for v in vulns:
                                vuln_entry = {
                                    "port": item["port"],
                                    "service": item["service"],
                                    "cve": v["cve"],
                                    "title": v["title"],
                                    "cvss": v["cvss"],
                                    "severity": v["severity"],
                                    "description": v["description"],
                                    "mitigation": v["mitigation"]
                                }
                                self.results["vulnerabilities"].append(vuln_entry)
                                self.results["summary"][v["severity"].lower()] += 1
                                
            self.progress = 100
            self.scanning = False
            return self.results

        # Real scan logic (concurrency with threads)
        open_ports_raw = []
        threads = []
        
        # Split ports into threads
        for port in port_list:
            t = threading.Thread(target=self.scan_port, args=(target_ip, port, open_ports_raw))
            threads.append(t)
            t.start()
            
        total_threads = len(threads)
        completed_threads = 0
        
        # Monitor thread execution and update progress
        for t in threads:
            t.join()
            completed_threads += 1
            self.progress = int((completed_threads / total_threads) * 100)

        # Process results
        for item in open_ports_raw:
            self.results["open_ports"].append(item)
            banner = item["banner"]
            
            # Map banner or service type to vulnerability DB
            vuln_found = False
            for key, vulns in VULN_DATABASE.items():
                if key.lower() in banner.lower() or (key.split('/')[0].lower() in banner.lower() if '/' in key else False):
                    vuln_found = True
                    for v in vulns:
                        vuln_entry = {
                            "port": item["port"],
                            "service": item["service"],
                            "cve": v["cve"],
                            "title": v["title"],
                            "cvss": v["cvss"],
                            "severity": v["severity"],
                            "description": v["description"],
                            "mitigation": v["mitigation"]
                        }
                        self.results["vulnerabilities"].append(vuln_entry)
                        self.results["summary"][v["severity"].lower()] += 1
            
            # Fallback signature checks
            if not vuln_found:
                # Add default low warning if port is open but no specific CVE matches
                if item["port"] in [21, 23]: # FTP, Telnet are unencrypted
                    severity = "High"
                    cve = "PLAINTEXT-PROTO"
                    title = f"Unencrypted Protocol ({item['service'].upper()})"
                    cvss = 7.5
                    description = f"The service {item['service']} transfers credentials and data in cleartext, exposing the host to credential sniffing."
                    mitigation = f"Disable {item['service']} and migrate to an encrypted equivalent (SSH or SFTP)."
                    
                    self.results["vulnerabilities"].append({
                        "port": item["port"],
                        "service": item["service"],
                        "cve": cve,
                        "title": title,
                        "cvss": cvss,
                        "severity": severity,
                        "description": description,
                        "mitigation": mitigation
                    })
                    self.results["summary"][severity.lower()] += 1

        self.scanning = False
        return self.results
