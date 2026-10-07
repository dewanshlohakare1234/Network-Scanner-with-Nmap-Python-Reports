"""
scanner.py — Pure Python Network Scanner (No External Dependencies!)
====================================================================
This module performs network scanning using ONLY Python's standard library:
  • socket        → TCP connections, DNS lookups, banner grabbing
  • concurrent.futures → Multi-threaded scanning for speed
  • struct        → Packing/unpacking binary data
  • ssl           → Detecting HTTPS/TLS services

NO nmap, NO pip install — just Python.

How TCP scanning works:
  1. We try to open a TCP connection (3-way handshake: SYN → SYN-ACK → ACK)
  2. If the connection succeeds → port is OPEN
  3. If it's refused            → port is CLOSED
  4. If it times out            → port is FILTERED (firewall blocking)
"""

import socket
import ssl
import struct
import datetime
import concurrent.futures
from typing import Optional


# ==========================================================================
# Well-known port → service name mapping (built-in, no file needed)
# ==========================================================================
COMMON_PORTS = {
    20: "ftp-data",    21: "ftp",         22: "ssh",         23: "telnet",
    25: "smtp",        43: "whois",       53: "dns",         67: "dhcp",
    68: "dhcp-client", 69: "tftp",        80: "http",        81: "http-alt",
    88: "kerberos",    110: "pop3",       111: "rpcbind",    119: "nntp",
    123: "ntp",        135: "msrpc",      137: "netbios-ns", 138: "netbios-dgm",
    139: "netbios-ssn",143: "imap",       161: "snmp",       162: "snmp-trap",
    179: "bgp",        194: "irc",        389: "ldap",       443: "https",
    445: "microsoft-ds",464: "kpasswd",   465: "smtps",      514: "syslog",
    515: "printer",    520: "rip",        521: "ripng",      543: "klogin",
    544: "kshell",     548: "afp",        554: "rtsp",       587: "submission",
    593: "http-rpc",   631: "ipp",        636: "ldaps",      873: "rsync",
    902: "vmware",     989: "ftps-data",  990: "ftps",       993: "imaps",
    995: "pop3s",      1080: "socks",     1194: "openvpn",   1433: "mssql",
    1434: "mssql-udp", 1521: "oracle",    1723: "pptp",      1883: "mqtt",
    2049: "nfs",       2082: "cpanel",    2083: "cpanel-ssl", 2086: "whm",
    2087: "whm-ssl",   2181: "zookeeper", 3000: "grafana",   3306: "mysql",
    3389: "rdp",       3690: "svn",       4443: "https-alt", 5000: "upnp",
    5432: "postgresql", 5672: "amqp",     5900: "vnc",       5901: "vnc-1",
    6379: "redis",     6443: "kubernetes",7001: "weblogic",  8000: "http-alt",
    8008: "http-alt",  8080: "http-proxy",8081: "http-proxy",8443: "https-alt",
    8888: "http-alt",  9000: "cslistener",9090: "prometheus", 9200: "elasticsearch",
    9300: "elasticsearch", 9418: "git",   10000: "webmin",   11211: "memcached",
    27017: "mongodb",  27018: "mongodb",  28017: "mongodb-web",
}

# The "Top 100" most commonly open ports (same set Nmap uses for -F)
TOP_100_PORTS = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111,
    113, 119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465,
    513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995,
    1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900,
    2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899,
    5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800,
    5900, 6000, 6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443,
    8888, 9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156,
]

# Top 1000 ports (trimmed to most useful — covers 99% of real services)
TOP_1000_PORTS = sorted(set(
    TOP_100_PORTS + list(COMMON_PORTS.keys()) + list(range(1, 1025)) +
    [1080, 1194, 1883, 2082, 2083, 2086, 2087, 2181, 3690, 4443,
     5432, 5672, 5901, 6379, 6443, 7001, 8888, 9000, 9090, 9200,
     9300, 9418, 10000, 11211, 27017, 27018, 28017]
))


class NetworkScanner:
    """
    A pure-Python network scanner — no external tools required.

    It uses TCP connect() scanning, which works without admin/root
    privileges on any operating system.

    Usage:
        scanner = NetworkScanner()
        results = scanner.quick_scan("scanme.nmap.org")
        results = scanner.deep_scan("example.com")
    """

    def __init__(self, timeout: float = 1.5, max_threads: int = 200):
        """
        Parameters:
            timeout     : Seconds to wait for each port connection (lower = faster but may miss)
            max_threads : How many ports to scan simultaneously (higher = faster)
        """
        self.timeout = timeout
        self.max_threads = max_threads

    # ==================================================================
    # PUBLIC SCAN METHODS
    # ==================================================================

    def quick_scan(self, target: str) -> dict:
        """
        Quick Scan — Top 100 most common ports.
        Fast reconnaissance to see what's running.
        """
        print(f"\n[*] Starting QUICK SCAN on {target} ...")
        print(f"    Scanning top {len(TOP_100_PORTS)} ports with {self.max_threads} threads")
        return self._run_scan(target, TOP_100_PORTS, scan_type="Quick Scan (Top 100 Ports)")

    def standard_scan(self, target: str) -> dict:
        """
        Standard Scan — Top 1000 ports + service detection.
        Covers virtually all common services.
        """
        print(f"\n[*] Starting STANDARD SCAN on {target} ...")
        print(f"    Scanning {len(TOP_1000_PORTS)} ports with {self.max_threads} threads")
        return self._run_scan(target, TOP_1000_PORTS, scan_type="Standard Scan (Top 1000 Ports)")

    def deep_scan(self, target: str) -> dict:
        """
        Deep Scan — ALL 65,535 TCP ports.
        Very thorough but takes several minutes.
        """
        all_ports = list(range(1, 65536))
        print(f"\n[*] Starting DEEP SCAN on {target} ...")
        print(f"    Scanning ALL 65,535 ports with {self.max_threads} threads")
        print(f"    ⏳ This will take a few minutes...")
        return self._run_scan(target, all_ports, scan_type="Deep Scan (All 65535 Ports)")

    def custom_scan(self, target: str, ports: list) -> dict:
        """
        Custom Scan — User provides a specific list of ports.
        """
        print(f"\n[*] Starting CUSTOM SCAN on {target} ...")
        print(f"    Scanning {len(ports)} specified ports")
        return self._run_scan(target, ports, scan_type=f"Custom Scan ({len(ports)} ports)")

    # ==================================================================
    # CORE SCANNING ENGINE
    # ==================================================================

    def _run_scan(self, target: str, ports: list, scan_type: str) -> dict:
        """
        The main scanning engine:
          1. Resolve the target hostname to an IP address
          2. Scan all requested ports using a thread pool
          3. Grab banners from open ports to identify services
          4. Package everything into a clean results dictionary
        """
        start_time = datetime.datetime.now()

        # ── Step 1: DNS Resolution ──
        ip_address = self._resolve_host(target)
        if not ip_address:
            return self._empty_result(target, scan_type, "DNS resolution failed")

        hostname = self._reverse_dns(ip_address)
        print(f"    Target IP : {ip_address}")
        if hostname:
            print(f"    Hostname  : {hostname}")

        # ── Step 2: Scan ports in parallel using threads ──
        open_ports = []
        scanned = 0
        total = len(ports)

        # ThreadPoolExecutor creates a pool of worker threads.
        # Each thread tries to connect to one port simultaneously.
        # This makes scanning MUCH faster than checking one port at a time.
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            # Submit all port-check tasks at once
            future_to_port = {
                executor.submit(self._check_port, ip_address, port): port
                for port in ports
            }

            # Collect results as they complete
            for future in concurrent.futures.as_completed(future_to_port):
                scanned += 1
                port = future_to_port[future]

                # Print a progress indicator every 500 ports
                if scanned % 500 == 0 or scanned == total:
                    pct = (scanned / total) * 100
                    print(f"    Progress: {scanned}/{total} ports ({pct:.0f}%)", end="\r")

                result = future.result()
                if result:  # result is not None → port is open
                    open_ports.append(result)

        print(f"    Progress: {total}/{total} ports (100%)   ")

        # ── Step 3: Banner grabbing on open ports ──
        if open_ports:
            print(f"\n[*] Found {len(open_ports)} open port(s). Grabbing banners...")
            with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
                futures = {
                    executor.submit(self._grab_banner, ip_address, p["port"]): p
                    for p in open_ports
                }
                for future in concurrent.futures.as_completed(futures):
                    port_info = futures[future]
                    banner = future.result()
                    if banner:
                        port_info["banner"] = banner
                        # Try to detect product/version from banner text
                        product, version = self._parse_banner(banner)
                        if product:
                            port_info["product"] = product
                        if version:
                            port_info["version"] = version

        # ── Step 4: Check for TLS/SSL on common HTTPS ports ──
        for p in open_ports:
            if p["port"] in (443, 8443, 4443, 2083, 2087, 993, 995, 465, 990, 636):
                cert_info = self._get_ssl_info(ip_address, p["port"])
                if cert_info:
                    p["ssl_info"] = cert_info

        elapsed = (datetime.datetime.now() - start_time).total_seconds()

        # ── Step 5: Build the final results dictionary ──
        results = {
            "scan_type": scan_type,
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "elapsed": f"{elapsed:.2f}",
            "target_input": target,
            "hosts": [
                {
                    "ip": ip_address,
                    "hostname": hostname or "",
                    "state": "up" if open_ports or self._is_host_up(ip_address) else "unknown",
                    "ports": sorted(open_ports, key=lambda x: x["port"]),
                }
            ],
            "total_ports_scanned": total,
            "open_port_count": len(open_ports),
        }

        print(f"\n[✓] Scan complete in {elapsed:.2f} seconds")
        print(f"    {len(open_ports)} open port(s) found on {ip_address}")

        return results

    # ==================================================================
    # LOW-LEVEL HELPERS
    # ==================================================================

    def _check_port(self, ip: str, port: int) -> Optional[dict]:
        """
        Try to connect to ip:port via TCP.

        How TCP Connect Scanning Works:
        ┌────────┐  SYN         ┌────────┐
        │ Scanner │ ──────────► │ Target │
        │        │  SYN-ACK     │        │  ← Port is OPEN
        │        │ ◄────────── │        │
        │        │  ACK         │        │
        │        │ ──────────► │        │
        └────────┘              └────────┘

        If the target responds with RST → port is CLOSED.
        If no response (timeout)       → port is FILTERED.

        Returns:
            dict with port info if OPEN, None otherwise.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            # connect_ex returns 0 on success, error code otherwise
            result = sock.connect_ex((ip, port))
            if result == 0:
                # Port is OPEN! Build an info dict.
                return {
                    "port": port,
                    "protocol": "tcp",
                    "state": "open",
                    "service": COMMON_PORTS.get(port, "unknown"),
                    "banner": "",
                    "product": "",
                    "version": "",
                }
            return None  # Port is closed or filtered
        except (socket.timeout, socket.error, OSError):
            return None
        finally:
            sock.close()

    def _grab_banner(self, ip: str, port: int) -> str:
        """
        Banner Grabbing — connect to an open port and read what it says.

        Many services send a "banner" when you connect, like:
          SSH:   "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"
          HTTP:  "HTTP/1.1 200 OK\r\nServer: Apache/2.4.52"
          FTP:   "220 ProFTPD 1.3.5e Server"
          SMTP:  "220 mail.example.com ESMTP Postfix"

        For HTTP-like services we send a simple GET request to trigger
        a response, since HTTP servers don't send anything until asked.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((ip, port))

            # HTTP-based services need us to send a request first
            if port in (80, 443, 8080, 8081, 8000, 8008, 8443, 8888, 3000,
                        5000, 9090, 9200, 4443, 81, 2082, 2083, 10000):
                request = (
                    f"HEAD / HTTP/1.1\r\n"
                    f"Host: {ip}\r\n"
                    f"User-Agent: PythonNetScanner/1.0\r\n"
                    f"Connection: close\r\n\r\n"
                )
                sock.send(request.encode())

            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            sock.close()
            return banner
        except Exception:
            return ""

    def _get_ssl_info(self, ip: str, port: int) -> Optional[dict]:
        """
        Connect with TLS/SSL and read the server's certificate.
        This reveals the domain name, issuer (e.g., Let's Encrypt),
        and expiry date — useful security intelligence.
        """
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip, port), timeout=3) as raw_sock:
                with context.wrap_socket(raw_sock, server_hostname=ip) as tls_sock:
                    cert = tls_sock.getpeercert(binary_form=False)
                    if cert:
                        return {
                            "subject": str(cert.get("subject", "")),
                            "issuer": str(cert.get("issuer", "")),
                            "expires": cert.get("notAfter", ""),
                            "version": tls_sock.version(),
                        }
        except Exception:
            pass
        return None

    @staticmethod
    def _resolve_host(target: str) -> Optional[str]:
        """Convert a hostname to an IP address using DNS."""
        try:
            ip = socket.gethostbyname(target)
            return ip
        except socket.gaierror:
            print(f"    [!] ERROR: Cannot resolve '{target}'. Check the hostname.")
            return None

    @staticmethod
    def _reverse_dns(ip: str) -> str:
        """Try to find the hostname for an IP (reverse DNS lookup)."""
        try:
            return socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror):
            return ""

    @staticmethod
    def _is_host_up(ip: str) -> bool:
        """Quick check — try to connect to a common port to verify the host is alive."""
        for port in (80, 443, 22, 21):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                result = s.connect_ex((ip, port))
                s.close()
                if result == 0:
                    return True
            except Exception:
                pass
        return False

    @staticmethod
    def _parse_banner(banner: str) -> tuple:
        """
        Try to extract product name and version from a banner string.

        Examples:
          "SSH-2.0-OpenSSH_8.9p1"         → ("OpenSSH", "8.9p1")
          "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0" → ("nginx", "1.18.0")
          "220 ProFTPD 1.3.5e Server"      → ("ProFTPD", "1.3.5e")
        """
        import re
        product = ""
        version = ""

        # SSH banner
        ssh_match = re.search(r'SSH-[\d.]+-(\S+)', banner)
        if ssh_match:
            parts = ssh_match.group(1).replace("_", " ").split()
            product = parts[0] if parts else ""
            version = parts[1] if len(parts) > 1 else ""
            return product, version

        # HTTP Server header
        server_match = re.search(r'Server:\s*(\S+)', banner, re.IGNORECASE)
        if server_match:
            sv = server_match.group(1)
            if "/" in sv:
                product, version = sv.split("/", 1)
            else:
                product = sv
            return product, version

        # FTP / SMTP banner  (e.g. "220 ProFTPD 1.3.5e Server")
        ftp_match = re.search(r'^\d{3}[\s-]+(\S+)\s+([\d.]+\S*)', banner)
        if ftp_match:
            product = ftp_match.group(1)
            version = ftp_match.group(2)
            return product, version

        return product, version


# ======================================================================
# Self-test — run directly to scan a safe target
# ======================================================================
if __name__ == "__main__":
    s = NetworkScanner()
    result = s.quick_scan("scanme.nmap.org")
    import json
    print(json.dumps(result, indent=2))
