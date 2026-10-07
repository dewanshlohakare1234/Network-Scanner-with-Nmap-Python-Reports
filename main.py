"""
main.py — Entry Point for the Pure Python Network Scanner
==========================================================
This is the ONLY file you need to run.  It shows an interactive menu,
takes your target, runs the scan, and generates reports.

Requirements:
  ✅ Python 3.6+   (that's it — no pip install, no nmap, nothing else!)

Usage:
  python main.py

Safe target for practice:
  scanme.nmap.org  (the Nmap project allows scanning this server)

⚠️ LEGAL WARNING:
  Only scan networks/systems you OWN or have WRITTEN permission to test.
  Unauthorized scanning is illegal in most jurisdictions.
"""

import sys
import os
import webbrowser   # Built-in: opens URLs in the default browser

# Import our own modules
from scanner import NetworkScanner
from reporter import print_report, generate_html_report


# ── ANSI Colour Codes ──
CYAN   = "\033[96m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"


def display_banner():
    """Print a cool ASCII banner when the tool starts."""
    banner = f"""
{CYAN}{BOLD}
  ╔═══════════════════════════════════════════════════════════╗
  ║                                                           ║
  ║     ██████╗ ██╗   ██╗    ███████╗ ██████╗ █████╗ ███╗   ██║
  ║     ██╔══██╗╚██╗ ██╔╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║
  ║     ██████╔╝ ╚████╔╝     ███████╗██║     ███████║██╔██╗ ██║
  ║     ██╔═══╝   ╚██╔╝      ╚════██║██║     ██╔══██║██║╚██╗██║
  ║     ██║        ██║       ███████║╚██████╗██║  ██║██║ ╚████║
  ║     ╚═╝        ╚═╝       ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══║
  ║                                                           ║
  ║  🛡️  Pure Python Network Scanner                          ║
  ║  📋  Zero Dependencies — Just Python!                     ║
  ║  🌐  Scans Websites & Servers + Generates HTML Reports    ║
  ╚═══════════════════════════════════════════════════════════╝
{RESET}"""
    print(banner)


def display_menu():
    """Show the interactive scan menu."""
    print(f"""
{BOLD}  ┌─────────────────────────────────────────────┐
  │         SELECT A SCAN TYPE                  │
  └─────────────────────────────────────────────┘{RESET}
  {GREEN}[1]{RESET} Quick Scan        — Top 100 ports (fast, ~10 sec)
  {GREEN}[2]{RESET} Standard Scan     — Top 1000 ports (thorough, ~1 min)
  {GREEN}[3]{RESET} Deep Scan         — All 65,535 ports (full, ~5 min)
  {GREEN}[4]{RESET} Custom Port Scan  — You specify which ports
  {GREEN}[5]{RESET} Website Info Scan — HTTP headers + SSL certificate
  {RED}[6]{RESET} Exit
""")


def get_target() -> str:
    """Ask the user for a target to scan."""
    print(f"  {YELLOW}Enter target website or IP address:{RESET}")
    print(f"  {DIM}Examples: scanme.nmap.org | google.com | 192.168.1.1{RESET}")
    target = input(f"  {BOLD}Target ▸ {RESET}").strip()

    # Clean up the input — remove http:// or https:// if pasted
    if target.startswith("http://"):
        target = target[7:]
    elif target.startswith("https://"):
        target = target[8:]
    # Remove trailing slash or path
    target = target.split("/")[0]

    if not target:
        print(f"  {RED}[!] Target cannot be empty.{RESET}")
        return get_target()
    return target


def get_custom_ports() -> list:
    """Ask the user for specific port numbers or ranges."""
    print(f"\n  {YELLOW}Enter ports to scan:{RESET}")
    print(f"  {DIM}Formats: 80,443,8080  or  1-1024  or  22,80,443,3000-9000{RESET}")
    raw = input(f"  {BOLD}Ports ▸ {RESET}").strip()

    ports = []
    try:
        for part in raw.split(","):
            part = part.strip()
            if "-" in part:
                start, end = part.split("-", 1)
                ports.extend(range(int(start), int(end) + 1))
            else:
                ports.append(int(part))
    except ValueError:
        print(f"  {RED}[!] Invalid port format. Using top 100 defaults.{RESET}")
        from scanner import TOP_100_PORTS
        return TOP_100_PORTS

    # Validate range
    ports = [p for p in ports if 1 <= p <= 65535]
    if not ports:
        print(f"  {RED}[!] No valid ports. Using top 100 defaults.{RESET}")
        from scanner import TOP_100_PORTS
        return TOP_100_PORTS

    return sorted(set(ports))


def website_info_scan(target: str):
    """
    Special scan mode: connect to port 80 & 443, grab HTTP headers
    and SSL certificate info. Useful for quick website recon.
    """
    import socket
    import ssl

    print(f"\n{BOLD}[*] Website Information Scan: {target}{RESET}\n")

    # Resolve DNS
    try:
        ip = socket.gethostbyname(target)
        print(f"  {GREEN}✓{RESET} IP Address      : {ip}")
    except socket.gaierror:
        print(f"  {RED}✗{RESET} DNS resolution failed for '{target}'")
        return

    # Reverse DNS
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        print(f"  {GREEN}✓{RESET} Reverse DNS     : {hostname}")
    except Exception:
        print(f"  {DIM}  Reverse DNS     : (not available){RESET}")

    # HTTP headers from port 80
    print(f"\n  {CYAN}─── HTTP Headers (Port 80) ───{RESET}")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((ip, 80))
        request = f"HEAD / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n"
        s.send(request.encode())
        response = s.recv(4096).decode("utf-8", errors="ignore")
        s.close()
        for line in response.split("\r\n"):
            if line:
                print(f"    {line}")
    except Exception as e:
        print(f"    {RED}Could not connect: {e}{RESET}")

    # HTTPS / SSL certificate from port 443
    print(f"\n  {CYAN}─── SSL/TLS Certificate (Port 443) ───{RESET}")
    try:
        context = ssl.create_default_context()
        with socket.create_connection((ip, 443), timeout=5) as raw:
            with context.wrap_socket(raw, server_hostname=target) as tls:
                cert = tls.getpeercert()
                print(f"    TLS Version   : {tls.version()}")
                print(f"    Cipher        : {tls.cipher()[0]}")
                # Subject
                for field in cert.get("subject", ()):
                    for key, value in field:
                        print(f"    {key:<14}: {value}")
                # Issuer
                for field in cert.get("issuer", ()):
                    for key, value in field:
                        print(f"    Issuer {key:<8}: {value}")
                print(f"    Valid From    : {cert.get('notBefore', '?')}")
                print(f"    Valid Until   : {cert.get('notAfter', '?')}")
                # SANs
                sans = cert.get("subjectAltName", ())
                if sans:
                    domains = [v for _, v in sans]
                    print(f"    Alt Names     : {', '.join(domains[:5])}")
                    if len(domains) > 5:
                        print(f"                    ... and {len(domains)-5} more")
    except Exception as e:
        print(f"    {RED}Could not connect: {e}{RESET}")

    print()


def run_scan(scanner: NetworkScanner, choice: str):
    """Execute the chosen scan, print results, and save HTML report."""
    target = get_target()

    if choice == "5":
        # Special mode — website info scan (no port table)
        website_info_scan(target)
        return

    # ── Run the selected scan ──
    if choice == "1":
        results = scanner.quick_scan(target)
    elif choice == "2":
        results = scanner.standard_scan(target)
    elif choice == "3":
        results = scanner.deep_scan(target)
    elif choice == "4":
        ports = get_custom_ports()
        results = scanner.custom_scan(target, ports)
    else:
        return

    # ── Print terminal report ──
    print_report(results)

    # ── Generate HTML report ──
    report_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
    report_path = generate_html_report(results, output_dir=report_dir)

    print(f"  {GREEN}[✓] Report saved! Open it in your browser:{RESET}")
    print(f"      {CYAN}{report_path}{RESET}")

    # Ask if they want to open the report in browser
    try:
        open_it = input(f"\n  {BOLD}Open report in browser? (y/n) ▸ {RESET}").strip().lower()
        if open_it in ("y", "yes"):
            webbrowser.open(f"file://{report_path}")
            print(f"  {GREEN}[✓] Opened in browser!{RESET}")
    except (EOFError, KeyboardInterrupt):
        pass

    print()


def main():
    """Main loop — display menu, dispatch scans, repeat."""
    display_banner()

    # Create one scanner instance (reused for all scans)
    scanner = NetworkScanner(timeout=1.5, max_threads=200)

    while True:
        display_menu()
        try:
            choice = input(f"  {BOLD}Choice [1-6] ▸ {RESET}").strip()
        except (EOFError, KeyboardInterrupt):
            print(f"\n  {CYAN}Goodbye! Stay safe. 🔒{RESET}\n")
            sys.exit(0)

        if choice == "6":
            print(f"\n  {CYAN}Goodbye! Stay safe. 🔒{RESET}\n")
            sys.exit(0)
        elif choice in ("1", "2", "3", "4", "5"):
            try:
                run_scan(scanner, choice)
            except KeyboardInterrupt:
                print(f"\n\n  {YELLOW}[!] Scan interrupted.{RESET}\n")
            except Exception as e:
                print(f"\n  {RED}[!] Error: {e}{RESET}\n")
        else:
            print(f"  {RED}[!] Invalid choice. Enter 1-6.{RESET}")


if __name__ == "__main__":
    main()
