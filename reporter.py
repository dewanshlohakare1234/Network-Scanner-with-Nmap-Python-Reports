"""
reporter.py — Report Generation (Pure Python, No Dependencies!)
===============================================================
Takes the scan results dictionary from scanner.py and generates:
  1. A colourful TERMINAL summary  (ANSI codes — works on Win10+, Linux, macOS)
  2. A professional HTML report    (pure string formatting — no Jinja2 needed)

Everything here uses ONLY Python's built-in modules:
  • os, datetime           → file management
  • html                   → escape user data for safe HTML
  • string (f-strings)     → template the HTML

No pip install required!
"""

import os
import html as html_module   # We use html.escape() to prevent XSS in reports
import datetime


# ======================================================================
# 1. TERMINAL REPORT  (coloured console output)
# ======================================================================

def print_report(results: dict) -> None:
    """
    Pretty-print scan results to the terminal using ANSI colour codes.

    ANSI codes work on:
      ✓ Windows Terminal / PowerShell 7 / CMD (Windows 10+)
      ✓ All Linux and macOS terminals
    """
    # ── Colour constants ──
    CYAN   = "\033[96m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    RED    = "\033[91m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"

    w = 62  # line width

    print(f"\n{BOLD}{CYAN}{'═' * w}")
    print(f"  🛡️  NETWORK SCAN REPORT")
    print(f"{'═' * w}{RESET}")
    print(f"  Scan Type       : {results['scan_type']}")
    print(f"  Target          : {results['target_input']}")
    print(f"  Timestamp       : {results['timestamp']}")
    print(f"  Ports Scanned   : {results['total_ports_scanned']}")
    print(f"  Open Ports      : {GREEN}{results['open_port_count']}{RESET}")
    print(f"  Scan Duration   : {results['elapsed']} seconds")
    print(f"{BOLD}{CYAN}{'═' * w}{RESET}\n")

    if not results["hosts"]:
        print(f"  {YELLOW}No hosts responded.{RESET}\n")
        return

    for host in results["hosts"]:
        state_c = GREEN if host["state"] == "up" else RED
        hostname_str = f" ({host['hostname']})" if host["hostname"] else ""

        print(f"  {BOLD}{CYAN}HOST: {host['ip']}{hostname_str}{RESET}")
        print(f"  State: {state_c}{host['state']}{RESET}")

        if host["ports"]:
            # Table header
            print(f"\n  {'PORT':<10} {'STATE':<10} {'SERVICE':<15} {'PRODUCT / VERSION'}")
            print(f"  {'─' * 10} {'─' * 10} {'─' * 15} {'─' * 30}")

            for p in host["ports"]:
                port_str = f"{p['port']}/{p['protocol']}"
                state_c  = GREEN if p["state"] == "open" else YELLOW
                version  = f"{p.get('product', '')} {p.get('version', '')}".strip() or "—"
                print(f"  {port_str:<10} {state_c}{p['state']:<10}{RESET} "
                      f"{p['service']:<15} {version}")

                # Show banner excerpt if available
                banner = p.get("banner", "")
                if banner:
                    # Show first line of banner (truncated)
                    first_line = banner.split("\n")[0][:70]
                    print(f"  {DIM}           └─ Banner: {first_line}{RESET}")

                # Show SSL/TLS info if available
                ssl_info = p.get("ssl_info")
                if ssl_info:
                    print(f"  {DIM}           └─ TLS: {ssl_info.get('version', '?')} | "
                          f"Expires: {ssl_info.get('expires', '?')}{RESET}")
        else:
            print(f"\n  {YELLOW}No open ports found.{RESET}")

        print()

    print(f"{BOLD}{CYAN}{'═' * w}{RESET}\n")


# ======================================================================
# 2. HTML REPORT  (pure Python string formatting — no Jinja2!)
# ======================================================================

def generate_html_report(results: dict, output_dir: str = "reports") -> str:
    """
    Render scan results into a professional, dark-themed HTML report.

    Uses Python f-strings and string concatenation instead of Jinja2.
    html.escape() is used on all user-supplied data to prevent XSS.

    Parameters:
        results   : The dict returned by any NetworkScanner scan method.
        output_dir: Folder to save the .html file in.

    Returns:
        Absolute path to the generated HTML file.
    """
    esc = html_module.escape  # shorthand for html.escape()

    # ── Build the host cards HTML ──
    hosts_html = ""
    for host in results.get("hosts", []):
        # State badge
        state_class = "badge-up" if host["state"] == "up" else "badge-down"

        # Port rows
        port_rows = ""
        for p in host["ports"]:
            port_class = "badge-open" if p["state"] == "open" else "badge-closed"
            product_version = esc(f"{p.get('product', '')} {p.get('version', '')}".strip()) or "—"
            banner_text = esc(p.get("banner", "").split("\n")[0][:100])

            port_rows += f"""
                <tr>
                    <td><strong>{p['port']}</strong></td>
                    <td>{esc(p['protocol'])}</td>
                    <td><span class="badge {port_class}">{esc(p['state'])}</span></td>
                    <td>{esc(p['service'])}</td>
                    <td>{product_version}</td>
                </tr>"""

            # Banner row (if any)
            if banner_text:
                port_rows += f"""
                <tr class="banner-row">
                    <td colspan="5">
                        <div class="banner">📡 {banner_text}</div>
                    </td>
                </tr>"""

            # SSL info row (if any)
            ssl_info = p.get("ssl_info")
            if ssl_info:
                port_rows += f"""
                <tr class="banner-row">
                    <td colspan="5">
                        <div class="ssl-info">
                            🔒 TLS {esc(str(ssl_info.get('version', '')))} |
                            Expires: {esc(str(ssl_info.get('expires', '')))}
                        </div>
                    </td>
                </tr>"""

        # Port table or "no ports" message
        if host["ports"]:
            ports_html = f"""
            <table>
                <thead>
                    <tr>
                        <th>Port</th><th>Protocol</th><th>State</th>
                        <th>Service</th><th>Product / Version</th>
                    </tr>
                </thead>
                <tbody>{port_rows}
                </tbody>
            </table>"""
        else:
            ports_html = '<p class="no-ports">No open ports detected.</p>'

        hostname_str = f" ({esc(host['hostname'])})" if host["hostname"] else ""

        hosts_html += f"""
        <div class="host-card">
            <h2>🖥️ {esc(host['ip'])}{hostname_str}</h2>
            <div class="host-meta">
                <span>State: <span class="badge {state_class}">{esc(host['state'])}</span></span>
            </div>
            {ports_html}
        </div>"""

    if not results.get("hosts"):
        hosts_html = """
        <div class="host-card" style="text-align:center">
            <p class="no-ports">⚠️ No hosts responded to the scan.</p>
        </div>"""

    # ── Assemble the full HTML page ──
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Network Scan Report — {esc(results['timestamp'])}</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin:0; padding:0; }}
  body {{
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    background: #0d1117; color: #c9d1d9; line-height: 1.6; padding: 2rem;
  }}

  .container {{ max-width: 1000px; margin: 0 auto; }}

  /* Header */
  .header {{
    background: linear-gradient(135deg, #161b22, #1a2233);
    border: 1px solid #30363d; border-radius: 12px;
    padding: 2rem; margin-bottom: 2rem; text-align: center;
  }}
  .header h1 {{ color: #58a6ff; font-size: 1.8rem; margin-bottom: .5rem; }}
  .header p  {{ color: #8b949e; font-size: .95rem; }}
  .header code {{
    background: #21262d; padding: 3px 8px; border-radius: 4px;
    font-size: .85rem; color: #79c0ff;
  }}

  /* Stats */
  .stats {{
    display: flex; gap: 1rem; flex-wrap: wrap;
    justify-content: center; margin-bottom: 2rem;
  }}
  .stat-card {{
    background: #161b22; border: 1px solid #30363d; border-radius: 10px;
    padding: 1.2rem 1.8rem; text-align: center; min-width: 150px; flex: 1;
  }}
  .stat-card .value {{ font-size: 2rem; font-weight: 700; color: #58a6ff; }}
  .stat-card .label {{ color: #8b949e; font-size: .85rem; margin-top: .3rem; }}

  /* Host card */
  .host-card {{
    background: #161b22; border: 1px solid #30363d; border-radius: 10px;
    padding: 1.5rem; margin-bottom: 1.5rem;
  }}
  .host-card h2 {{ color: #79c0ff; font-size: 1.25rem; margin-bottom: .5rem; }}
  .host-meta span {{ margin-right: 1.5rem; color: #8b949e; font-size: .9rem; }}

  /* Table */
  table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; }}
  th {{
    background: #21262d; color: #8b949e; text-transform: uppercase;
    font-size: .75rem; letter-spacing: .05em;
    padding: .6rem 1rem; text-align: left; border-bottom: 1px solid #30363d;
  }}
  td {{ padding: .55rem 1rem; border-bottom: 1px solid #21262d; font-size: .9rem; }}
  tr:hover td {{ background: #1c2128; }}
  .banner-row td {{ padding: 0 1rem .4rem 1rem; border: none; }}

  /* Badges */
  .badge {{
    display: inline-block; padding: 2px 10px; border-radius: 12px;
    font-size: .78rem; font-weight: 600;
  }}
  .badge-open, .badge-up {{ background: #23863620; color: #3fb950; border: 1px solid #23863650; }}
  .badge-closed, .badge-down {{ background: #da363420; color: #f85149; border: 1px solid #da363450; }}

  /* Banner & SSL */
  .banner {{
    background: #1c1e26; border-left: 3px solid #58a6ff;
    padding: .5rem .8rem; font-size: .8rem; border-radius: 4px;
    color: #8b949e; font-family: monospace; word-break: break-all;
  }}
  .ssl-info {{
    background: #1c1e26; border-left: 3px solid #3fb950;
    padding: .5rem .8rem; font-size: .8rem; border-radius: 4px;
    color: #3fb950; font-family: monospace;
  }}
  .no-ports {{ color: #f0883e; margin-top: 1rem; }}

  /* Footer */
  .footer {{
    text-align: center; color: #484f58; font-size: .8rem;
    margin-top: 2rem; padding-top: 1rem; border-top: 1px solid #21262d;
  }}

  /* Info box */
  .info-box {{
    background: #161b22; border: 1px solid #30363d; border-radius: 8px;
    padding: 1rem 1.5rem; margin-bottom: 1.5rem; font-size: .9rem;
  }}
  .info-box dt {{ color: #8b949e; float: left; width: 150px; font-weight: 600; }}
  .info-box dd {{ margin-left: 160px; margin-bottom: .3rem; }}
</style>
</head>
<body>
<div class="container">

  <div class="header">
    <h1>🛡️ Network Scan Report</h1>
    <p>{esc(results['scan_type'])} — {esc(results['timestamp'])}</p>
    <p style="margin-top:.5rem;">
      <code>Target: {esc(results['target_input'])}</code>
    </p>
  </div>

  <div class="stats">
    <div class="stat-card">
      <div class="value">{results['open_port_count']}</div>
      <div class="label">Open Ports</div>
    </div>
    <div class="stat-card">
      <div class="value">{results['total_ports_scanned']}</div>
      <div class="label">Ports Scanned</div>
    </div>
    <div class="stat-card">
      <div class="value">{esc(str(results['elapsed']))}s</div>
      <div class="label">Duration</div>
    </div>
    <div class="stat-card">
      <div class="value">{len(results.get('hosts', []))}</div>
      <div class="label">Hosts</div>
    </div>
  </div>

  <div class="info-box">
    <dl>
      <dt>Scan Type</dt><dd>{esc(results['scan_type'])}</dd>
      <dt>Target Input</dt><dd>{esc(results['target_input'])}</dd>
      <dt>Resolved IP</dt><dd>{esc(results['hosts'][0]['ip'] if results.get('hosts') else 'N/A')}</dd>
      <dt>Scan Time</dt><dd>{esc(results['timestamp'])}</dd>
    </dl>
  </div>

  {hosts_html}

  <div class="footer">
    Generated by <strong>Python Network Scanner</strong> — Pure Python, Zero Dependencies
  </div>
</div>
</body>
</html>"""

    # ── Save to file ──
    os.makedirs(output_dir, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"scan_report_{ts}.html"
    filepath = os.path.join(output_dir, filename)

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html_content)

    abs_path = os.path.abspath(filepath)
    print(f"[+] HTML report saved → {abs_path}")
    return abs_path


# ======================================================================
# Self-test with dummy data
# ======================================================================
if __name__ == "__main__":
    dummy = {
        "scan_type": "Quick Scan (Top 100 Ports)",
        "timestamp": "2026-10-07 22:30:00",
        "elapsed": "2.45",
        "target_input": "scanme.nmap.org",
        "total_ports_scanned": 100,
        "open_port_count": 2,
        "hosts": [
            {
                "ip": "45.33.32.156",
                "hostname": "scanme.nmap.org",
                "state": "up",
                "ports": [
                    {"port": 22, "protocol": "tcp", "state": "open",
                     "service": "ssh", "banner": "SSH-2.0-OpenSSH_6.6.1p1",
                     "product": "OpenSSH", "version": "6.6.1p1"},
                    {"port": 80, "protocol": "tcp", "state": "open",
                     "service": "http", "banner": "HTTP/1.1 200 OK\r\nServer: Apache/2.4.7",
                     "product": "Apache", "version": "2.4.7"},
                ],
            }
        ],
    }
    print_report(dummy)
    generate_html_report(dummy)
