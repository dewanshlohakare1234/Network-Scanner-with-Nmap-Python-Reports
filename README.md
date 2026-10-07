# 🛡️ Network Scanner — Pure Python

<div align="center">

![Python](https://img.shields.io/badge/Python-3.6+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Windows%20|%20Linux%20|%20macOS-blue?style=for-the-badge)
![Dependencies](https://img.shields.io/badge/Dependencies-Zero-brightgreen?style=for-the-badge)

**A powerful network scanner built with pure Python — zero external dependencies.**
**Scan any website or server, detect open ports & services, and generate professional HTML reports.**

[Features](#-features) •
[Installation](#-installation) •
[Usage](#-usage) •
[Screenshots](#-screenshots) •
[How It Works](#-how-it-works) •
[Project Structure](#-project-structure) •
[Contributing](#-contributing)

</div>

---

## ✨ Features

- 🔍 **4 Scan Modes** — Quick, Standard, Deep (all 65,535 ports), and Custom
- 🌐 **Website Info Scan** — HTTP headers + SSL/TLS certificate inspection
- 📡 **Banner Grabbing** — Detect software names & versions running on open ports
- 🔒 **SSL/TLS Analysis** — Read certificates, check expiry, identify TLS version
- ⚡ **Multi-Threaded** — 200 concurrent threads for blazing-fast scans
- 📊 **HTML Reports** — Professional dark-themed reports auto-saved to `reports/`
- 🎨 **Coloured Terminal Output** — Pretty tables with ANSI colours
- 📦 **Zero Dependencies** — Uses ONLY Python's built-in standard library
- 🖥️ **Cross-Platform** — Works on Windows, Linux, and macOS

---

## 📦 Installation

**No installation needed!** Just clone and run.

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/network-scanner.git
cd network-scanner

# Run it (Python 3.6+ required)
python main.py
```

> **Note:** This project uses only Python's built-in libraries. No `pip install` needed!

---

## 🚀 Usage

### Interactive Menu

```bash
python main.py
```

You'll see an interactive menu:

```
  ┌─────────────────────────────────────────────┐
  │         SELECT A SCAN TYPE                  │
  └─────────────────────────────────────────────┘
  [1] Quick Scan        — Top 100 ports (fast, ~10 sec)
  [2] Standard Scan     — Top 1000 ports (thorough, ~1 min)
  [3] Deep Scan         — All 65,535 ports (full, ~5 min)
  [4] Custom Port Scan  — You specify which ports
  [5] Website Info Scan — HTTP headers + SSL certificate
  [6] Exit
```

### Scan Types Explained

| Option | Ports Scanned | Speed | Best For |
|--------|--------------|-------|----------|
| **Quick Scan** | Top 100 | ~10 sec | Fast recon — is SSH/HTTP open? |
| **Standard Scan** | Top 1000 | ~1 min | Real security assessments |
| **Deep Scan** | All 65,535 | ~5 min | Finding hidden services |
| **Custom Scan** | Your choice | Varies | Targeting specific ports |
| **Website Info** | 80 + 443 | ~3 sec | Website recon & SSL check |

### Examples

```bash
# Quick scan a website
Target: scanme.nmap.org     # ← Safe practice target

# Scan specific database ports
Target: your-server.com
Ports:  3306,5432,27017,6379

# Scan a port range
Target: 192.168.1.1
Ports:  1-1024

# Website recon
Target: google.com          # Shows HTTP headers + SSL cert
```

> You can paste full URLs like `https://example.com/page` — the tool automatically strips the protocol and path.

---

## 📸 Screenshots

### Terminal Output

```
══════════════════════════════════════════════════════════════
  🛡️  NETWORK SCAN REPORT
══════════════════════════════════════════════════════════════
  Scan Type       : Quick Scan (Top 100 Ports)
  Target          : scanme.nmap.org
  Open Ports      : 4
  Scan Duration   : 8.32 seconds
══════════════════════════════════════════════════════════════

  HOST: 45.33.32.156 (scanme.nmap.org)
  State: up

  PORT       STATE      SERVICE         PRODUCT / VERSION
  ────────── ────────── ─────────────── ──────────────────
  22/tcp     open       ssh             OpenSSH 6.6.1p1
  80/tcp     open       http            Apache 2.4.7
  9929/tcp   open       unknown         —
  31337/tcp  open       unknown         —
```

### HTML Report

The tool generates a professional dark-themed HTML report that opens right in your browser:

- 📊 Stats cards showing open ports, scan duration, total ports scanned
- 🖥️ Host cards with port tables
- 📡 Service banners in monospace
- 🔒 SSL/TLS certificate details

Reports are auto-saved to the `reports/` folder with timestamped filenames.

---

## 🔬 How It Works

### Architecture

```
main.py (Menu + UI)
    │
    ├── scanner.py (Scanning Engine)
    │       ├── DNS Resolution      → socket.gethostbyname()
    │       ├── Port Scanning       → socket.connect_ex() × 200 threads
    │       ├── Banner Grabbing     → socket.recv() after connecting
    │       └── SSL Inspection      → ssl.wrap_socket() + getpeercert()
    │
    └── reporter.py (Report Generator)
            ├── Terminal Report     → ANSI coloured tables
            └── HTML Report        → Dark-themed HTML via f-strings
```

### TCP Connect Scanning

The scanner performs a **TCP 3-way handshake** on each port:

```
 Your PC                     Target Server
   │                              │
   │──── SYN ────────────────────►│   "Can I connect?"
   │                              │
   │◄─── SYN-ACK ────────────────│   → Port is OPEN ✅
   │◄─── RST ────────────────────│   → Port is CLOSED ❌
   │     ... timeout ...          │   → Port is FILTERED 🔥
```

### Why It's Fast

Instead of scanning ports one-by-one (which would take 25+ minutes for 1000 ports), we use **200 concurrent threads**:

```python
# 1000 ports ÷ 200 threads = 5 batches × 1.5s timeout = ~8 seconds
with ThreadPoolExecutor(max_workers=200) as executor:
    futures = {executor.submit(check_port, ip, port): port for port in ports}
```

---

## 📁 Project Structure

```
network-scanner/
│
├── main.py              # Entry point — interactive menu + UI
│   ├── display_banner() #   ASCII art logo
│   ├── display_menu()   #   Scan type selection
│   ├── get_target()     #   Input + URL cleanup
│   ├── run_scan()       #   Dispatches scan → report → browser
│   └── website_info()   #   HTTP headers + SSL certificate scan
│
├── scanner.py           # Core scanning engine
│   ├── COMMON_PORTS     #   Built-in port-to-service mapping (100+)
│   ├── TOP_100_PORTS    #   Most common ports list
│   ├── NetworkScanner   #   Main scanner class
│   │   ├── quick_scan()     # Top 100 ports
│   │   ├── standard_scan()  # Top 1000 ports
│   │   ├── deep_scan()      # All 65,535 ports
│   │   ├── custom_scan()    # User-defined ports
│   │   ├── _check_port()    # TCP connect to single port
│   │   ├── _grab_banner()   # Read service banner
│   │   ├── _get_ssl_info()  # TLS certificate details
│   │   └── _parse_banner()  # Extract product/version from banner
│   └── ...
│
├── reporter.py          # Report generation
│   ├── print_report()       # Coloured terminal output
│   └── generate_html_report() # Professional HTML file
│
├── reports/             # Auto-generated HTML reports (gitignored)
├── requirements.txt     # Documents built-in modules used
├── .gitignore           # Git ignore rules
├── LICENSE              # MIT License
└── README.md            # This file
```

---

## 🐍 Built-in Python Modules Used

| Module | Purpose |
|--------|---------|
| `socket` | TCP connections, DNS resolution, banner grabbing |
| `ssl` | TLS/SSL certificate reading |
| `concurrent.futures` | Multi-threaded parallel port scanning |
| `datetime` | Timestamps for results and filenames |
| `os` | File and directory management |
| `html` | XSS-safe HTML escaping in reports |
| `re` | Regex-based banner parsing |
| `webbrowser` | Open HTML reports in default browser |
| `sys` | Clean program exit |

---

## ⚠️ Legal Disclaimer

> **This tool is for educational purposes and authorized security testing only.**
>
> - ✅ Scan your own servers and networks
> - ✅ Use `scanme.nmap.org` for practice
> - ✅ Scan with written permission from the owner
> - ❌ **NEVER** scan systems you don't own or have permission to test
>
> Unauthorized network scanning is illegal under laws like the Computer Fraud and Abuse Act (CFAA) and similar legislation worldwide. The author is not responsible for misuse.

---

## 🛠️ Troubleshooting

| Problem | Solution |
|---------|----------|
| `python` not found | Install Python 3.6+ from [python.org](https://python.org) |
| `ModuleNotFoundError` | `cd` into the `network-scanner` folder first |
| 0 open ports found | Target may have a firewall — try `scanme.nmap.org` |
| Scan takes too long | Use Quick Scan (option 1) or reduce target range |
| Colours look broken | Use Windows Terminal / PowerShell 7 (not old CMD) |

---

## 🤝 Contributing

Contributions are welcome! Here's how:

1. **Fork** this repository
2. **Create a branch**: `git checkout -b feature/my-feature`
3. **Commit changes**: `git commit -m "Add my feature"`
4. **Push**: `git push origin feature/my-feature`
5. **Open a Pull Request**

### Ideas for contributions:
- [ ] UDP scanning support
- [ ] JSON export format
- [ ] Subnet sweeping (scan entire networks)
- [ ] Rate limiting / stealth mode
- [ ] IPv6 support

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

## ⭐ Star This Repo

If you found this project helpful, please give it a ⭐ on GitHub — it helps others discover it!

---

<div align="center">

**Built with ❤️ using Pure Python**

</div>
