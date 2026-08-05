# CyberMint

**Cybersecurity Command Hub** — A professional terminal-based security toolkit for cybersecurity professionals, researchers, students, and developers. Inspired by Kali Linux & NetHunter.

```
  ██████╗██╗   ██╗██████╗ ███████╗██████╗ ███╗   ███╗██╗███╗   ██╗████████╗
  ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗████╗ ████║██║████╗  ██║╚══██╔══╝
  ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██╔████╔██║██║██╔██╗ ██║   ██║
  ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██║╚██╔╝██║██║██║╚██╗██║   ██║
  ╚██████╗   ██║   ██████╔╝███████╗██║  ██║██║ ╚═╝ ██║██║██║ ╚████║   ██║
   ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝   ╚═╝
```

---

## Installation

```bash
git clone https://github.com/okami-buzz/cybermint-tools
cd cybermint-tools
bash install.sh
```

> Works on **Linux**, **macOS**, and **Termux (Android)**

### Run

```bash
python3 main.py
```

### Requirements

- Python 3.8+
- Dependencies auto-installed by `install.sh`

---

## Modules (11 Total)

### [01] Intelligence Center
> Asset management, risk scoring & correlation

- Project management (create, track, delete)
- Asset registry (domains, IPs, services)
- Security score calculator
- Findings correlation
- Notes manager
- Project dashboard

---

### [02] Recon Center
> Information gathering & footprinting

- WHOIS lookup
- DNS intelligence (A, AAAA, MX, NS, TXT, CNAME, SOA)
- SSL/TLS certificate analysis
- TCP port scanner (common ports)
- Technology & HTTP header detection
- Full recon profile (all-in-one)
- Scan history viewer

---

### [03] Web Hacking
> Web application security testing

| Tool | Description |
|---|---|
| Directory Brute-Force | Find hidden files & directories (built-in + custom wordlist) |
| Admin Panel Finder | Locate login/admin pages |
| SQL Injection Tester | Error-based & boolean SQLi detection |
| XSS Scanner | Reflected XSS detection across GET parameters |
| CMS Detector | Fingerprint WordPress, Joomla, Drupal, Django, Laravel, Magento & more |
| JWT Analyzer | Decode header/payload, check algorithm, expiry, security issues |
| CORS Checker | Detect misconfigured cross-origin policies |
| HTTP Method Tester | Test GET/POST/PUT/DELETE/OPTIONS/TRACE/CONNECT |
| Open Redirect Tester | Detect unvalidated redirect flaws |
| Cookie Analyzer | Audit Secure, HttpOnly, SameSite flags |
| Full Web Audit | Run all checks in one command |

---

### [04] Security Analysis
> Configuration & vulnerability assessment

- HTTP security header analysis
- Full configuration audit (HTTPS, HSTS, CSP, X-Frame-Options, etc.)
- Manual finding recorder
- Risk classification & scoring
- OWASP Top 10 checklist
- Recommendations engine

---

### [05] Network Center
> Network analysis & device inventory

- Local network information
- Ping sweep / device discovery
- Service & banner grabbing
- DNS resolver
- Traceroute
- IP Geolocation
- Network report generator

---

### [06] Digital Forensics
> File analysis & integrity verification

- Multi-algorithm hash generator (MD5, SHA1, SHA256, SHA512)
- File metadata extractor
- Hash comparison (identify identical/modified files)
- Directory integrity snapshot
- Log analyzer (IPs, emails, errors, HTTP codes, timestamps)
- String extractor from binary files
- Saved hash records

---

### [07] Threat Intelligence
> IOC management & threat research

- Add/search/filter IOCs (hash, domain, IP, URL, email, CVE)
- Threat summary dashboard
- Bulk IOC import from file
- CVE lookup (via circl.lu API)
- Threat notes & research database

---

### [08] Password & Crypto
> Hash analysis, cracking & encoding

| Tool | Description |
|---|---|
| Hash Identifier | Detect MD5, SHA1, SHA256, bcrypt, NTLM & more by length/pattern |
| Hash Generator | Generate hashes from any input |
| Hash Cracker | Wordlist-based cracking with leet-speak variants |
| Password Generator | Random, passphrase, PIN, hex, base64 |
| Wordlist Generator | Build target-based wordlists from name/birthday/keywords |
| Password Strength | Analyze strength with detailed scoring |
| Encoder / Decoder | Base64, Hex, URL, HTML, ROT13, Binary, Caesar cipher |
| All Hashes | Hash a string with every algorithm at once |
| Brute Force Estimator | Calculate crack time by charset & speed |

---

### [09] OSINT Center
> Open Source Intelligence gathering

| Tool | Description |
|---|---|
| Subdomain Enumeration | Brute-force subdomains with built-in wordlist |
| Email Harvester | Scrape emails from public pages + Hunter.io |
| Google Dork Generator | Auto-build 20+ targeted search queries |
| Wayback Machine Lookup | Fetch archived snapshots via archive.org CDX API |
| Username Search | Hunt a username across 20 platforms (GitHub, Twitter, Instagram, TikTok, Reddit, Steam, etc.) |
| IP Reputation Check | Geo + Shodan InternetDB (open ports, CVEs, tags) |
| Domain OSINT Profile | Full passive recon in one command |
| Certificate Transparency | Find subdomains via crt.sh SSL logs |
| DNS Brute Force | Aggressive DNS subdomain discovery |

---

### [10] Payload Generator
> For authorized penetration testing only

| Tool | Description |
|---|---|
| Reverse Shell Generator | 15 languages: Bash, Python, PHP, PowerShell, Perl, Ruby, Go, Node.js, Netcat, Socat, AWK, Java, Awk, and more |
| Bind Shell Generator | Python, Netcat, Perl, Socat, PowerShell |
| Web Shell Snippets | PHP (cmd/eval/passthru/popen), Python Flask, Perl CGI, ASP, JSP, Node.js |
| MSFvenom Command Builder | Auto-build payload commands for Linux/Windows/Android/macOS |
| SQLMap Command Builder | Full sqlmap command with tamper, WAF bypass options |
| Payload Encoder | Base64, URL, double-URL, hex, hex-escape |
| Exploit Reference | SQLi, XSS, LFI, SSRF, command injection, Linux privesc cheatsheet |
| Command Injection Builder | Semicolon, pipe, backtick, dollar, newline — with URL encoding variants |

> ⚠️ For authorized security testing only. Do not use on systems you don't own.

---

### [11] Report Center
> Professional security reports

- Full project security report (auto-generated)
- Executive summary
- Findings summary by severity
- IOC report
- Scan history report
- Export to TXT / Markdown

---

### [12] Plugin Manager
> Extend CyberMint with custom modules

Drop your plugin folder into `plugins/` with an `__init__.py` — it loads automatically.

```python
PLUGIN_INFO = {
    "name": "My Plugin",
    "version": "1.0.0",
    "author": "You",
    "description": "What it does",
    "category": "custom",
}

def get_info():
    return PLUGIN_INFO

def show_menu(current_project=None):
    pass  # Your UI here
```

---

### [13] Settings
- System information
- View & edit configuration
- Check for updates (GitHub)
- Database stats
- Clear logs

---

## Project Structure

```
CyberMint/
├── main.py                  — Entry point
├── install.sh               — Installer (Linux, macOS, Termux)
├── requirements.txt
├── README.md
│
├── core/
│   ├── engine.py            — Module & plugin management
│   ├── database.py          — SQLite database (projects, findings, IOCs, reports)
│   ├── config.py            — JSON configuration
│   ├── updater.py           — GitHub update checker
│   └── logger.py            — Logging system
│
├── modules/
│   ├── intelligence/        — [01] Asset intelligence
│   ├── recon/               — [02] Recon & footprinting
│   ├── webhack/             — [03] Web hacking tools
│   ├── analysis/            — [04] Security analysis
│   ├── network/             — [05] Network tools
│   ├── forensics/           — [06] Digital forensics
│   ├── threat/              — [07] Threat intelligence
│   ├── crypto/              — [08] Password & crypto
│   ├── osint/               — [09] OSINT tools
│   ├── payload/             — [10] Payload generator
│   └── reports/             — [11] Report center
│
├── plugins/                 — Drop custom plugins here
│   ├── custom_module/
│   ├── community_module/
│   └── research_module/
│
├── database/                — SQLite DB, logs, config.json
├── reports/                 — Generated report files
├── themes/
└── docs/
```

---

## Database

All data stored locally in SQLite (`database/cybermint.db`):

- **Projects** — targets, status, risk level, security score
- **Findings** — severity, category, recommendations
- **Assets** — domains, IPs, services
- **IOCs** — hashes, domains, IPs, CVEs
- **Scan History** — all module runs with results
- **Notes** — research notes per project
- **Reports** — saved report content & file paths

---

## License

MIT License — see `LICENSE`

---

*Built with Python + Rich • Runs on Linux, macOS, Termux*
