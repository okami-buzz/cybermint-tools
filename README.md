# CyberMint

**Cybersecurity Command Hub** — A professional terminal-based security toolkit for cybersecurity professionals, researchers, students, and developers.

```
  ██████╗██╗   ██╗██████╗ ███████╗██████╗ ███╗   ███╗██╗███╗   ██╗████████╗
  ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗████╗ ████║██║████╗  ██║╚══██╔══╝
  ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██╔████╔██║██║██╔██╗ ██║   ██║
  ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██║╚██╔╝██║██║██║╚██╗██║   ██║
  ╚██████╗   ██║   ██████╔╝███████╗██║  ██║██║ ╚═╝ ██║██║██║ ╚████║   ██║
   ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝   ╚═╝
```

## Features

| Module | Description |
|---|---|
| **Intelligence Center** | Asset management, risk scoring, findings correlation, notes |
| **Recon Center** | WHOIS, DNS, SSL/TLS, port scanning, tech detection |
| **Security Analysis** | Header analysis, config checks, OWASP checklist, findings |
| **Network Center** | Device discovery, service info, traceroute, IP geolocation |
| **Digital Forensics** | File hashing, metadata, directory integrity, log analysis |
| **Threat Intelligence** | IOC management, CVE lookup, threat notes |
| **Report Center** | Full reports, executive summaries, export (TXT/MD) |
| **Plugin Manager** | Load and run custom/community/research plugins |
| **Settings** | Config, update checking, database stats |

## Installation

```bash
git clone https://github.com/yourusername/CyberMint
cd CyberMint
bash install.sh
```

Or manually:

```bash
pip install -r requirements.txt
python3 main.py
```

## Requirements

- Python 3.8+
- See `requirements.txt` for dependencies

## Project Structure

```
CyberMint/
├── main.py               # Entry point
├── install.sh            # Installer
├── requirements.txt
├── README.md
│
├── core/                 # Core engine
│   ├── engine.py         # Module/plugin management
│   ├── database.py       # SQLite database
│   ├── config.py         # Configuration
│   ├── updater.py        # Update checker
│   └── logger.py         # Logging
│
├── modules/              # Built-in modules
│   ├── intelligence/
│   ├── recon/
│   ├── analysis/
│   ├── network/
│   ├── forensics/
│   ├── threat/
│   └── reports/
│
├── plugins/              # Extensible plugins
│   ├── custom_module/
│   ├── community_module/
│   └── research_module/
│
├── database/             # SQLite DB & logs
├── reports/              # Generated reports
├── themes/               # Theme files
└── docs/                 # Documentation
```

## Plugin Development

Copy `plugins/custom_module/` and implement:

```python
PLUGIN_INFO = {
    "name": "My Plugin",
    "version": "1.0.0",
    "author": "You",
    "description": "Description",
    "category": "custom",
}

def get_info():
    return PLUGIN_INFO

def show_menu(current_project=None):
    # Your plugin UI here
    pass
```

## License

MIT License — see `LICENSE`
