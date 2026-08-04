# CyberMint

**CyberMint** is a professional terminal-based cybersecurity command hub built in Python.

## How to Run

```bash
python3 main.py
```

Or via the configured Replit workflow: **Run CyberMint**

## Stack

- **Language**: Python 3
- **UI**: [rich](https://rich.readthedocs.io/) — terminal rendering
- **Database**: SQLite (via `core/database.py`)
- **Config**: JSON (`database/config.json`)
- **Modules**: `modules/` — each module is a standalone folder

## Project Layout

```
main.py          — entry point
core/            — engine, database, config, logger, updater
modules/         — intelligence, recon, analysis, network, forensics, threat, reports
plugins/         — extensible plugin directory
database/        — SQLite DB + logs + config.json
reports/         — exported report files
ui/              — theme and console helpers
```

## User Preferences

- Dark cyan terminal theme
- Professional CLI interface (no web UI)
- All data stored locally (SQLite)
- Modular / plugin-based architecture
