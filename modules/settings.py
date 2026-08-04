"""
CyberMint Settings & System Info
"""
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich import box

from core.config import config
from core.engine import engine
from core.updater import check_for_updates
from ui.theme import theme
import platform
from datetime import datetime

console = Console()


def show_menu():
    while True:
        console.clear()
        theme.banner("SETTINGS", "Configuration & System Information")

        options = [
            ("[01]", "System Information",  "Platform & engine details"),
            ("[02]", "View Configuration",  "Current settings"),
            ("[03]", "Edit Configuration",  "Change settings"),
            ("[04]", "Reset Configuration", "Restore defaults"),
            ("[05]", "Check for Updates",   "Query GitHub for new version"),
            ("[06]", "Database Stats",      "Database file information"),
            ("[07]", "Clear Logs",          "Remove old log files"),
            ("[00]", "Back to Main Menu",   ""),
        ]
        theme.menu_table(options)

        choice = Prompt.ask("\n  [cyan]>[/cyan] Select option", default="00")

        if choice == "00":
            break
        elif choice == "01":
            _system_info()
        elif choice == "02":
            _view_config()
        elif choice == "03":
            _edit_config()
        elif choice == "04":
            _reset_config()
        elif choice == "05":
            _check_updates()
        elif choice == "06":
            _db_stats()
        elif choice == "07":
            _clear_logs()


def _system_info():
    console.clear()
    theme.section_header("SYSTEM INFORMATION")

    health = engine.health_check()
    t = Table(box=box.SIMPLE, header_style="bold cyan", border_style="dim cyan")
    t.add_column("Property",  style="cyan",       min_width=25)
    t.add_column("Value",     style="bold white")

    t.add_row("CyberMint Version",   health["version"])
    t.add_row("Engine Status",       f"[green]{health['status']}[/green]")
    t.add_row("Modules Loaded",      str(health["modules_loaded"]))
    t.add_row("Plugins Loaded",      str(health["plugins_loaded"]))
    t.add_row("Python Version",      platform.python_version())
    t.add_row("Platform",            platform.system() + " " + platform.release())
    t.add_row("Architecture",        platform.machine())
    t.add_row("Current Time",        datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    console.print(t)
    console.input("\n  Press Enter to continue...")


def _view_config():
    console.clear()
    theme.section_header("CURRENT CONFIGURATION")

    cfg = config.get_all()
    t = Table(box=box.SIMPLE, header_style="bold cyan", border_style="dim cyan")
    t.add_column("Key",   style="cyan",       min_width=30)
    t.add_column("Value", style="bold white")

    def flatten(d, prefix=""):
        for k, v in d.items():
            full_key = f"{prefix}.{k}" if prefix else k
            if isinstance(v, dict):
                flatten(v, full_key)
            else:
                t.add_row(full_key, str(v))

    flatten(cfg)
    console.print(t)
    console.input("\n  Press Enter to continue...")


def _edit_config():
    console.clear()
    theme.section_header("EDIT CONFIGURATION")

    console.print("  [dim]Enter key in dot-notation (e.g. network.timeout)[/dim]\n")
    key   = Prompt.ask("  [cyan]Config key[/cyan]")
    current = config.get(key)
    console.print(f"  Current value: [bold white]{current}[/bold white]")
    value = Prompt.ask("  [cyan]New value[/cyan]", default=str(current) if current else "")

    # Try to convert to appropriate type
    if value.isdigit():
        value = int(value)
    elif value.lower() in ("true", "false"):
        value = value.lower() == "true"

    config.set(key, value)
    theme.success(f"Set {key} = {value}")
    console.input("  Press Enter to continue...")


def _reset_config():
    if Confirm.ask("  [yellow]Reset all settings to defaults?[/yellow]"):
        config.reset()
        theme.success("Configuration reset to defaults.")
    console.input("  Press Enter to continue...")


def _check_updates():
    console.clear()
    theme.section_header("UPDATE CHECK")
    console.print("  [cyan]Checking for updates...[/cyan]\n")

    result = check_for_updates()
    if result.get("error"):
        theme.warn(f"Could not check for updates: {result['error']}")
    elif result.get("update_available"):
        console.print(f"  [bold yellow]Update available![/bold yellow]")
        console.print(f"  Current: [bold white]{result['current']}[/bold white]")
        console.print(f"  Latest:  [bold cyan]{result['latest']}[/bold cyan]")
        console.print(f"  URL:     {result.get('url','')}")
        if result.get("notes"):
            console.print(f"\n  [dim]{result['notes']}[/dim]")
    else:
        theme.success(f"CyberMint is up to date (v{result.get('current','?')}).")

    console.input("\n  Press Enter to continue...")


def _db_stats():
    console.clear()
    theme.section_header("DATABASE STATS")

    from pathlib import Path
    import core.database as db

    db_path = Path("database/cybermint.db")
    t = Table(box=box.SIMPLE, header_style="bold cyan")
    t.add_column("Metric",  style="cyan",       min_width=25)
    t.add_column("Value",   style="bold white")

    if db_path.exists():
        size = db_path.stat().st_size
        t.add_row("Database Path",  str(db_path))
        t.add_row("Database Size",  f"{size:,} bytes")
        t.add_row("Projects",       str(len(db.get_projects())))
        t.add_row("Findings",       str(len(db.get_findings())))
        t.add_row("IOCs",           str(len(db.get_iocs())))
        t.add_row("Scan Records",   str(len(db.get_scan_history())))
    else:
        t.add_row("Status", "Database not found")

    console.print(t)
    console.input("\n  Press Enter to continue...")


def _clear_logs():
    from pathlib import Path
    log_dir = Path("database/logs")
    if not log_dir.exists():
        theme.warn("No log directory found.")
        console.input("  Press Enter...")
        return

    logs = list(log_dir.glob("*.log"))
    if not logs:
        theme.warn("No log files to clear.")
        console.input("  Press Enter...")
        return

    if Confirm.ask(f"  Delete {len(logs)} log file(s)?"):
        for f in logs:
            f.unlink()
        theme.success(f"Cleared {len(logs)} log file(s).")
    console.input("  Press Enter to continue...")
