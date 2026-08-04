"""
CyberMint Threat Intelligence Center
IOC management, hash records, domain/IP intelligence.
"""
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich import box

import core.database as db
from core.logger import get_logger
from ui.theme import theme

console = Console()
logger = get_logger("ThreatIntel")

IOC_TYPES = ["hash", "domain", "ip", "url", "email", "filename", "cve", "other"]
THREAT_LEVELS = ["critical", "high", "medium", "low", "unknown"]


def show_menu(current_project=None):
    while True:
        console.clear()
        theme.banner("THREAT INTELLIGENCE", "IOC Management & Research")

        options = [
            ("[01]", "Add IOC",              "Add Indicator of Compromise"),
            ("[02]", "Search IOCs",          "Search threat intelligence"),
            ("[03]", "IOC by Type",          "Filter IOCs by type"),
            ("[04]", "Threat Summary",       "Overview of threat data"),
            ("[05]", "Import IOC List",      "Bulk import from file"),
            ("[06]", "CVE Lookup",           "Search CVE database"),
            ("[07]", "Threat Notes",         "Research notes"),
            ("[00]", "Back to Main Menu",    ""),
        ]
        theme.menu_table(options)

        choice = Prompt.ask("\n  [cyan]>[/cyan] Select option", default="00")

        if choice == "00":
            break
        elif choice == "01":
            _add_ioc()
        elif choice == "02":
            query = Prompt.ask("  [cyan]Search query[/cyan]")
            _search_iocs(query)
        elif choice == "03":
            ioc_type = Prompt.ask("  [cyan]IOC type[/cyan]",
                                  choices=IOC_TYPES, default="domain")
            _iocs_by_type(ioc_type)
        elif choice == "04":
            _threat_summary()
        elif choice == "05":
            fp = Prompt.ask("  [cyan]File path (one IOC per line)[/cyan]")
            _import_iocs(fp)
        elif choice == "06":
            cve = Prompt.ask("  [cyan]CVE ID (e.g. CVE-2021-44228)[/cyan]")
            _cve_lookup(cve)
        elif choice == "07":
            _threat_notes(current_project)


def _add_ioc():
    console.clear()
    theme.section_header("ADD IOC")

    ioc_type = Prompt.ask("  [cyan]Type[/cyan]", choices=IOC_TYPES, default="domain")
    value    = Prompt.ask("  [cyan]Value[/cyan]")
    threat   = Prompt.ask("  [cyan]Threat level[/cyan]", choices=THREAT_LEVELS, default="unknown")
    desc     = Prompt.ask("  [cyan]Description[/cyan]", default="")
    source   = Prompt.ask("  [cyan]Source[/cyan]", default="manual")
    tags     = Prompt.ask("  [cyan]Tags (comma separated)[/cyan]", default="")

    db.add_ioc(ioc_type, value, threat, desc, source, tags)
    theme.success(f"IOC added: [{ioc_type}] {value}")
    console.input("  Press Enter to continue...")


def _search_iocs(query):
    console.clear()
    theme.section_header(f"IOC SEARCH — '{query}'")

    all_iocs = db.get_iocs()
    results  = [i for i in all_iocs
                if query.lower() in i["value"].lower()
                or query.lower() in (i.get("description") or "").lower()
                or query.lower() in (i.get("tags") or "").lower()]

    _render_ioc_table(results)
    console.input("\n  Press Enter to continue...")


def _iocs_by_type(ioc_type):
    console.clear()
    theme.section_header(f"IOCs — {ioc_type.upper()}")
    iocs = db.get_iocs(ioc_type)
    _render_ioc_table(iocs)
    console.input("\n  Press Enter to continue...")


def _render_ioc_table(iocs):
    if not iocs:
        theme.warn("No IOCs found.")
        return

    threat_colors = {
        "critical": "red", "high": "orange3",
        "medium":   "yellow", "low": "green", "unknown": "dim"
    }

    t = Table(box=box.SIMPLE, header_style="bold cyan", border_style="dim cyan")
    t.add_column("#",      width=4,  style="dim")
    t.add_column("Type",   width=10, style="cyan")
    t.add_column("Value",  style="bold white", min_width=30)
    t.add_column("Threat", width=10)
    t.add_column("Source", style="dim", width=12)
    t.add_column("Tags",   style="dim")

    for i, ioc in enumerate(iocs, 1):
        threat = ioc.get("threat_level", "unknown")
        color  = threat_colors.get(threat, "white")
        t.add_row(
            str(i),
            ioc["ioc_type"],
            ioc["value"][:50],
            f"[{color}]{threat.upper()}[/{color}]",
            (ioc.get("source") or "")[:12],
            (ioc.get("tags") or "")[:20],
        )
    console.print(t)
    console.print(f"\n  Total: [bold white]{len(iocs)}[/bold white] IOC(s)")


def _threat_summary():
    console.clear()
    theme.section_header("THREAT SUMMARY")

    all_iocs = db.get_iocs()

    by_type   = {}
    by_threat = {}
    for ioc in all_iocs:
        by_type[ioc["ioc_type"]]                   = by_type.get(ioc["ioc_type"], 0) + 1
        by_threat[ioc.get("threat_level","unknown")] = by_threat.get(ioc.get("threat_level","unknown"), 0) + 1

    console.print(Panel(
        f"  [bold cyan]Total IOCs:[/bold cyan]  {len(all_iocs)}\n\n"
        + "  [bold cyan]By Type:[/bold cyan]\n"
        + "".join(f"    {k:<15} {v}\n" for k, v in sorted(by_type.items(), key=lambda x: -x[1]))
        + "\n  [bold cyan]By Threat Level:[/bold cyan]\n"
        + "".join(f"    {k:<15} {v}\n" for k, v in sorted(by_threat.items(), key=lambda x: -x[1])),
        title="[bold cyan][ THREAT INTELLIGENCE SUMMARY ][/bold cyan]",
        border_style="cyan",
    ))
    console.input("  Press Enter to continue...")


def _import_iocs(filepath):
    console.clear()
    theme.section_header("IMPORT IOC LIST")

    from pathlib import Path
    p = Path(filepath)
    if not p.exists():
        theme.error("File not found.")
        console.input("  Press Enter...")
        return

    ioc_type = Prompt.ask("  [cyan]Default IOC type[/cyan]", choices=IOC_TYPES, default="domain")
    threat   = Prompt.ask("  [cyan]Default threat level[/cyan]", choices=THREAT_LEVELS, default="unknown")

    count = 0
    with open(filepath, "r") as f:
        for line in f:
            val = line.strip()
            if val and not val.startswith("#"):
                db.add_ioc(ioc_type, val, threat, "", "import", "")
                count += 1

    theme.success(f"Imported {count} IOC(s).")
    console.input("  Press Enter to continue...")


def _cve_lookup(cve_id):
    console.clear()
    theme.section_header(f"CVE LOOKUP — {cve_id}")

    import requests
    url = f"https://cve.circl.lu/api/cve/{cve_id}"
    try:
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            data = r.json()
            if not data:
                theme.warn("CVE not found in database.")
            else:
                t = Table(box=box.SIMPLE, header_style="bold cyan", border_style="dim cyan")
                t.add_column("Field",  style="cyan",       min_width=20)
                t.add_column("Value",  style="bold white", min_width=50)

                t.add_row("CVE ID",      data.get("id", cve_id))
                t.add_row("Published",   data.get("Published", "N/A"))
                t.add_row("Modified",    data.get("Modified", "N/A"))
                t.add_row("CVSS Score",  str(data.get("cvss", "N/A")))
                t.add_row("Summary",     (data.get("summary","") or "")[:200])

                refs = data.get("references", [])
                if refs:
                    t.add_row("References", str(len(refs)) + " links")

                console.print(t)
                theme.success("CVE data retrieved.")
        else:
            theme.error(f"HTTP {r.status_code}")
    except Exception as e:
        theme.error(f"CVE lookup failed: {e}")

    console.input("\n  Press Enter to continue...")


def _threat_notes(project=None):
    while True:
        console.clear()
        theme.section_header("THREAT NOTES")
        notes = db.get_notes(project["id"] if project else None)

        if notes:
            for n in notes:
                console.print(f"  [bold cyan]{n['title']}[/bold cyan]  [dim]{n['created_at'][:16]}[/dim]")
                console.print(f"    {n['content'][:120]}")
                if n.get("tags"):
                    console.print(f"    [dim]Tags: {n['tags']}[/dim]")
                console.print()
        else:
            theme.warn("No threat notes.")

        console.print("  [1] Add Note  [0] Back")
        choice = Prompt.ask("  [cyan]>[/cyan]", default="0")
        if choice == "0":
            break
        elif choice == "1":
            if not project:
                theme.warn("Select a project from Intelligence Center to attach notes.")
                console.input("  Press Enter...")
                continue
            title   = Prompt.ask("  Title")
            content = Prompt.ask("  Content")
            tags    = Prompt.ask("  Tags", default="threat-intel")
            db.add_note(project["id"], title, content, tags)
            theme.success("Note saved.")
            console.input("  Press Enter...")
