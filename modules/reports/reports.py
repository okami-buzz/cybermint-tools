"""
CyberMint Report Center
Professional security reporting with export support.
"""
import os
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt
from rich import box

import core.database as db
from core.logger import get_logger
from ui.theme import theme

console = Console()
logger = get_logger("Reports")

REPORTS_DIR = Path("reports")


def show_menu(current_project=None):
    while True:
        console.clear()
        theme.banner("REPORT CENTER", "Professional Security Reports")

        options = [
            ("[01]", "Generate Full Report",    "Complete project security report"),
            ("[02]", "Findings Summary",        "Findings by severity"),
            ("[03]", "Executive Summary",       "High-level risk overview"),
            ("[04]", "IOC Report",              "Threat intelligence report"),
            ("[05]", "Scan History Report",     "All scans for a project"),
            ("[06]", "View Saved Reports",      "Browse generated reports"),
            ("[07]", "Export Report",           "Export report to file"),
            ("[00]", "Back to Main Menu",       ""),
        ]
        theme.menu_table(options)

        if current_project:
            console.print(f"\n  [cyan]Active Project:[/cyan] [bold white]{current_project['name']}[/bold white]")

        choice = theme.get_choice()

        if choice == "00":
            break
        elif choice in ("01","02","03","04","05"):
            if not current_project:
                current_project = _select_project()
            if not current_project:
                continue
            if choice == "01":
                _full_report(current_project)
            elif choice == "02":
                _findings_summary(current_project)
            elif choice == "03":
                _executive_summary(current_project)
            elif choice == "04":
                _ioc_report(current_project)
            elif choice == "05":
                _scan_history_report(current_project)
        elif choice == "06":
            _view_saved(current_project)
        elif choice == "07":
            if current_project:
                _export_report(current_project)
            else:
                theme.warn("Select a project first.")
                console.input("  Press Enter...")


def _select_project():
    projects = db.get_projects()
    if not projects:
        theme.warn("No projects found.")
        console.input("  Press Enter...")
        return None
    console.print("\n  [bold cyan]Select a project:[/bold cyan]")
    for i, p in enumerate(projects, 1):
        console.print(f"  [{i}] {p['name']}")
    choice = Prompt.ask("  [cyan]>[/cyan]", default="1")
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(projects):
            return projects[idx]
    except ValueError:
        pass
    return None


def _build_full_report(project) -> str:
    pid = project["id"]
    findings  = db.get_findings(pid)
    assets    = db.get_assets(pid)
    scans     = db.get_scan_history(pid)
    notes     = db.get_notes(pid)
    iocs      = db.get_iocs()

    sev_counts = {"critical":0,"high":0,"medium":0,"low":0,"info":0}
    for f in findings:
        sev_counts[f["severity"].lower()] = sev_counts.get(f["severity"].lower(), 0) + 1

    score = project.get("security_score", 0)
    lines = [
        "=" * 70,
        "  CYBERMINT SECURITY REPORT",
        "=" * 70,
        f"  Project:      {project['name']}",
        f"  Target:       {project.get('target','N/A')}",
        f"  Status:       {project.get('status','active')}",
        f"  Risk Level:   {project.get('risk_level','unknown').upper()}",
        f"  Score:        {score}/100",
        f"  Generated:    {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"  Description:  {project.get('description','')}",
        "",
        "─" * 70,
        "  EXECUTIVE SUMMARY",
        "─" * 70,
        f"  Total Findings:  {len(findings)}",
        f"  Critical:        {sev_counts['critical']}",
        f"  High:            {sev_counts['high']}",
        f"  Medium:          {sev_counts['medium']}",
        f"  Low:             {sev_counts['low']}",
        f"  Info:            {sev_counts['info']}",
        f"  Total Assets:    {len(assets)}",
        f"  Scans Run:       {len(scans)}",
        "",
    ]

    if findings:
        lines += [
            "─" * 70,
            "  FINDINGS",
            "─" * 70,
        ]
        order = {"critical":0,"high":1,"medium":2,"low":3,"info":4}
        findings.sort(key=lambda x: order.get(x["severity"].lower(), 99))
        for f in findings:
            lines += [
                f"",
                f"  [{f['severity'].upper()}] {f['title']}",
                f"  Category:       {f.get('category','N/A')}",
                f"  Target:         {f.get('target','N/A')}",
                f"  Description:    {f.get('description','')}",
                f"  Recommendation: {f.get('recommendation','')}",
                f"  Status:         {f.get('status','open')}",
                f"  Date:           {f['created_at'][:10]}",
            ]

    if assets:
        lines += [
            "",
            "─" * 70,
            "  ASSETS",
            "─" * 70,
        ]
        for a in assets:
            lines.append(f"  • [{a.get('asset_type','')}] {a['name']}  {a.get('value','')}")

    lines += [
        "",
        "─" * 70,
        "  RECOMMENDATIONS",
        "─" * 70,
    ]
    recs = [f for f in findings if f.get("recommendation")]
    if recs:
        for f in recs:
            lines.append(f"  • [{f['severity'].upper()}] {f['recommendation']}")
    else:
        lines.append("  No specific recommendations recorded.")

    lines += [
        "",
        "=" * 70,
        "  Report generated by CyberMint v1.0.0",
        "=" * 70,
    ]

    return "\n".join(lines)


def _full_report(project):
    console.clear()
    theme.section_header(f"FULL REPORT — {project['name']}")

    report_text = _build_full_report(project)
    console.print(report_text)

    REPORTS_DIR.mkdir(exist_ok=True)
    filename = REPORTS_DIR / f"{project['name'].replace(' ','_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(filename, "w") as f:
        f.write(report_text)

    db.save_report(project["id"], f"Full Report — {project['name']}",
                   "full", report_text, str(filename))
    theme.success(f"Report saved: {filename}")
    console.input("\n  Press Enter to continue...")


def _findings_summary(project):
    console.clear()
    theme.section_header(f"FINDINGS SUMMARY — {project['name']}")

    findings = db.get_findings(project["id"])
    if not findings:
        theme.warn("No findings.")
        console.input("  Press Enter...")
        return

    sev_colors = {"critical":"red","high":"orange3","medium":"yellow","low":"green","info":"cyan"}
    order      = {"critical":0,"high":1,"medium":2,"low":3,"info":4}
    findings.sort(key=lambda x: order.get(x["severity"].lower(), 99))

    t = Table(box=box.SIMPLE, header_style="bold cyan", border_style="dim cyan")
    t.add_column("#",      width=4, style="dim")
    t.add_column("Sev",    width=10)
    t.add_column("Title",  style="bold white", min_width=35)
    t.add_column("Cat",    style="cyan",       min_width=12)
    t.add_column("Target", min_width=20)
    t.add_column("Date",   style="dim", width=11)

    for i, f in enumerate(findings, 1):
        sev   = f["severity"].lower()
        color = sev_colors.get(sev,"white")
        t.add_row(str(i), f"[{color}]{sev.upper()}[/{color}]",
                  f["title"], f.get("category",""), f.get("target",""), f["created_at"][:10])
    console.print(t)
    console.input("\n  Press Enter to continue...")


def _executive_summary(project):
    console.clear()
    theme.section_header(f"EXECUTIVE SUMMARY — {project['name']}")

    findings = db.get_findings(project["id"])
    sev      = {"critical":0,"high":0,"medium":0,"low":0,"info":0}
    for f in findings:
        sev[f["severity"].lower()] = sev.get(f["severity"].lower(), 0) + 1

    score = project.get("security_score", 0)
    color = "green" if score >= 70 else "yellow" if score >= 40 else "red"
    risk  = project.get("risk_level","unknown").upper()

    summary = Panel(
        f"""  [bold cyan]Project:[/bold cyan]      {project['name']}
  [bold cyan]Target:[/bold cyan]       {project.get('target','N/A')}
  [bold cyan]Risk Level:[/bold cyan]   {risk}
  [bold cyan]Score:[/bold cyan]        [{color}]{score}/100[/{color}]

  [bold cyan]Finding Summary:[/bold cyan]
    Critical:  [red]{sev['critical']}[/red]
    High:      [orange3]{sev['high']}[/orange3]
    Medium:    [yellow]{sev['medium']}[/yellow]
    Low:       [green]{sev['low']}[/green]
    Info:      [cyan]{sev['info']}[/cyan]

  [bold cyan]Overall Status:[/bold cyan]  {'[red]NEEDS ATTENTION[/red]' if sev['critical']+sev['high']>0 else '[green]ACCEPTABLE[/green]'}""",
        title="[bold cyan][ EXECUTIVE SUMMARY ][/bold cyan]",
        border_style="cyan",
    )
    console.print(summary)
    console.input("\n  Press Enter to continue...")


def _ioc_report(project):
    console.clear()
    theme.section_header("IOC REPORT")
    iocs = db.get_iocs()
    if not iocs:
        theme.warn("No IOCs recorded.")
        console.input("  Press Enter...")
        return

    by_type = {}
    for i in iocs:
        by_type.setdefault(i["ioc_type"], []).append(i)

    for ioc_type, items in by_type.items():
        console.print(f"\n  [bold cyan]{ioc_type.upper()} ({len(items)})[/bold cyan]")
        for item in items[:10]:
            console.print(f"  • [{item.get('threat_level','?')}] {item['value'][:60]}")
        if len(items) > 10:
            console.print(f"  [dim]  ... {len(items)-10} more[/dim]")

    console.input("\n  Press Enter to continue...")


def _scan_history_report(project):
    console.clear()
    theme.section_header(f"SCAN HISTORY — {project['name']}")
    scans = db.get_scan_history(project["id"], limit=50)
    if not scans:
        theme.warn("No scans.")
        console.input("  Press Enter...")
        return

    t = Table(box=box.SIMPLE, header_style="bold cyan")
    t.add_column("Date",    style="dim",        width=17)
    t.add_column("Module",  style="cyan",       width=15)
    t.add_column("Target",  style="bold white", width=25)
    t.add_column("Summary")
    for s in scans:
        t.add_row(s["created_at"][:16], s["module"], s.get("target",""), s.get("result_summary",""))
    console.print(t)
    console.input("\n  Press Enter to continue...")


def _view_saved(project=None):
    console.clear()
    theme.section_header("SAVED REPORTS")
    reports = db.get_reports(project["id"] if project else None)
    if not reports:
        theme.warn("No saved reports.")
        console.input("  Press Enter...")
        return

    t = Table(box=box.SIMPLE, header_style="bold cyan")
    t.add_column("#",    width=4, style="dim")
    t.add_column("Title", style="bold white", min_width=35)
    t.add_column("Type",  style="cyan",       width=12)
    t.add_column("File",  style="dim")
    t.add_column("Date",  style="dim", width=11)
    for i, r in enumerate(reports, 1):
        t.add_row(str(i), r["title"], r.get("report_type",""), r.get("file_path","")[:40], r["created_at"][:10])
    console.print(t)
    console.input("\n  Press Enter to continue...")


def _export_report(project):
    console.clear()
    theme.section_header("EXPORT REPORT")
    fmt = Prompt.ask("  [cyan]Format[/cyan]", choices=["txt","md"], default="txt")

    report_text = _build_full_report(project)
    REPORTS_DIR.mkdir(exist_ok=True)
    filename = REPORTS_DIR / f"{project['name'].replace(' ','_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{fmt}"

    if fmt == "md":
        report_text = report_text.replace("=" * 70, "---").replace("─" * 70, "---")

    with open(filename, "w") as f:
        f.write(report_text)

    theme.success(f"Report exported: {filename}")
    console.input("  Press Enter to continue...")
