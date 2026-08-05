"""
CyberMint Intelligence Center
Organize and understand collected security information.
"""
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich import box

import core.database as db
from core.logger import get_logger
from ui.theme import theme

console = Console()
logger = get_logger("Intelligence")


def show_menu(current_project=None):
    while True:
        console.clear()
        theme.banner("INTELLIGENCE CENTER", "Asset Intelligence & Risk Analysis")

        options = [
            ("[01]", "View All Projects",       "List and select projects"),
            ("[02]", "Create New Project",       "Start a new security project"),
            ("[03]", "Project Dashboard",        "Overview of current project"),
            ("[04]", "Asset Registry",           "Manage project assets"),
            ("[05]", "Risk Scoring",             "View and update risk scores"),
            ("[06]", "Findings Overview",        "Browse findings by severity"),
            ("[07]", "Notes Manager",            "Add and view notes"),
            ("[08]", "Correlation View",         "Correlate findings & assets"),
            ("[09]", "Delete Project",           "Remove a project"),
            ("[00]", "Back to Main Menu",        ""),
        ]
        theme.menu_table(options)

        if current_project:
            console.print(f"\n  [cyan]Active Project:[/cyan] [bold white]{current_project['name']}[/bold white]  "
                          f"[dim]Target: {current_project.get('target', 'N/A')}[/dim]")

        choice = theme.get_choice()

        if choice == "00":
            break
        elif choice == "01":
            current_project = _view_projects()
        elif choice == "02":
            current_project = _create_project() or current_project
        elif choice == "03":
            if current_project:
                _project_dashboard(current_project)
            else:
                theme.warn("No project selected. Create or select one first.")
                console.input("  Press Enter to continue...")
        elif choice == "04":
            if current_project:
                _asset_registry(current_project)
            else:
                theme.warn("Select a project first.")
                console.input("  Press Enter to continue...")
        elif choice == "05":
            if current_project:
                _risk_scoring(current_project)
            else:
                theme.warn("Select a project first.")
                console.input("  Press Enter to continue...")
        elif choice == "06":
            if current_project:
                _findings_overview(current_project)
            else:
                theme.warn("Select a project first.")
                console.input("  Press Enter to continue...")
        elif choice == "07":
            if current_project:
                _notes_manager(current_project)
            else:
                theme.warn("Select a project first.")
                console.input("  Press Enter to continue...")
        elif choice == "08":
            if current_project:
                _correlation_view(current_project)
            else:
                theme.warn("Select a project first.")
                console.input("  Press Enter to continue...")
        elif choice == "09":
            if current_project:
                _delete_project(current_project)
                current_project = None
            else:
                theme.warn("Select a project first.")
                console.input("  Press Enter to continue...")


def _view_projects():
    console.clear()
    theme.section_header("ALL PROJECTS")
    projects = db.get_projects()
    if not projects:
        theme.warn("No projects found. Create one first.")
        console.input("  Press Enter to continue...")
        return None

    t = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan",
              border_style="dim cyan")
    t.add_column("#",       style="dim", width=4)
    t.add_column("Name",    style="bold white", min_width=20)
    t.add_column("Target",  style="cyan")
    t.add_column("Status",  style="green")
    t.add_column("Score",   justify="center")
    t.add_column("Created", style="dim")

    for i, p in enumerate(projects, 1):
        score = p.get("security_score", 0)
        score_color = "green" if score >= 70 else "yellow" if score >= 40 else "red"
        t.add_row(
            str(i),
            p["name"],
            p.get("target", "N/A"),
            p.get("status", "active"),
            f"[{score_color}]{score}/100[/{score_color}]",
            p["created_at"][:10],
        )
    console.print(t)

    choice = Prompt.ask("\n  [cyan]>[/cyan] Enter project number to select (or 0 to cancel)", default="0")
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(projects):
            theme.success(f"Selected project: {projects[idx]['name']}")
            console.input("  Press Enter to continue...")
            return projects[idx]
    except ValueError:
        pass
    return None


def _create_project():
    console.clear()
    theme.section_header("CREATE NEW PROJECT")
    name   = Prompt.ask("  [cyan]Project name[/cyan]")
    target = Prompt.ask("  [cyan]Target[/cyan] (domain/IP/system)", default="")
    desc   = Prompt.ask("  [cyan]Description[/cyan]", default="")

    ok, msg = db.create_project(name, desc, target)
    if ok:
        theme.success(msg)
        projects = db.get_projects()
        proj = next((p for p in projects if p["name"] == name), None)
        console.input("  Press Enter to continue...")
        return proj
    else:
        theme.error(msg)
        console.input("  Press Enter to continue...")
        return None


def _project_dashboard(project):
    console.clear()
    theme.section_header(f"PROJECT DASHBOARD — {project['name']}")

    findings = db.get_findings(project["id"])
    assets   = db.get_assets(project["id"])
    notes    = db.get_notes(project["id"])
    scans    = db.get_scan_history(project["id"], limit=5)

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "info").lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    score = project.get("security_score", 0)
    score_color = "green" if score >= 70 else "yellow" if score >= 40 else "red"

    overview = Panel(
        f"""  [bold cyan]Project:[/bold cyan]     {project['name']}
  [bold cyan]Target:[/bold cyan]      {project.get('target', 'N/A')}
  [bold cyan]Status:[/bold cyan]      {project.get('status', 'active')}
  [bold cyan]Risk Level:[/bold cyan]  {project.get('risk_level', 'unknown').upper()}
  [bold cyan]Score:[/bold cyan]       [{score_color}]{score}/100[/{score_color}]
  [bold cyan]Description:[/bold cyan] {project.get('description', 'N/A')}
  [bold cyan]Created:[/bold cyan]     {project['created_at'][:19]}""",
        title="[bold cyan][ PROJECT OVERVIEW ][/bold cyan]",
        border_style="cyan",
    )
    console.print(overview)

    # Stats row
    stats = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    stats.add_column("Label", style="dim")
    stats.add_column("Value", style="bold white")
    stats.add_row("Total Findings", str(len(findings)))
    stats.add_row("  Critical",     f"[red]{severity_counts['critical']}[/red]")
    stats.add_row("  High",         f"[orange3]{severity_counts['high']}[/orange3]")
    stats.add_row("  Medium",       f"[yellow]{severity_counts['medium']}[/yellow]")
    stats.add_row("  Low",          f"[green]{severity_counts['low']}[/green]")
    stats.add_row("Assets",         str(len(assets)))
    stats.add_row("Notes",          str(len(notes)))
    stats.add_row("Scans Run",      str(len(db.get_scan_history(project["id"], limit=1000))))
    console.print(stats)

    if scans:
        console.print("\n  [bold cyan]Recent Scans:[/bold cyan]")
        for s in scans:
            console.print(f"  [dim]{s['created_at'][:16]}[/dim]  [cyan]{s['module']}[/cyan]  {s['result_summary']}")

    console.input("\n  Press Enter to continue...")


def _asset_registry(project):
    while True:
        console.clear()
        theme.section_header(f"ASSET REGISTRY — {project['name']}")
        assets = db.get_assets(project["id"])

        if assets:
            t = Table(box=box.SIMPLE, header_style="bold cyan", border_style="dim cyan")
            t.add_column("#",    width=4, style="dim")
            t.add_column("Name", style="bold white", min_width=20)
            t.add_column("Type", style="cyan")
            t.add_column("Value")
            t.add_column("Notes", style="dim")
            for i, a in enumerate(assets, 1):
                t.add_row(str(i), a["name"], a.get("asset_type",""), a.get("value",""), (a.get("notes","") or "")[:40])
            console.print(t)
        else:
            theme.warn("No assets registered yet.")

        console.print("\n  [1] Add Asset  [0] Back")
        choice = Prompt.ask("  [cyan]>[/cyan]", default="0")
        if choice == "0":
            break
        elif choice == "1":
            name  = Prompt.ask("  Asset name")
            atype = Prompt.ask("  Type (domain/IP/service/file)", default="domain")
            value = Prompt.ask("  Value", default="")
            notes = Prompt.ask("  Notes", default="")
            db.add_asset(project["id"], name, atype, value, notes=notes)
            theme.success("Asset added.")
            console.input("  Press Enter...")


def _risk_scoring(project):
    console.clear()
    theme.section_header(f"RISK SCORING — {project['name']}")
    findings = db.get_findings(project["id"])

    weights = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}
    deduction = sum(weights.get(f["severity"].lower(), 0) for f in findings)
    score = max(0, 100 - deduction)

    db.update_project(project["id"], security_score=score)
    project["security_score"] = score

    sev_counts = {}
    for f in findings:
        s = f["severity"].lower()
        sev_counts[s] = sev_counts.get(s, 0) + 1

    color = "green" if score >= 70 else "yellow" if score >= 40 else "red"
    console.print(Panel(
        f"  [bold cyan]Security Score:[/bold cyan] [{color}]{score}/100[/{color}]\n\n"
        + "  Severity Breakdown:\n"
        + "".join(f"    {k.capitalize()}: {v}\n" for k, v in sev_counts.items()),
        title="[bold cyan][ RISK SCORE ][/bold cyan]",
        border_style="cyan",
    ))

    rl = Prompt.ask("  [cyan]Set risk level[/cyan]", choices=["critical","high","medium","low","unknown"], default=project.get("risk_level","unknown"))
    db.update_project(project["id"], risk_level=rl)
    theme.success(f"Risk level set to: {rl}")
    console.input("  Press Enter to continue...")


def _findings_overview(project):
    console.clear()
    theme.section_header(f"FINDINGS — {project['name']}")
    findings = db.get_findings(project["id"])
    if not findings:
        theme.warn("No findings recorded.")
        console.input("  Press Enter...")
        return

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda x: severity_order.get(x["severity"].lower(), 99))

    sev_colors = {"critical":"red","high":"orange3","medium":"yellow","low":"green","info":"cyan"}
    t = Table(box=box.SIMPLE, header_style="bold cyan", border_style="dim cyan")
    t.add_column("#",          width=4, style="dim")
    t.add_column("Severity",   width=10)
    t.add_column("Title",      style="bold white", min_width=30)
    t.add_column("Category",   style="cyan")
    t.add_column("Status")
    t.add_column("Date", style="dim")
    for i, f in enumerate(findings, 1):
        sev = f["severity"].lower()
        color = sev_colors.get(sev, "white")
        t.add_row(str(i), f"[{color}]{sev.upper()}[/{color}]", f["title"],
                  f.get("category",""), f.get("status","open"), f["created_at"][:10])
    console.print(t)
    console.input("\n  Press Enter to continue...")


def _notes_manager(project):
    while True:
        console.clear()
        theme.section_header(f"NOTES — {project['name']}")
        notes = db.get_notes(project["id"])
        if notes:
            for n in notes:
                console.print(f"  [bold cyan]{n['title']}[/bold cyan]  [dim]{n['created_at'][:16]}[/dim]")
                console.print(f"    {n['content'][:100]}")
                console.print()
        else:
            theme.warn("No notes yet.")

        console.print("  [1] Add Note  [0] Back")
        choice = Prompt.ask("  [cyan]>[/cyan]", default="0")
        if choice == "0":
            break
        elif choice == "1":
            title   = Prompt.ask("  Title")
            content = Prompt.ask("  Content")
            tags    = Prompt.ask("  Tags (comma separated)", default="")
            db.add_note(project["id"], title, content, tags)
            theme.success("Note saved.")
            console.input("  Press Enter...")


def _correlation_view(project):
    console.clear()
    theme.section_header(f"CORRELATION VIEW — {project['name']}")
    assets   = db.get_assets(project["id"])
    findings = db.get_findings(project["id"])

    console.print(f"\n  Assets: [bold white]{len(assets)}[/bold white]   Findings: [bold white]{len(findings)}[/bold white]\n")

    for asset in assets[:10]:
        related = [f for f in findings if asset["name"].lower() in (f.get("target","") or "").lower()
                   or asset["value"] in (f.get("target","") or "")]
        console.print(f"  [cyan]▸[/cyan] [bold white]{asset['name']}[/bold white]  [dim]{asset.get('asset_type','')}[/dim]")
        if related:
            for r in related:
                console.print(f"      └── [{r['severity']}] {r['title']}")
        else:
            console.print("      └── No findings linked")
        console.print()

    console.input("  Press Enter to continue...")


def _delete_project(project):
    if Confirm.ask(f"  [red]Delete project '{project['name']}'? This is irreversible.[/red]"):
        db.delete_project(project["id"])
        theme.success("Project deleted.")
        console.input("  Press Enter to continue...")
