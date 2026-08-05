"""
CyberMint Security Analysis Center
Configuration checks, header analysis, vulnerability identification.
"""
import requests
import socket
import re
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt
from rich import box
from rich.progress import Progress, SpinnerColumn, TextColumn

import core.database as db
from core.logger import get_logger
from ui.theme import theme

console = Console()
logger = get_logger("Analysis")


SECURITY_CHECKS = {
    "HTTPS Enforcement": {
        "check": "https",
        "severity": "high",
        "description": "Site should enforce HTTPS",
        "recommendation": "Enable HTTPS and redirect all HTTP traffic to HTTPS.",
    },
    "HTTP Strict-Transport-Security": {
        "check": "hsts",
        "severity": "high",
        "description": "HSTS header missing",
        "recommendation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header.",
    },
    "Content-Security-Policy": {
        "check": "csp",
        "severity": "medium",
        "description": "CSP header missing — XSS risk",
        "recommendation": "Implement a Content-Security-Policy header to restrict allowed sources.",
    },
    "X-Frame-Options": {
        "check": "xfo",
        "severity": "medium",
        "description": "X-Frame-Options missing — clickjacking risk",
        "recommendation": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' header.",
    },
    "X-Content-Type-Options": {
        "check": "xcto",
        "severity": "low",
        "description": "X-Content-Type-Options missing",
        "recommendation": "Add 'X-Content-Type-Options: nosniff' header.",
    },
    "Referrer-Policy": {
        "check": "rp",
        "severity": "low",
        "description": "Referrer-Policy header missing",
        "recommendation": "Add 'Referrer-Policy: strict-origin-when-cross-origin' header.",
    },
    "Permissions-Policy": {
        "check": "pp",
        "severity": "low",
        "description": "Permissions-Policy header missing",
        "recommendation": "Add Permissions-Policy to restrict browser features.",
    },
    "Server Information Disclosure": {
        "check": "server_banner",
        "severity": "info",
        "description": "Server header reveals software version",
        "recommendation": "Configure server to hide version information in headers.",
    },
}


def show_menu(current_project=None):
    while True:
        console.clear()
        theme.banner("SECURITY ANALYSIS", "Configuration & Vulnerability Assessment")

        options = [
            ("[01]", "HTTP Security Headers", "Analyze response headers"),
            ("[02]", "Configuration Check",   "Full configuration audit"),
            ("[03]", "Risk Classification",   "Classify finding risk level"),
            ("[04]", "Add Manual Finding",    "Record a manual finding"),
            ("[05]", "View All Findings",     "Browse project findings"),
            ("[06]", "OWASP Quick Checklist", "OWASP Top 10 checklist"),
            ("[00]", "Back to Main Menu",     ""),
        ]
        theme.menu_table(options)

        if current_project:
            console.print(f"\n  [cyan]Active Project:[/cyan] [bold white]{current_project['name']}[/bold white]")

        choice = theme.get_choice()

        if choice == "00":
            break
        elif choice == "01":
            target = Prompt.ask("  [cyan]Enter URL or domain[/cyan]")
            _header_analysis(target, current_project)
        elif choice == "02":
            target = Prompt.ask("  [cyan]Enter URL or domain[/cyan]")
            _full_config_check(target, current_project)
        elif choice == "03":
            if current_project:
                _risk_classification(current_project)
            else:
                theme.warn("Select a project first.")
                console.input("  Press Enter...")
        elif choice == "04":
            if current_project:
                _add_manual_finding(current_project)
            else:
                theme.warn("Select a project first.")
                console.input("  Press Enter...")
        elif choice == "05":
            if current_project:
                _view_findings(current_project)
            else:
                theme.warn("Select a project first.")
                console.input("  Press Enter...")
        elif choice == "06":
            _owasp_checklist(current_project)


def _header_analysis(target, project=None):
    console.clear()
    if not target.startswith("http"):
        target = "https://" + target
    theme.section_header(f"HEADER ANALYSIS — {target}")

    findings_found = []
    try:
        with Progress(SpinnerColumn(), TextColumn("[cyan]Fetching headers..."), transient=True) as p:
            p.add_task("")
            r = requests.get(target, timeout=10, allow_redirects=True,
                             headers={"User-Agent": "CyberMint/1.0"})

        headers = {k.lower(): v for k, v in r.headers.items()}
        checks = {
            "hsts":        ("strict-transport-security", "present"),
            "csp":         ("content-security-policy",   "present"),
            "xfo":         ("x-frame-options",           "present"),
            "xcto":        ("x-content-type-options",    "present"),
            "rp":          ("referrer-policy",           "present"),
            "pp":          ("permissions-policy",        "present"),
            "server_banner": ("server",                  "absent"),
        }

        t = Table(box=box.SIMPLE, header_style="bold cyan", border_style="dim cyan")
        t.add_column("Check",          style="bold white", min_width=30)
        t.add_column("Severity",       width=10)
        t.add_column("Status",         width=10)
        t.add_column("Value/Note",     style="dim", min_width=30)

        sev_color = {"high": "red", "medium": "yellow", "low": "green", "info": "cyan"}

        for name, info in SECURITY_CHECKS.items():
            check_key = info["check"]
            severity  = info["severity"]
            color     = sev_color.get(severity, "white")

            if check_key == "https":
                passed = r.url.startswith("https://")
                status = "[green]PASS[/green]" if passed else "[red]FAIL[/red]"
                note   = "HTTPS enforced" if passed else "Not using HTTPS"
            elif check_key in checks:
                hdr, rule = checks[check_key]
                val = headers.get(hdr, "")
                if rule == "present":
                    passed = bool(val)
                    status = "[green]PASS[/green]" if passed else "[red]FAIL[/red]"
                    note   = val[:60] if val else "Header missing"
                else:  # absent — should not be revealing
                    passed = not bool(val)
                    status = "[green]PASS[/green]" if passed else "[yellow]INFO[/yellow]"
                    note   = f"Reveals: {val[:40]}" if val else "Not disclosed"
            else:
                continue

            t.add_row(name, f"[{color}]{severity.upper()}[/{color}]", status, note)

            if not passed and check_key != "https":
                findings_found.append({
                    "title":          f"Missing: {name}",
                    "description":    info["description"],
                    "severity":       severity,
                    "category":       "Headers",
                    "target":         target,
                    "recommendation": info["recommendation"],
                })

        console.print(t)
        console.print(f"\n  [cyan]Status Code:[/cyan] {r.status_code}  |  [cyan]Final URL:[/cyan] {r.url}")

        if findings_found and project:
            if Prompt.ask(f"\n  Save {len(findings_found)} finding(s) to project?",
                          choices=["y","n"], default="y") == "y":
                for f in findings_found:
                    db.add_finding(project["id"], **f)
                theme.success(f"{len(findings_found)} findings saved.")

    except requests.exceptions.ConnectionError:
        theme.error("Could not connect to target.")
    except Exception as e:
        theme.error(f"Analysis failed: {e}")

    console.input("\n  Press Enter to continue...")


def _full_config_check(target, project=None):
    console.clear()
    if not target.startswith("http"):
        target = "https://" + target
    theme.section_header(f"FULL CONFIGURATION CHECK — {target}")

    _header_analysis(target, project)

    # Additional checks
    console.print("\n  [bold cyan]Additional Checks:[/bold cyan]")
    _check_redirect(target)
    _check_robots_sitemap(target, project)


def _check_redirect(target):
    http_url = target.replace("https://", "http://")
    try:
        r = requests.get(http_url, timeout=8, allow_redirects=False,
                         headers={"User-Agent": "CyberMint/1.0"})
        if r.status_code in (301, 302, 308) and "https" in r.headers.get("Location", "").lower():
            console.print("  [green]✓[/green] HTTP → HTTPS redirect in place.")
        else:
            console.print("  [yellow]⚠[/yellow] HTTP → HTTPS redirect not detected.")
    except Exception:
        pass


def _check_robots_sitemap(target, project=None):
    base = target.rstrip("/")
    for path in ["/robots.txt", "/sitemap.xml", "/.well-known/security.txt"]:
        try:
            r = requests.get(base + path, timeout=5,
                             headers={"User-Agent": "CyberMint/1.0"})
            icon = "[green]✓[/green]" if r.status_code == 200 else "[dim]✗[/dim]"
            console.print(f"  {icon} {path}  [{r.status_code}]")
        except Exception:
            console.print(f"  [dim]✗[/dim] {path}  [error]")

    console.input("\n  Press Enter to continue...")


def _add_manual_finding(project):
    console.clear()
    theme.section_header("ADD MANUAL FINDING")

    title  = Prompt.ask("  [cyan]Finding title[/cyan]")
    sev    = Prompt.ask("  [cyan]Severity[/cyan]", choices=["critical","high","medium","low","info"], default="medium")
    desc   = Prompt.ask("  [cyan]Description[/cyan]", default="")
    cat    = Prompt.ask("  [cyan]Category[/cyan]", default="Manual")
    target = Prompt.ask("  [cyan]Target[/cyan]", default="")
    rec    = Prompt.ask("  [cyan]Recommendation[/cyan]", default="")

    db.add_finding(project["id"], title, desc, sev, cat, target, rec)
    theme.success("Finding saved.")
    console.input("  Press Enter to continue...")


def _view_findings(project):
    console.clear()
    theme.section_header(f"FINDINGS — {project['name']}")
    findings = db.get_findings(project["id"])
    if not findings:
        theme.warn("No findings recorded.")
        console.input("  Press Enter...")
        return

    sev_order  = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sev_colors = {"critical":"red","high":"orange3","medium":"yellow","low":"green","info":"cyan"}
    findings.sort(key=lambda x: sev_order.get(x["severity"].lower(), 99))

    for f in findings:
        sev   = f["severity"].lower()
        color = sev_colors.get(sev, "white")
        console.print(Panel(
            f"  [bold white]{f['title']}[/bold white]\n"
            f"  [dim]Category:[/dim] {f.get('category','N/A')}   "
            f"[dim]Target:[/dim] {f.get('target','N/A')}\n"
            f"  [dim]Description:[/dim] {f.get('description','')}\n"
            f"  [dim]Recommendation:[/dim] {f.get('recommendation','')}",
            title=f"[{color}]{sev.upper()}[/{color}]",
            border_style=color,
            padding=(0, 1),
        ))

    console.input("\n  Press Enter to continue...")


def _risk_classification(project):
    console.clear()
    theme.section_header("RISK CLASSIFICATION")

    findings = db.get_findings(project["id"])
    sev_counts = {}
    for f in findings:
        s = f["severity"].lower()
        sev_counts[s] = sev_counts.get(s, 0) + 1

    t = Table(box=box.SIMPLE, header_style="bold cyan")
    t.add_column("Severity", style="bold")
    t.add_column("Count",    justify="center")
    t.add_column("Risk Weight")

    weights = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}
    colors  = {"critical":"red","high":"orange3","medium":"yellow","low":"green","info":"cyan"}
    total_weight = 0

    for sev in ["critical","high","medium","low","info"]:
        cnt = sev_counts.get(sev, 0)
        w   = weights[sev] * cnt
        total_weight += w
        color = colors[sev]
        t.add_row(f"[{color}]{sev.upper()}[/{color}]", str(cnt), str(w))

    console.print(t)
    score = max(0, 100 - total_weight)
    color = "green" if score >= 70 else "yellow" if score >= 40 else "red"
    console.print(f"\n  [bold cyan]Security Score:[/bold cyan] [{color}]{score}/100[/{color}]")
    console.input("\n  Press Enter to continue...")


def _owasp_checklist(project=None):
    console.clear()
    theme.section_header("OWASP TOP 10 CHECKLIST")

    owasp = [
        ("A01:2021", "Broken Access Control",              "Verify authorization on all endpoints"),
        ("A02:2021", "Cryptographic Failures",             "Check data-in-transit & at-rest encryption"),
        ("A03:2021", "Injection",                          "Test SQL, LDAP, OS command injection"),
        ("A04:2021", "Insecure Design",                    "Review threat modeling and design patterns"),
        ("A05:2021", "Security Misconfiguration",          "Audit default configs, error messages, headers"),
        ("A06:2021", "Vulnerable & Outdated Components",   "Scan dependencies for known CVEs"),
        ("A07:2021", "Identification & Auth Failures",     "Review auth, session, MFA implementation"),
        ("A08:2021", "Software & Data Integrity Failures", "Verify CI/CD pipeline and update integrity"),
        ("A09:2021", "Security Logging & Monitoring",      "Ensure sufficient logging and alerting"),
        ("A10:2021", "Server-Side Request Forgery",        "Test SSRF in all URL-fetching functionality"),
    ]

    t = Table(box=box.SIMPLE, header_style="bold cyan", border_style="dim cyan")
    t.add_column("ID",        style="cyan",       width=12)
    t.add_column("Category",  style="bold white", min_width=30)
    t.add_column("Check",     style="dim",        min_width=40)
    t.add_column("Status",    width=10)

    for oid, cat, check in owasp:
        t.add_row(oid, cat, check, "[dim][ ][/dim]")

    console.print(t)
    console.print("\n  [dim]Mark items as reviewed in your project findings.[/dim]")
    console.input("\n  Press Enter to continue...")
