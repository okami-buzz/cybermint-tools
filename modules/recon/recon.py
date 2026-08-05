"""
CyberMint Recon Center
Information gathering: DNS, WHOIS, certificates, technology detection.
"""
import socket
import ssl
import json
from datetime import datetime

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
logger = get_logger("Recon")


def show_menu(current_project=None):
    while True:
        console.clear()
        theme.banner("RECON CENTER", "Information Gathering & Footprinting")

        options = [
            ("[01]", "Domain WHOIS",        "WHOIS lookup for a domain"),
            ("[02]", "DNS Intelligence",    "DNS record enumeration"),
            ("[03]", "SSL/TLS Certificate", "Certificate information"),
            ("[04]", "Port Scanner",        "Basic TCP port scan"),
            ("[05]", "Technology Detection","HTTP headers & tech stack"),
            ("[06]", "Full Recon Profile",  "Run all recon on a target"),
            ("[07]", "Scan History",        "View previous scans"),
            ("[00]", "Back to Main Menu",   ""),
        ]
        theme.menu_table(options)

        if current_project:
            console.print(f"\n  [cyan]Active Project:[/cyan] [bold white]{current_project['name']}[/bold white]")

        choice = theme.get_choice()

        if choice == "00":
            break
        elif choice == "01":
            target = Prompt.ask("  [cyan]Enter domain[/cyan]")
            _whois_lookup(target, current_project)
        elif choice == "02":
            target = Prompt.ask("  [cyan]Enter domain[/cyan]")
            _dns_lookup(target, current_project)
        elif choice == "03":
            target = Prompt.ask("  [cyan]Enter domain/host[/cyan]")
            _ssl_info(target, current_project)
        elif choice == "04":
            target = Prompt.ask("  [cyan]Enter host/IP[/cyan]")
            _port_scan(target, current_project)
        elif choice == "05":
            target = Prompt.ask("  [cyan]Enter URL or domain[/cyan]")
            _tech_detect(target, current_project)
        elif choice == "06":
            target = Prompt.ask("  [cyan]Enter domain/host[/cyan]")
            _full_recon(target, current_project)
        elif choice == "07":
            _show_history(current_project)


def _whois_lookup(target, project=None):
    console.clear()
    theme.section_header(f"WHOIS — {target}")
    results = {}
    try:
        import whois
        with Progress(SpinnerColumn(), TextColumn("[cyan]Running WHOIS..."), transient=True) as p:
            p.add_task("")
            w = whois.whois(target)

        fields = {
            "Domain Name":    w.domain_name,
            "Registrar":      w.registrar,
            "Created":        w.creation_date,
            "Expires":        w.expiration_date,
            "Updated":        w.updated_date,
            "Name Servers":   w.name_servers,
            "Status":         w.status,
            "Registrant Org": getattr(w, "org", None),
            "Country":        getattr(w, "country", None),
        }

        t = Table(box=box.SIMPLE, header_style="bold cyan", border_style="dim cyan")
        t.add_column("Field",  style="cyan",       min_width=20)
        t.add_column("Value",  style="bold white",  min_width=40)

        for k, v in fields.items():
            if v:
                if isinstance(v, list):
                    v = ", ".join(str(x) for x in v[:3])
                else:
                    v = str(v)[:80]
                t.add_row(k, v)
                results[k] = v

        console.print(t)
        theme.success("WHOIS lookup complete.")

    except ImportError:
        theme.error("python-whois not installed. Run: pip install python-whois")
    except Exception as e:
        theme.error(f"WHOIS failed: {e}")
        logger.error("WHOIS error for %s: %s", target, e)

    if project:
        db.save_scan(project["id"], "whois", target,
                     f"WHOIS completed for {target}", results)
    console.input("\n  Press Enter to continue...")


def _dns_lookup(target, project=None):
    console.clear()
    theme.section_header(f"DNS INTELLIGENCE — {target}")
    results = {}

    try:
        import dns.resolver
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

        t = Table(box=box.SIMPLE, header_style="bold cyan", border_style="dim cyan")
        t.add_column("Type",   style="cyan",      width=8)
        t.add_column("Record", style="bold white", min_width=50)

        with Progress(SpinnerColumn(), TextColumn("[cyan]Querying DNS..."), transient=True) as p:
            p.add_task("")
            for rtype in record_types:
                try:
                    answers = dns.resolver.resolve(target, rtype, lifetime=5)
                    for r in answers:
                        val = str(r)
                        t.add_row(rtype, val)
                        results.setdefault(rtype, []).append(val)
                except Exception:
                    pass

        console.print(t)

    except ImportError:
        # Fallback to socket
        theme.warn("dnspython not available — using basic lookup.")
        try:
            info = socket.getaddrinfo(target, None)
            for item in info[:5]:
                addr = item[4][0]
                console.print(f"  [cyan]A[/cyan]  {addr}")
                results.setdefault("A", []).append(addr)
        except Exception as e:
            theme.error(f"DNS lookup failed: {e}")

    except Exception as e:
        theme.error(f"DNS error: {e}")

    theme.success("DNS lookup complete.")
    if project:
        db.save_scan(project["id"], "dns", target,
                     f"DNS enumeration for {target}", results)
    console.input("\n  Press Enter to continue...")


def _ssl_info(target, project=None):
    console.clear()
    theme.section_header(f"SSL/TLS CERTIFICATE — {target}")
    results = {}

    try:
        with Progress(SpinnerColumn(), TextColumn("[cyan]Fetching certificate..."), transient=True) as p:
            p.add_task("")
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=target) as s:
                s.settimeout(8)
                s.connect((target, 443))
                cert = s.getpeercert()

        t = Table(box=box.SIMPLE, header_style="bold cyan", border_style="dim cyan")
        t.add_column("Field",  style="cyan",      min_width=22)
        t.add_column("Value",  style="bold white", min_width=40)

        subject = dict(x[0] for x in cert.get("subject", []))
        issuer  = dict(x[0] for x in cert.get("issuer", []))
        san     = cert.get("subjectAltName", [])

        t.add_row("Common Name",   subject.get("commonName", "N/A"))
        t.add_row("Organization",  subject.get("organizationName", "N/A"))
        t.add_row("Issuer",        issuer.get("organizationName", "N/A"))
        t.add_row("Valid From",    cert.get("notBefore", "N/A"))
        t.add_row("Valid Until",   cert.get("notAfter", "N/A"))
        t.add_row("Version",       str(cert.get("version", "N/A")))
        t.add_row("SANs",          ", ".join(v for _, v in san[:8]))

        console.print(t)

        results = {
            "subject": subject, "issuer": issuer,
            "not_before": cert.get("notBefore"),
            "not_after": cert.get("notAfter"),
        }
        theme.success("Certificate information retrieved.")

    except ssl.SSLError as e:
        theme.error(f"SSL error: {e}")
    except Exception as e:
        theme.error(f"Could not retrieve certificate: {e}")

    if project:
        db.save_scan(project["id"], "ssl", target,
                     f"SSL cert info for {target}", results)
    console.input("\n  Press Enter to continue...")


def _port_scan(target, project=None):
    console.clear()
    theme.section_header(f"PORT SCANNER — {target}")

    common_ports = {
        21: "FTP",    22: "SSH",    23: "Telnet",  25: "SMTP",
        53: "DNS",    80: "HTTP",   110: "POP3",   143: "IMAP",
        443: "HTTPS", 445: "SMB",   3306: "MySQL", 3389: "RDP",
        5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
        27017: "MongoDB", 1433: "MSSQL", 5900: "VNC", 5000: "Flask",
    }

    open_ports = []
    t = Table(box=box.SIMPLE, header_style="bold cyan", border_style="dim cyan")
    t.add_column("Port",    style="bold white", width=8)
    t.add_column("Service", style="cyan",       width=15)
    t.add_column("Status",  width=10)

    with Progress(SpinnerColumn(), TextColumn("[cyan]Scanning ports..."), transient=True) as p:
        p.add_task("")
        for port, service in common_ports.items():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.8)
                result = s.connect_ex((target, port))
                s.close()
                if result == 0:
                    t.add_row(str(port), service, "[green]OPEN[/green]")
                    open_ports.append({"port": port, "service": service})
            except Exception:
                pass

    if open_ports:
        console.print(t)
        theme.success(f"Found {len(open_ports)} open port(s).")
    else:
        theme.warn("No open ports found in common range.")

    if project:
        db.save_scan(project["id"], "port_scan", target,
                     f"{len(open_ports)} open ports on {target}", {"open_ports": open_ports})
    console.input("\n  Press Enter to continue...")


def _tech_detect(target, project=None):
    console.clear()
    if not target.startswith("http"):
        target = "https://" + target
    theme.section_header(f"TECHNOLOGY DETECTION — {target}")

    import requests as req
    results = {}

    try:
        with Progress(SpinnerColumn(), TextColumn("[cyan]Fetching headers..."), transient=True) as p:
            p.add_task("")
            r = req.get(target, timeout=10, allow_redirects=True,
                        headers={"User-Agent": "Mozilla/5.0 CyberMint/1.0"})

        headers = dict(r.headers)
        t = Table(box=box.SIMPLE, header_style="bold cyan", border_style="dim cyan")
        t.add_column("Header",  style="cyan",      min_width=30)
        t.add_column("Value",   style="bold white", min_width=40)

        security_headers = [
            "Server", "X-Powered-By", "X-Frame-Options", "X-XSS-Protection",
            "Strict-Transport-Security", "Content-Security-Policy",
            "X-Content-Type-Options", "Referrer-Policy",
            "Permissions-Policy", "Cache-Control", "Set-Cookie",
        ]

        for h in security_headers:
            val = headers.get(h, headers.get(h.lower()))
            if val:
                t.add_row(h, val[:80])
                results[h] = val

        console.print(t)
        console.print(f"\n  [cyan]Status Code:[/cyan] [bold white]{r.status_code}[/bold white]")
        console.print(f"  [cyan]Final URL:[/cyan]   [bold white]{r.url}[/bold white]")

        # Security header analysis
        missing = [h for h in ["X-Frame-Options","Content-Security-Policy",
                                "Strict-Transport-Security","X-Content-Type-Options"]
                   if h not in headers]
        if missing:
            theme.warn(f"Missing security headers: {', '.join(missing)}")
            results["missing_headers"] = missing

        theme.success("Technology detection complete.")

    except Exception as e:
        theme.error(f"Request failed: {e}")

    if project:
        db.save_scan(project["id"], "tech_detect", target,
                     f"Tech detection for {target}", results)
    console.input("\n  Press Enter to continue...")


def _full_recon(target, project=None):
    console.clear()
    theme.section_header(f"FULL RECON PROFILE — {target}")
    console.print("  [cyan]Running all recon modules sequentially...[/cyan]\n")

    _dns_lookup(target, project)
    _ssl_info(target, project)
    _port_scan(target, project)
    _tech_detect(target, project)

    theme.success(f"Full recon profile complete for {target}.")
    console.input("\n  Press Enter to continue...")


def _show_history(project=None):
    console.clear()
    theme.section_header("SCAN HISTORY")
    history = db.get_scan_history(project["id"] if project else None, limit=20)
    if not history:
        theme.warn("No scan history found.")
        console.input("  Press Enter...")
        return

    t = Table(box=box.SIMPLE, header_style="bold cyan", border_style="dim cyan")
    t.add_column("Date",    style="dim",        width=17)
    t.add_column("Module",  style="cyan",       width=15)
    t.add_column("Target",  style="bold white", width=25)
    t.add_column("Summary")

    for h in history:
        t.add_row(h["created_at"][:16], h["module"], h["target"] or "", h["result_summary"] or "")
    console.print(t)
    console.input("\n  Press Enter to continue...")
