"""
CyberMint OSINT Center
Subdomain enum, email harvest, Google dorks, Wayback, IP rep, username check.
"""
import requests
import socket
import re
import json
import urllib.parse
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt
from rich import box
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

import core.database as db
from core.logger import get_logger
from ui.theme import theme

console = Console()
logger  = get_logger("OSINT")

SUBDOMAIN_LIST = [
    "www","mail","ftp","localhost","webmail","smtp","pop","ns1","ns2","ns3",
    "vpn","m","mobile","api","dev","stage","staging","test","beta","alpha",
    "app","apps","admin","panel","dashboard","shop","store","blog","news",
    "portal","secure","server","server1","server2","cloud","cdn","media",
    "static","assets","img","images","video","files","upload","downloads",
    "remote","gateway","firewall","router","proxy","mx","mx1","mx2","email",
    "exchange","imap","pop3","autodiscover","autoconfig","ldap","login",
    "sso","auth","oauth","id","identity","account","accounts","register",
    "support","help","forum","wiki","docs","documentation","kb","status",
    "monitoring","alerting","metrics","grafana","kibana","elastic","jenkins",
    "ci","cd","git","gitlab","jira","confluence","redmine","tracker","db",
    "database","mysql","postgres","redis","mongo","internal","intranet",
    "corp","office","backup","archive","old","new","v2","v3","api2","api3",
    "connect","link","pay","payment","billing","invoice","demo","sandbox",
    "uat","qa","preprod","pre","prod","production","live","public","private",
    "secret","hidden","cpanel","whm","plesk","webmin","phpmyadmin",
]

DORK_TEMPLATES = {
    "Login Pages":          'site:{domain} inurl:login OR inurl:signin OR inurl:auth',
    "Admin Panels":         'site:{domain} inurl:admin OR inurl:panel OR inurl:dashboard',
    "Config Files":         'site:{domain} ext:env OR ext:cfg OR ext:config OR ext:ini',
    "Database Dumps":       'site:{domain} ext:sql OR ext:db OR ext:sqlite',
    "Backup Files":         'site:{domain} ext:bak OR ext:backup OR ext:old OR ext:zip',
    "Password Files":       'site:{domain} inurl:password OR inurl:passwd OR ext:passwd',
    "Log Files":            'site:{domain} ext:log',
    "API Keys/Tokens":      'site:{domain} inurl:api_key OR inurl:token OR inurl:secret',
    "Error Messages":       'site:{domain} "Warning: mysql" OR "PHP Fatal error" OR "stack trace"',
    "Directory Listing":    'site:{domain} intitle:"index of"',
    "Open Redirects":       'site:{domain} inurl:redirect OR inurl:return OR inurl:url=http',
    "phpMyAdmin":           'site:{domain} inurl:phpmyadmin',
    "WordPress":            'site:{domain} inurl:wp-content OR inurl:wp-admin',
    "Exposed Documents":    'site:{domain} ext:pdf OR ext:docx OR ext:xlsx',
    "Camera/IoT":           'site:{domain} inurl:view/index.shtml OR intitle:"webcam"',
    "Sub-Subdomains":       'site:*.{domain}',
    "Related Domains":      'related:{domain}',
    "Cached Version":       'cache:{domain}',
    "Email Addresses":      'site:{domain} "@{domain}"',
    "Pastebin Leaks":       'site:pastebin.com "{domain}"',
    "GitHub Leaks":         'site:github.com "{domain}"',
    "Shodan Dork":          'hostname:{domain}',
}

SOCIAL_PLATFORMS = [
    ("GitHub",     "https://github.com/{username}"),
    ("Twitter/X",  "https://twitter.com/{username}"),
    ("Instagram",  "https://instagram.com/{username}"),
    ("LinkedIn",   "https://linkedin.com/in/{username}"),
    ("Facebook",   "https://facebook.com/{username}"),
    ("Reddit",     "https://reddit.com/user/{username}"),
    ("TikTok",     "https://tiktok.com/@{username}"),
    ("YouTube",    "https://youtube.com/@{username}"),
    ("Pinterest",  "https://pinterest.com/{username}"),
    ("Telegram",   "https://t.me/{username}"),
    ("Medium",     "https://medium.com/@{username}"),
    ("HackerNews", "https://news.ycombinator.com/user?id={username}"),
    ("GitLab",     "https://gitlab.com/{username}"),
    ("BitBucket",  "https://bitbucket.org/{username}"),
    ("Steam",      "https://steamcommunity.com/id/{username}"),
    ("Twitch",     "https://twitch.tv/{username}"),
    ("Keybase",    "https://keybase.io/{username}"),
    ("Pastebin",   "https://pastebin.com/u/{username}"),
    ("DockerHub",  "https://hub.docker.com/u/{username}"),
    ("NPM",        "https://npmjs.com/~{username}"),
]


def show_menu(current_project=None):
    while True:
        console.clear()
        theme.banner("OSINT CENTER", "Open Source Intelligence Gathering")

        options = [
            ("[01]", "Subdomain Enumeration",  "Brute-force & DNS subdomains"),
            ("[02]", "Email Harvester",        "Find emails linked to a domain"),
            ("[03]", "Google Dork Generator",  "Build 20+ advanced search queries"),
            ("[04]", "Wayback Machine Lookup", "Fetch archived site snapshots"),
            ("[05]", "Username Search",        "Hunt a username across 20 platforms"),
            ("[06]", "IP Reputation Check",    "Check IP against threat lists"),
            ("[07]", "Domain OSINT Profile",   "Full passive recon on a domain"),
            ("[08]", "Certificate Transparency","Find subdomains via SSL certs"),
            ("[09]", "DNS Brute Force",        "Aggressive DNS subdomain discovery"),
            ("[00]", "Back to Main Menu",      ""),
        ]
        theme.menu_table(options)

        if current_project:
            console.print(f"\n  [cyan]Active Project:[/cyan] [bold white]{current_project['name']}[/bold white]")

        choice = theme.get_choice()

        if choice == "00":
            break
        elif choice == "01":
            domain = Prompt.ask("  [cyan]Domain[/cyan]")
            _subdomain_enum(domain, current_project)
        elif choice == "02":
            domain = Prompt.ask("  [cyan]Domain[/cyan]")
            _email_harvester(domain, current_project)
        elif choice == "03":
            domain = Prompt.ask("  [cyan]Domain[/cyan]")
            _dork_generator(domain)
        elif choice == "04":
            domain = Prompt.ask("  [cyan]Domain or URL[/cyan]")
            _wayback(domain)
        elif choice == "05":
            username = Prompt.ask("  [cyan]Username[/cyan]")
            _username_search(username, current_project)
        elif choice == "06":
            ip = Prompt.ask("  [cyan]IP Address[/cyan]")
            _ip_reputation(ip, current_project)
        elif choice == "07":
            domain = Prompt.ask("  [cyan]Domain[/cyan]")
            _domain_profile(domain, current_project)
        elif choice == "08":
            domain = Prompt.ask("  [cyan]Domain[/cyan]")
            _cert_transparency(domain, current_project)
        elif choice == "09":
            domain = Prompt.ask("  [cyan]Domain[/cyan]")
            _dns_bruteforce(domain, current_project)


def _get(url, timeout=10, headers=None):
    h = {"User-Agent": "Mozilla/5.0 (CyberMint OSINT)"}
    if headers:
        h.update(headers)
    try:
        return requests.get(url, timeout=timeout, headers=h)
    except Exception:
        return None


# ── Subdomain Enumeration ─────────────────────────────────────────────────────

def _subdomain_enum(domain, project=None):
    console.clear()
    theme.section_header(f"SUBDOMAIN ENUMERATION — {domain}")
    found = []

    with Progress(SpinnerColumn(), TextColumn("[cyan]Enumerating subdomains... {task.completed}/{task.total}"),
                  BarColumn(), transient=True) as p:
        task = p.add_task("", total=len(SUBDOMAIN_LIST))
        for sub in SUBDOMAIN_LIST:
            fqdn = f"{sub}.{domain}"
            p.advance(task)
            try:
                ip = socket.gethostbyname(fqdn)
                found.append({"subdomain": fqdn, "ip": ip})
            except Exception:
                pass

    if found:
        t = Table(box=box.SIMPLE, header_style="bold cyan", border_style="dim cyan")
        t.add_column("#",         width=4, style="dim")
        t.add_column("Subdomain", style="bold white", min_width=35)
        t.add_column("IP",        style="cyan")
        for i, s in enumerate(found, 1):
            t.add_row(str(i), s["subdomain"], s["ip"])
        console.print(t)
        theme.success(f"Found {len(found)} subdomain(s).")
        if project:
            for s in found:
                db.add_asset(project["id"], s["subdomain"], "subdomain", s["ip"])
            db.save_scan(project["id"], "subdomain_enum", domain,
                         f"Found {len(found)} subdomains", found)
    else:
        theme.warn("No subdomains found.")
    console.input("\n  Press Enter to continue...")


# ── Email Harvester ───────────────────────────────────────────────────────────

def _email_harvester(domain, project=None):
    console.clear()
    theme.section_header(f"EMAIL HARVESTER — {domain}")
    emails = set()

    sources = [
        f"https://{domain}",
        f"https://www.{domain}",
        f"https://{domain}/contact",
        f"https://{domain}/about",
        f"https://{domain}/team",
    ]

    email_pattern = re.compile(
        r"[a-zA-Z0-9._%+\-]+@" + re.escape(domain), re.IGNORECASE
    )

    with Progress(SpinnerColumn(), TextColumn("[cyan]Harvesting emails..."), transient=True) as p:
        p.add_task("")
        for url in sources:
            try:
                r = requests.get(url, timeout=8,
                                 headers={"User-Agent": "Mozilla/5.0"})
                found = email_pattern.findall(r.text)
                emails.update(found)
            except Exception:
                pass

        # Also check Hunter.io (no key needed for basic)
        try:
            r = requests.get(
                f"https://api.hunter.io/v2/domain-search?domain={domain}&limit=10",
                timeout=8)
            if r.status_code == 200:
                data = r.json()
                for e in data.get("data", {}).get("emails", []):
                    emails.add(e.get("value", ""))
        except Exception:
            pass

    if emails:
        t = Table(box=box.SIMPLE, header_style="bold cyan")
        t.add_column("#",     width=4, style="dim")
        t.add_column("Email", style="bold white")
        for i, e in enumerate(sorted(emails), 1):
            if e:
                t.add_row(str(i), e)
        console.print(t)
        theme.success(f"Found {len(emails)} email(s).")
        if project:
            db.save_scan(project["id"], "email_harvest", domain,
                         f"Found {len(emails)} emails", list(emails))
    else:
        theme.warn("No emails found on public pages.")
        console.print("  [dim]Tip: Try Hunter.io or theHarvester for deeper results.[/dim]")
    console.input("\n  Press Enter to continue...")


# ── Google Dork Generator ─────────────────────────────────────────────────────

def _dork_generator(domain):
    console.clear()
    theme.section_header(f"GOOGLE DORK GENERATOR — {domain}")
    console.print("  [dim]Copy these dorks into Google / DuckDuckGo / Bing[/dim]\n")

    t = Table(box=box.SIMPLE, header_style="bold cyan", border_style="dim cyan")
    t.add_column("#",       width=4,  style="dim")
    t.add_column("Purpose", style="bold white", min_width=22)
    t.add_column("Dork",    style="cyan")

    for i, (purpose, template) in enumerate(DORK_TEMPLATES.items(), 1):
        dork = template.format(domain=domain)
        t.add_row(str(i), purpose, dork)

    console.print(t)

    save = Prompt.ask("\n  Save dorks to file?", choices=["y","n"], default="n")
    if save == "y":
        fname = f"dorks_{domain.replace('.','_')}.txt"
        with open(fname, "w") as f:
            for purpose, template in DORK_TEMPLATES.items():
                f.write(f"# {purpose}\n{template.format(domain=domain)}\n\n")
        theme.success(f"Saved to {fname}")

    console.input("\n  Press Enter to continue...")


# ── Wayback Machine ───────────────────────────────────────────────────────────

def _wayback(domain):
    console.clear()
    domain = domain.replace("https://","").replace("http://","").rstrip("/")
    theme.section_header(f"WAYBACK MACHINE — {domain}")

    try:
        r = _get(f"http://archive.org/wayback/available?url={domain}")
        if r and r.status_code == 200:
            data = r.json()
            snap = data.get("archived_snapshots", {}).get("closest", {})
            if snap.get("available"):
                console.print(Panel(
                    f"  [bold cyan]Status:[/bold cyan]    [green]AVAILABLE[/green]\n"
                    f"  [bold cyan]Timestamp:[/bold cyan] {snap.get('timestamp')}\n"
                    f"  [bold cyan]URL:[/bold cyan]       {snap.get('url')}",
                    title="[bold cyan][ LATEST SNAPSHOT ][/bold cyan]",
                    border_style="cyan",
                ))
            else:
                theme.warn("No snapshots found for this domain.")

        # CDX API for historical data
        r2 = _get(f"http://web.archive.org/cdx/search/cdx?url={domain}/*"
                  f"&output=json&limit=10&fl=timestamp,original,statuscode")
        if r2 and r2.status_code == 200:
            records = r2.json()
            if len(records) > 1:
                console.print("\n  [bold cyan]Recent Snapshots:[/bold cyan]")
                t = Table(box=box.SIMPLE, header_style="bold cyan")
                t.add_column("Timestamp", style="dim",        width=17)
                t.add_column("URL",       style="bold white", min_width=40)
                t.add_column("Status",    width=8)
                for rec in records[1:11]:
                    ts, url, code = rec[0], rec[1], rec[2]
                    color = "green" if code == "200" else "yellow"
                    t.add_row(ts, url[:60], f"[{color}]{code}[/{color}]")
                console.print(t)

    except Exception as e:
        theme.error(f"Wayback lookup failed: {e}")
    console.input("\n  Press Enter to continue...")


# ── Username Search ───────────────────────────────────────────────────────────

def _username_search(username, project=None):
    console.clear()
    theme.section_header(f"USERNAME SEARCH — {username}")
    found = []

    t = Table(box=box.SIMPLE, header_style="bold cyan", border_style="dim cyan")
    t.add_column("#",        width=4, style="dim")
    t.add_column("Platform", style="bold white", min_width=15)
    t.add_column("Status",   width=10)
    t.add_column("URL",      style="dim")

    with Progress(SpinnerColumn(), TextColumn("[cyan]Checking platforms... {task.completed}/{task.total}"),
                  BarColumn(), transient=True) as p:
        task = p.add_task("", total=len(SOCIAL_PLATFORMS))
        for i, (platform, url_tmpl) in enumerate(SOCIAL_PLATFORMS, 1):
            url = url_tmpl.format(username=username)
            p.advance(task)
            try:
                r = requests.get(url, timeout=6, allow_redirects=True,
                                 headers={"User-Agent": "Mozilla/5.0"})
                if r.status_code == 200 and username.lower() in r.url.lower():
                    status = "[green]FOUND[/green]"
                    found.append({"platform": platform, "url": url})
                elif r.status_code == 404:
                    status = "[dim]Not Found[/dim]"
                else:
                    status = f"[dim]{r.status_code}[/dim]"
            except Exception:
                status = "[dim]Error[/dim]"
            t.add_row(str(i), platform, status, url)

    console.print(t)
    theme.success(f"Found on {len(found)} platform(s).")
    if found and project:
        db.save_scan(project["id"], "username_search", username,
                     f"@{username} found on {len(found)} platforms", found)
    console.input("\n  Press Enter to continue...")


# ── IP Reputation ─────────────────────────────────────────────────────────────

def _ip_reputation(ip, project=None):
    console.clear()
    theme.section_header(f"IP REPUTATION — {ip}")

    results = {}

    # AbuseIPDB (no key needed for basic info)
    try:
        r = requests.get(
            f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}",
            headers={"Accept": "application/json",
                     "Key": ""},
            timeout=8)
    except Exception:
        pass

    # ipapi.co
    try:
        r = requests.get(f"https://ipapi.co/{ip}/json/", timeout=8)
        if r.status_code == 200:
            data = r.json()
            if "error" not in data:
                results["geo"] = data
                t = Table(box=box.SIMPLE, header_style="bold cyan", border_style="dim cyan")
                t.add_column("Field",  style="cyan",       min_width=20)
                t.add_column("Value",  style="bold white")
                fields = [
                    ("IP",           data.get("ip")),
                    ("City",         data.get("city")),
                    ("Region",       data.get("region")),
                    ("Country",      data.get("country_name")),
                    ("ISP / Org",    data.get("org")),
                    ("ASN",          data.get("asn")),
                    ("Timezone",     data.get("timezone")),
                    ("Latitude",     data.get("latitude")),
                    ("Longitude",    data.get("longitude")),
                ]
                for k, v in fields:
                    if v:
                        t.add_row(k, str(v))
                console.print(t)
    except Exception as e:
        theme.error(f"Geo lookup failed: {e}")

    # Shodan InternetDB (no API key needed)
    try:
        r2 = requests.get(f"https://internetdb.shodan.io/{ip}", timeout=8)
        if r2.status_code == 200:
            data2 = r2.json()
            results["shodan"] = data2
            console.print("\n  [bold cyan]Shodan InternetDB:[/bold cyan]")
            ports = data2.get("ports", [])
            tags  = data2.get("tags",  [])
            vulns = data2.get("vulns", [])
            hostnames = data2.get("hostnames", [])

            if hostnames:
                console.print(f"  [cyan]Hostnames:[/cyan] {', '.join(hostnames[:5])}")
            if ports:
                console.print(f"  [cyan]Open Ports:[/cyan] {', '.join(str(p) for p in ports)}")
            if tags:
                console.print(f"  [cyan]Tags:[/cyan] {', '.join(tags)}")
            if vulns:
                console.print(f"  [red]CVEs:[/red] {', '.join(vulns[:10])}")
                if project:
                    for v in vulns:
                        db.add_ioc("cve", v, "high", f"Found on {ip}", "Shodan")
    except Exception:
        pass

    if project:
        db.save_scan(project["id"], "ip_reputation", ip,
                     f"IP reputation check for {ip}", results)
    console.input("\n  Press Enter to continue...")


# ── Domain OSINT Profile ──────────────────────────────────────────────────────

def _domain_profile(domain, project=None):
    console.clear()
    theme.section_header(f"DOMAIN OSINT PROFILE — {domain}")
    console.print("  [cyan]Running full passive recon...[/cyan]\n")

    _subdomain_enum(domain, project)
    _cert_transparency(domain, project)
    _email_harvester(domain, project)
    _dork_generator(domain)

    theme.success(f"OSINT profile complete for {domain}.")
    console.input("\n  Press Enter to continue...")


# ── Certificate Transparency ──────────────────────────────────────────────────

def _cert_transparency(domain, project=None):
    console.clear()
    theme.section_header(f"CERTIFICATE TRANSPARENCY — {domain}")
    console.print("  [dim]Querying crt.sh for SSL certificate logs...[/dim]\n")

    try:
        r = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=15,
            headers={"User-Agent": "Mozilla/5.0 (CyberMint)"}
        )
        if r.status_code == 200:
            data = r.json()
            subdomains = set()
            for cert in data:
                name = cert.get("name_value","")
                for sub in name.split("\n"):
                    sub = sub.strip().lstrip("*.")
                    if sub.endswith(domain) and sub != domain:
                        subdomains.add(sub)

            if subdomains:
                t = Table(box=box.SIMPLE, header_style="bold cyan", border_style="dim cyan")
                t.add_column("#",         width=4, style="dim")
                t.add_column("Subdomain", style="bold white")
                t.add_column("Issued",    style="dim", width=12)

                cert_map = {}
                for cert in data:
                    name = cert.get("name_value","")
                    date = cert.get("not_before","")[:10]
                    for sub in name.split("\n"):
                        sub = sub.strip().lstrip("*.")
                        if sub not in cert_map:
                            cert_map[sub] = date

                for i, sub in enumerate(sorted(subdomains), 1):
                    t.add_row(str(i), sub, cert_map.get(sub,""))
                console.print(t)
                theme.success(f"Found {len(subdomains)} unique subdomain(s) via SSL certs.")

                if project:
                    for sub in subdomains:
                        db.add_asset(project["id"], sub, "subdomain (cert)", "")
                    db.save_scan(project["id"], "cert_transparency", domain,
                                 f"crt.sh: {len(subdomains)} subdomains", list(subdomains))
            else:
                theme.warn("No subdomains found in certificate logs.")
        else:
            theme.error(f"crt.sh returned HTTP {r.status_code}")
    except Exception as e:
        theme.error(f"CT lookup failed: {e}")
    console.input("\n  Press Enter to continue...")


# ── DNS Brute Force ───────────────────────────────────────────────────────────

def _dns_bruteforce(domain, project=None):
    console.clear()
    theme.section_header(f"DNS BRUTE FORCE — {domain}")
    found = []

    try:
        import dns.resolver
        use_dnspy = True
    except ImportError:
        use_dnspy = False

    with Progress(SpinnerColumn(),
                  TextColumn("[cyan]Brute-forcing DNS... {task.completed}/{task.total}"),
                  BarColumn(), transient=True) as p:
        task = p.add_task("", total=len(SUBDOMAIN_LIST))
        for sub in SUBDOMAIN_LIST:
            fqdn = f"{sub}.{domain}"
            p.advance(task)
            try:
                if use_dnspy:
                    import dns.resolver
                    answers = dns.resolver.resolve(fqdn, "A", lifetime=2)
                    ips = [str(r) for r in answers]
                else:
                    ips = [socket.gethostbyname(fqdn)]
                found.append({"subdomain": fqdn, "ips": ips})
            except Exception:
                pass

    if found:
        t = Table(box=box.SIMPLE, header_style="bold cyan")
        t.add_column("#",         width=4, style="dim")
        t.add_column("Subdomain", style="bold white", min_width=35)
        t.add_column("IPs",       style="cyan")
        for i, s in enumerate(found, 1):
            t.add_row(str(i), s["subdomain"], ", ".join(s["ips"]))
        console.print(t)
        theme.success(f"Found {len(found)} DNS record(s).")
        if project:
            db.save_scan(project["id"], "dns_bruteforce", domain,
                         f"Found {len(found)} DNS records", found)
    else:
        theme.warn("No subdomains resolved.")
    console.input("\n  Press Enter to continue...")
