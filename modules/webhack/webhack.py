"""
CyberMint Web Hacking Module
Directory brute-force, SQLi, XSS, CMS detect, JWT, CORS, admin finder.
"""
import requests
import base64
import json
import re
import urllib.parse
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
logger = get_logger("WebHack")

# ── Built-in wordlists ────────────────────────────────────────────────────────
DIR_WORDLIST = [
    "admin","administrator","login","wp-admin","phpmyadmin","dashboard","panel",
    "cpanel","webmail","mail","api","api/v1","api/v2","backup","backups","config",
    "configuration","db","database","dev","development","test","testing","staging",
    "upload","uploads","files","file","assets","static","images","img","css","js",
    "includes","include","lib","libs","library","vendor","src","source","app",
    "application","portal","user","users","account","accounts","auth","login.php",
    "admin.php","index.php","wp-login.php","xmlrpc.php","robots.txt","sitemap.xml",
    "sitemap.xml.gz",".git","git",".env","env","secret","secrets","private","hidden",
    ".htaccess","web.config","readme.txt","README.md","changelog","CHANGELOG",
    "console","shell","cmd","command","exec","execute","cgi-bin","scripts","server",
    "status","health","metrics","actuator","actuator/health","swagger","swagger-ui",
    "swagger-ui.html","api-docs","graphql","graphiql","debug","info","trace",
    "error","errors","log","logs","tmp","temp","cache","old","bak","backup.zip",
    "backup.sql","dump","db.sql","1","2","register","signup","forgot","reset",
    "password","profile","settings","preferences","search","contact","about",
    "help","support","faq","terms","privacy","sitemap","news","blog","forum",
    "shop","store","cart","checkout","payment","invoice","report","reports",
    "manage","management","manager","editor","cms","system","sys","service",
    "services","microservice","internal","external","proxy","gateway","webhook",
    ".well-known","security.txt",".well-known/security.txt","crossdomain.xml",
]

ADMIN_PATHS = [
    "admin","administrator","admin/login","admin.php","wp-admin","wp-login.php",
    "phpmyadmin","cpanel","webadmin","panel","controlpanel","control","manage",
    "management","manager","dashboard","backend","superadmin","superuser","root",
    "adminpanel","admin_panel","admin-panel","login","signin","auth",
]

SQL_PAYLOADS = [
    "'", '"', "' OR '1'='1", "' OR 1=1--", "\" OR \"1\"=\"1",
    "' OR 1=1#", "admin'--", "' UNION SELECT NULL--",
    "1' AND SLEEP(3)--", "1; DROP TABLE users--",
]

SQL_ERRORS = [
    "sql syntax","mysql_fetch","pg_query","ORA-","sqlite3","syntax error",
    "unclosed quotation","ODBC","Microsoft OLE DB","mysql_num_rows",
    "Warning: mysql","You have an error in your SQL","supplied argument is not",
    "Column count doesn't match","Incorrect syntax near",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "'\"><script>alert(1)</script>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    "<body onload=alert(1)>",
]

CMS_FINGERPRINTS = {
    "WordPress":  ["/wp-login.php", "/wp-admin/", "/wp-content/", "/xmlrpc.php"],
    "Joomla":     ["/administrator/", "/components/", "/modules/", "/joomla.xml"],
    "Drupal":     ["/sites/default/", "/misc/drupal.js", "/CHANGELOG.txt", "/node/"],
    "Django":     ["/admin/", "/static/admin/", "/accounts/login/"],
    "Laravel":    ["/public/index.php", "laravel_session", "X-Powered-By: PHP"],
    "Magento":    ["/skin/frontend/", "/js/mage/", "/downloader/"],
    "PrestaShop": ["/modules/", "/themes/", "/img/cms/"],
    "Shopify":    ["cdn.shopify.com", "Shopify.theme"],
    "Ghost":      ["/ghost/", "/content/themes/", "ghost-access-token"],
}

CORS_HEADERS = ["Access-Control-Allow-Origin","Access-Control-Allow-Methods",
                "Access-Control-Allow-Headers","Access-Control-Allow-Credentials"]


def show_menu(current_project=None):
    while True:
        console.clear()
        theme.banner("WEB HACKING", "Web Application Security Testing")

        options = [
            ("[01]", "Directory Brute-Force",  "Find hidden files & directories"),
            ("[02]", "Admin Panel Finder",     "Locate admin/login pages"),
            ("[03]", "SQL Injection Tester",   "Detect SQLi vulnerabilities"),
            ("[04]", "XSS Scanner",            "Find reflected XSS"),
            ("[05]", "CMS Detector",           "Identify CMS & framework"),
            ("[06]", "JWT Analyzer",           "Decode & audit JWT tokens"),
            ("[07]", "CORS Checker",           "Detect CORS misconfigs"),
            ("[08]", "HTTP Method Tester",     "Test allowed HTTP methods"),
            ("[09]", "Open Redirect Tester",   "Detect open redirect flaws"),
            ("[10]", "Cookie Analyzer",        "Audit cookie security flags"),
            ("[11]", "Full Web Audit",         "Run all web checks on a target"),
            ("[00]", "Back to Main Menu",      ""),
        ]
        theme.menu_table(options)

        if current_project:
            console.print(f"\n  [cyan]Active Project:[/cyan] [bold white]{current_project['name']}[/bold white]")

        choice = theme.get_choice()

        if choice == "00":
            break
        elif choice == "01":
            target = Prompt.ask("  [cyan]Target URL[/cyan]")
            _dir_bruteforce(target, current_project)
        elif choice == "02":
            target = Prompt.ask("  [cyan]Target URL[/cyan]")
            _admin_finder(target, current_project)
        elif choice == "03":
            target = Prompt.ask("  [cyan]Target URL (with ?param=value)[/cyan]")
            _sqli_tester(target, current_project)
        elif choice == "04":
            target = Prompt.ask("  [cyan]Target URL (with ?param=value)[/cyan]")
            _xss_scanner(target, current_project)
        elif choice == "05":
            target = Prompt.ask("  [cyan]Target URL[/cyan]")
            _cms_detector(target, current_project)
        elif choice == "06":
            token = Prompt.ask("  [cyan]JWT Token[/cyan]")
            _jwt_analyzer(token)
        elif choice == "07":
            target = Prompt.ask("  [cyan]Target URL[/cyan]")
            _cors_checker(target, current_project)
        elif choice == "08":
            target = Prompt.ask("  [cyan]Target URL[/cyan]")
            _http_methods(target)
        elif choice == "09":
            target = Prompt.ask("  [cyan]Target URL[/cyan]")
            _open_redirect(target, current_project)
        elif choice == "10":
            target = Prompt.ask("  [cyan]Target URL[/cyan]")
            _cookie_analyzer(target, current_project)
        elif choice == "11":
            target = Prompt.ask("  [cyan]Target URL[/cyan]")
            _full_web_audit(target, current_project)


def _normalize_url(url):
    if not url.startswith("http"):
        url = "https://" + url
    return url.rstrip("/")


def _req(url, method="GET", timeout=8, allow_redirects=True, data=None, headers=None):
    h = {"User-Agent": "Mozilla/5.0 (CyberMint Security Scanner)"}
    if headers:
        h.update(headers)
    try:
        return requests.request(method, url, timeout=timeout,
                                allow_redirects=allow_redirects,
                                data=data, headers=h)
    except Exception:
        return None


# ── Directory Brute-Force ────────────────────────────────────────────────────

def _dir_bruteforce(target, project=None):
    console.clear()
    target = _normalize_url(target)
    theme.section_header(f"DIRECTORY BRUTE-FORCE — {target}")

    custom = Prompt.ask("  Custom wordlist file (leave blank for built-in)", default="")
    wordlist = DIR_WORDLIST
    if custom:
        try:
            with open(custom) as f:
                wordlist = [l.strip() for l in f if l.strip()]
        except Exception:
            theme.warn("Could not load custom wordlist, using built-in.")

    found = []
    t = Table(box=box.SIMPLE, header_style="bold cyan", border_style="dim cyan")
    t.add_column("Status", width=8)
    t.add_column("Size",   width=10)
    t.add_column("Path",   style="bold white")

    status_colors = {200:"green", 201:"green", 301:"yellow", 302:"yellow",
                     401:"orange3", 403:"orange3", 500:"red"}

    with Progress(SpinnerColumn(), TextColumn("[cyan]Scanning... {task.completed}/{task.total}"),
                  BarColumn(), transient=True) as p:
        task = p.add_task("", total=len(wordlist))
        for path in wordlist:
            url = f"{target}/{path}"
            r = _req(url, allow_redirects=False, timeout=5)
            p.advance(task)
            if r and r.status_code not in (404, 400, 410):
                code  = r.status_code
                color = status_colors.get(code, "cyan")
                size  = len(r.content)
                t.add_row(f"[{color}]{code}[/{color}]", f"{size:,}B", f"/{path}")
                found.append({"path": f"/{path}", "status": code, "size": size, "url": url})

    if found:
        console.print(t)
        theme.success(f"Found {len(found)} paths.")
        if project:
            db.save_scan(project["id"], "dir_bruteforce", target,
                         f"Found {len(found)} paths on {target}", found)
    else:
        theme.warn("No accessible paths found.")
    console.input("\n  Press Enter to continue...")


# ── Admin Panel Finder ────────────────────────────────────────────────────────

def _admin_finder(target, project=None):
    console.clear()
    target = _normalize_url(target)
    theme.section_header(f"ADMIN PANEL FINDER — {target}")
    found = []

    with Progress(SpinnerColumn(), TextColumn("[cyan]Searching admin panels..."), transient=True) as p:
        p.add_task("")
        for path in ADMIN_PATHS:
            url = f"{target}/{path}"
            r = _req(url, allow_redirects=True, timeout=5)
            if r and r.status_code in (200, 301, 302, 401, 403):
                code  = r.status_code
                color = "green" if code == 200 else "yellow" if code in (301,302) else "orange3"
                console.print(f"  [{color}]{code}[/{color}]  {url}")
                found.append({"url": url, "status": code})

    if found:
        theme.success(f"Found {len(found)} admin panel(s).")
        if project:
            for f in found:
                if f["status"] == 200:
                    db.add_finding(project["id"], f"Admin Panel Exposed: {f['url']}",
                                   "Admin panel is publicly accessible.",
                                   "high", "Web", target,
                                   "Restrict admin access by IP or require VPN.")
            db.save_scan(project["id"], "admin_finder", target,
                         f"Found {len(found)} admin panels", found)
    else:
        theme.warn("No admin panels found.")
    console.input("\n  Press Enter to continue...")


# ── SQL Injection Tester ──────────────────────────────────────────────────────

def _sqli_tester(target, project=None):
    console.clear()
    theme.section_header(f"SQL INJECTION TESTER — {target}")
    console.print("  [dim]Testing GET parameters for error-based & boolean SQLi...[/dim]\n")

    parsed = urllib.parse.urlparse(target)
    params = urllib.parse.parse_qs(parsed.query)

    if not params:
        theme.warn("No GET parameters found in URL. Add ?param=value to the URL.")
        console.input("  Press Enter...")
        return

    vulnerable = []
    t = Table(box=box.SIMPLE, header_style="bold cyan", border_style="dim cyan")
    t.add_column("Parameter", style="bold white", width=15)
    t.add_column("Payload",   style="cyan",       min_width=30)
    t.add_column("Result",    width=12)

    with Progress(SpinnerColumn(), TextColumn("[cyan]Testing payloads..."), transient=True) as p:
        p.add_task("")
        for param in params:
            for payload in SQL_PAYLOADS:
                test_params = dict(params)
                test_params[param] = [payload]
                qs  = urllib.parse.urlencode(test_params, doseq=True)
                url = urllib.parse.urlunparse(parsed._replace(query=qs))
                r   = _req(url, timeout=8)
                if r:
                    body = r.text.lower()
                    is_vuln = any(err.lower() in body for err in SQL_ERRORS)
                    if is_vuln:
                        t.add_row(param, payload[:40], "[red]VULNERABLE[/red]")
                        vulnerable.append({"param": param, "payload": payload, "url": url})
                    else:
                        t.add_row(param, payload[:40], "[green]Safe[/green]")

    console.print(t)
    if vulnerable:
        theme.warn(f"⚠ Possible SQLi in {len(vulnerable)} parameter(s)!")
        if project:
            db.add_finding(project["id"],
                           f"Possible SQL Injection: {parsed.netloc}",
                           f"Parameters {[v['param'] for v in vulnerable]} may be vulnerable to SQLi.",
                           "critical", "Injection", target,
                           "Use parameterized queries / prepared statements.")
            db.save_scan(project["id"], "sqli", target,
                         f"SQLi found in {len(vulnerable)} params", vulnerable)
    else:
        theme.success("No SQL injection detected.")
    console.input("\n  Press Enter to continue...")


# ── XSS Scanner ──────────────────────────────────────────────────────────────

def _xss_scanner(target, project=None):
    console.clear()
    theme.section_header(f"XSS SCANNER — {target}")
    console.print("  [dim]Testing GET parameters for reflected XSS...[/dim]\n")

    parsed = urllib.parse.urlparse(target)
    params = urllib.parse.parse_qs(parsed.query)
    if not params:
        theme.warn("No GET parameters in URL. Add ?param=value.")
        console.input("  Press Enter...")
        return

    vulnerable = []
    t = Table(box=box.SIMPLE, header_style="bold cyan", border_style="dim cyan")
    t.add_column("Parameter", style="bold white", width=15)
    t.add_column("Payload",   style="cyan",       min_width=35)
    t.add_column("Result",    width=12)

    with Progress(SpinnerColumn(), TextColumn("[cyan]Testing XSS payloads..."), transient=True) as p:
        p.add_task("")
        for param in params:
            for payload in XSS_PAYLOADS:
                test_params = dict(params)
                test_params[param] = [payload]
                qs  = urllib.parse.urlencode(test_params, doseq=True)
                url = urllib.parse.urlunparse(parsed._replace(query=qs))
                r   = _req(url, timeout=8)
                if r and payload in r.text:
                    t.add_row(param, payload[:40], "[red]REFLECTED[/red]")
                    vulnerable.append({"param": param, "payload": payload})
                elif r:
                    t.add_row(param, payload[:40], "[green]Safe[/green]")

    console.print(t)
    if vulnerable:
        theme.warn(f"⚠ Reflected XSS found in {len(vulnerable)} case(s)!")
        if project:
            db.add_finding(project["id"],
                           f"Reflected XSS: {parsed.netloc}",
                           "User input reflected in response without sanitization.",
                           "high", "XSS", target,
                           "Encode all user-controlled output. Implement CSP.")
            db.save_scan(project["id"], "xss", target,
                         f"XSS reflected in {len(vulnerable)} params", vulnerable)
    else:
        theme.success("No reflected XSS detected.")
    console.input("\n  Press Enter to continue...")


# ── CMS Detector ─────────────────────────────────────────────────────────────

def _cms_detector(target, project=None):
    console.clear()
    target = _normalize_url(target)
    theme.section_header(f"CMS DETECTOR — {target}")
    detected = []

    with Progress(SpinnerColumn(), TextColumn("[cyan]Fingerprinting CMS..."), transient=True) as p:
        p.add_task("")
        r_main = _req(target, timeout=10)
        for cms, indicators in CMS_FINGERPRINTS.items():
            score = 0
            hits  = []
            for ind in indicators:
                if ind.startswith("/"):
                    r = _req(f"{target}{ind}", timeout=5, allow_redirects=False)
                    if r and r.status_code in (200, 301, 302, 403):
                        score += 1
                        hits.append(ind)
                elif r_main and ind.lower() in r_main.text.lower():
                    score += 1
                    hits.append(ind)
            if score > 0:
                detected.append({"cms": cms, "score": score, "hits": hits})

    if detected:
        detected.sort(key=lambda x: -x["score"])
        t = Table(box=box.SIMPLE, header_style="bold cyan", border_style="dim cyan")
        t.add_column("CMS",        style="bold white", width=15)
        t.add_column("Confidence", width=12)
        t.add_column("Indicators", style="dim")
        for d in detected:
            conf = "HIGH" if d["score"] >= 3 else "MED" if d["score"] >= 2 else "LOW"
            color = "green" if conf == "HIGH" else "yellow" if conf == "MED" else "dim"
            t.add_row(d["cms"], f"[{color}]{conf}[/{color}]", ", ".join(d["hits"][:4]))
        console.print(t)

        top = detected[0]["cms"]
        theme.success(f"Most likely CMS: {top}")
        if project:
            db.save_scan(project["id"], "cms_detect", target,
                         f"Detected: {top}", detected)
    else:
        theme.warn("No known CMS detected.")
    console.input("\n  Press Enter to continue...")


# ── JWT Analyzer ─────────────────────────────────────────────────────────────

def _jwt_analyzer(token):
    console.clear()
    theme.section_header("JWT ANALYZER")

    try:
        parts = token.strip().split(".")
        if len(parts) != 3:
            theme.error("Invalid JWT format. Expected header.payload.signature")
            console.input("  Press Enter...")
            return

        def decode_part(p):
            p += "=" * (4 - len(p) % 4)
            return json.loads(base64.urlsafe_b64decode(p))

        header  = decode_part(parts[0])
        payload = decode_part(parts[1])

        t = Table(box=box.SIMPLE, header_style="bold cyan", border_style="dim cyan")
        t.add_column("Field",  style="cyan",       min_width=20)
        t.add_column("Value",  style="bold white", min_width=40)

        t.add_row("[bold]─── HEADER ───", "")
        for k, v in header.items():
            t.add_row(k, str(v))

        t.add_row("[bold]─── PAYLOAD ───", "")
        import time
        for k, v in payload.items():
            display = str(v)
            if k in ("exp","iat","nbf") and isinstance(v, int):
                display = f"{v}  ({time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(v))})"
            t.add_row(k, display)

        console.print(t)

        # Security checks
        alg = header.get("alg","")
        console.print("\n  [bold cyan]Security Analysis:[/bold cyan]")
        if alg.upper() in ("NONE",""):
            console.print("  [red]✗[/red] Algorithm is NONE — signature not verified!")
        elif alg.upper() == "HS256":
            console.print("  [yellow]⚠[/yellow] HS256 — symmetric key, check secret strength.")
        else:
            console.print(f"  [green]✓[/green] Algorithm: {alg}")

        exp = payload.get("exp")
        if exp:
            if time.time() > exp:
                console.print("  [red]✗[/red] Token is EXPIRED.")
            else:
                console.print(f"  [green]✓[/green] Token is valid (expires in {int((exp - time.time())/3600)}h).")

        if not payload.get("exp"):
            console.print("  [red]✗[/red] No expiry (exp) claim — token never expires!")

        console.print(f"\n  [dim]Signature:[/dim] {parts[2][:40]}...")

    except Exception as e:
        theme.error(f"Failed to decode JWT: {e}")
    console.input("\n  Press Enter to continue...")


# ── CORS Checker ─────────────────────────────────────────────────────────────

def _cors_checker(target, project=None):
    console.clear()
    target = _normalize_url(target)
    theme.section_header(f"CORS CHECKER — {target}")

    origins_to_test = [
        "https://evil.com",
        "https://attacker.com",
        "null",
        f"https://fake.{target.replace('https://','').replace('http://','')}",
    ]

    t = Table(box=box.SIMPLE, header_style="bold cyan", border_style="dim cyan")
    t.add_column("Test Origin",  style="cyan",       min_width=35)
    t.add_column("ACAO Header",  style="bold white", min_width=30)
    t.add_column("Risk",         width=12)

    misconfigs = []
    for origin in origins_to_test:
        r = _req(target, headers={"Origin": origin}, timeout=8)
        if r:
            acao = r.headers.get("Access-Control-Allow-Origin","")
            acac = r.headers.get("Access-Control-Allow-Credentials","")
            if acao == "*":
                risk = "[yellow]MEDIUM[/yellow]"
                misconfigs.append(origin)
            elif acao == origin or acao == "null":
                risk = "[red]HIGH[/red]" if acac == "true" else "[yellow]MEDIUM[/yellow]"
                misconfigs.append(origin)
            else:
                risk = "[green]Safe[/green]"
            t.add_row(origin[:40], acao[:30] or "Not Set", risk)

    console.print(t)

    # Show all CORS headers from main response
    r = _req(target, timeout=8)
    if r:
        cors_found = {h: r.headers.get(h) for h in CORS_HEADERS if h in r.headers}
        if cors_found:
            console.print("\n  [bold cyan]CORS Headers Found:[/bold cyan]")
            for k, v in cors_found.items():
                console.print(f"  [cyan]{k}:[/cyan] {v}")

    if misconfigs:
        theme.warn(f"CORS misconfiguration detected from {len(misconfigs)} origin(s)!")
        if project:
            db.add_finding(project["id"], f"CORS Misconfiguration: {target}",
                           "Server reflects arbitrary Origin headers, enabling cross-site attacks.",
                           "high", "CORS", target,
                           "Whitelist specific trusted origins only. Never reflect arbitrary origins.")
    else:
        theme.success("No CORS misconfigurations found.")
    console.input("\n  Press Enter to continue...")


# ── HTTP Method Tester ────────────────────────────────────────────────────────

def _http_methods(target):
    console.clear()
    target = _normalize_url(target)
    theme.section_header(f"HTTP METHOD TESTER — {target}")

    methods = ["GET","POST","PUT","DELETE","PATCH","OPTIONS","HEAD","TRACE","CONNECT"]
    t = Table(box=box.SIMPLE, header_style="bold cyan", border_style="dim cyan")
    t.add_column("Method",  style="bold white", width=10)
    t.add_column("Status",  width=8)
    t.add_column("Risk",    width=10)
    t.add_column("Note",    style="dim")

    risky = {"PUT":"[red]HIGH[/red]", "DELETE":"[red]HIGH[/red]",
             "TRACE":"[yellow]MED[/yellow]", "CONNECT":"[yellow]MED[/yellow]",
             "PATCH":"[yellow]MED[/yellow]"}

    with Progress(SpinnerColumn(), TextColumn("[cyan]Testing methods..."), transient=True) as p:
        p.add_task("")
        for method in methods:
            r = _req(target, method=method, timeout=6, allow_redirects=False)
            if r:
                risk = risky.get(method, "[green]Low[/green]")
                note = "Dangerous if enabled" if method in risky else ""
                code_color = "green" if r.status_code < 300 else "yellow" if r.status_code < 400 else "dim"
                t.add_row(method, f"[{code_color}]{r.status_code}[/{code_color}]", risk, note)

    console.print(t)
    console.input("\n  Press Enter to continue...")


# ── Open Redirect ─────────────────────────────────────────────────────────────

def _open_redirect(target, project=None):
    console.clear()
    theme.section_header(f"OPEN REDIRECT TESTER — {target}")

    redirect_payloads = [
        "//evil.com", "https://evil.com", "//evil.com/%2F..", "///evil.com",
        "https:evil.com", "/\\evil.com", "//evil%2Ecom",
    ]
    parsed  = urllib.parse.urlparse(target)
    params  = urllib.parse.parse_qs(parsed.query)
    if not params:
        params = {"url": ["test"], "redirect": ["test"], "next": ["test"],
                  "return": ["test"], "returnUrl": ["test"], "to": ["test"]}

    found = []
    for param in list(params.keys())[:5]:
        for payload in redirect_payloads:
            tp = dict(params)
            tp[param] = [payload]
            qs  = urllib.parse.urlencode(tp, doseq=True)
            url = urllib.parse.urlunparse(parsed._replace(query=qs))
            r   = _req(url, allow_redirects=False, timeout=6)
            if r and r.status_code in (301, 302, 303, 307, 308):
                loc = r.headers.get("Location","")
                if "evil.com" in loc:
                    console.print(f"  [red]✗ OPEN REDIRECT:[/red] {param}={payload}")
                    console.print(f"    Location: {loc}")
                    found.append({"param": param, "payload": payload, "location": loc})

    if found:
        theme.warn(f"{len(found)} open redirect(s) found!")
        if project:
            db.add_finding(project["id"], f"Open Redirect: {parsed.netloc}",
                           "Application redirects to attacker-controlled URLs.",
                           "medium", "Web", target,
                           "Validate and whitelist redirect destinations.")
    else:
        theme.success("No open redirects detected.")
    console.input("\n  Press Enter to continue...")


# ── Cookie Analyzer ──────────────────────────────────────────────────────────

def _cookie_analyzer(target, project=None):
    console.clear()
    target = _normalize_url(target)
    theme.section_header(f"COOKIE ANALYZER — {target}")

    r = _req(target, timeout=10)
    if not r:
        theme.error("Could not connect to target.")
        console.input("  Press Enter...")
        return

    cookies = r.cookies
    if not cookies:
        theme.warn("No cookies set by server.")
        console.input("  Press Enter...")
        return

    findings = []
    for cookie in cookies:
        t = Table(box=box.SIMPLE, header_style="bold cyan", border_style="dim cyan",
                  title=f"Cookie: {cookie.name}")
        t.add_column("Attribute",  style="cyan",       min_width=20)
        t.add_column("Value",      style="bold white", min_width=20)
        t.add_column("Status",     width=12)

        t.add_row("Name",     cookie.name,  "")
        t.add_row("Value",    (cookie.value or "")[:40], "")
        t.add_row("Domain",   cookie.domain or "N/A", "")
        t.add_row("Path",     cookie.path or "/", "")

        secure   = cookie.secure
        httponly = cookie.has_nonstandard_attr("HttpOnly") or "httponly" in str(cookie._rest).lower()
        samesite = cookie.get_nonstandard_attr("SameSite", "Not Set")

        t.add_row("Secure",   str(secure),
                  "[green]✓[/green]" if secure   else "[red]MISSING[/red]")
        t.add_row("HttpOnly", str(httponly),
                  "[green]✓[/green]" if httponly  else "[red]MISSING[/red]")
        t.add_row("SameSite", samesite,
                  "[green]✓[/green]" if samesite != "Not Set" else "[yellow]MISSING[/yellow]")

        console.print(t)
        console.print()

        if not secure:
            findings.append(f"Cookie '{cookie.name}' missing Secure flag")
        if not httponly:
            findings.append(f"Cookie '{cookie.name}' missing HttpOnly flag")

    if findings and project:
        for f in findings:
            db.add_finding(project["id"], f, "Cookie security attribute missing.",
                           "medium", "Cookie Security", target,
                           "Set Secure, HttpOnly, and SameSite flags on all cookies.")

    console.input("  Press Enter to continue...")


# ── Full Web Audit ────────────────────────────────────────────────────────────

def _full_web_audit(target, project=None):
    console.clear()
    theme.section_header(f"FULL WEB AUDIT — {target}")
    console.print("  [cyan]Running all web security checks...[/cyan]\n")

    _cms_detector(target, project)
    _cors_checker(target, project)
    _http_methods(target)
    _cookie_analyzer(target, project)
    _admin_finder(target, project)

    theme.success("Full web audit complete. Check findings in Intelligence Center.")
    console.input("\n  Press Enter to continue...")
