"""
CyberMint Network Center
Network analysis, device inventory, service information.
"""
import socket
import struct
import subprocess
import platform
import ipaddress
import re
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt
from rich import box
from rich.progress import Progress, SpinnerColumn, TextColumn

import core.database as db
from core.logger import get_logger
from ui.theme import theme

console = Console()
logger = get_logger("Network")


def show_menu(current_project=None):
    while True:
        console.clear()
        theme.banner("NETWORK CENTER", "Network Analysis & Device Inventory")

        options = [
            ("[01]", "Network Information",  "Local network details"),
            ("[02]", "Device Discovery",     "Ping sweep local subnet"),
            ("[03]", "Service Info",         "Port/service lookup"),
            ("[04]", "DNS Resolver",         "Resolve hostname to IP"),
            ("[05]", "Traceroute",           "Trace network path"),
            ("[06]", "IP Geolocation",       "Locate an IP address"),
            ("[07]", "Network Report",       "Generate network summary"),
            ("[00]", "Back to Main Menu",    ""),
        ]
        theme.menu_table(options)

        choice = theme.get_choice()

        if choice == "00":
            break
        elif choice == "01":
            _network_info()
        elif choice == "02":
            subnet = Prompt.ask("  [cyan]Subnet (e.g. 192.168.1.0/24)[/cyan]", default="")
            _device_discovery(subnet)
        elif choice == "03":
            host   = Prompt.ask("  [cyan]Host/IP[/cyan]")
            _service_info(host)
        elif choice == "04":
            host   = Prompt.ask("  [cyan]Hostname[/cyan]")
            _dns_resolve(host)
        elif choice == "05":
            host   = Prompt.ask("  [cyan]Target host[/cyan]")
            _traceroute(host)
        elif choice == "06":
            ip     = Prompt.ask("  [cyan]IP address[/cyan]")
            _ip_geo(ip)
        elif choice == "07":
            _network_report(current_project)


def _network_info():
    console.clear()
    theme.section_header("NETWORK INFORMATION")

    t = Table(box=box.SIMPLE, header_style="bold cyan", border_style="dim cyan")
    t.add_column("Property", style="cyan", min_width=25)
    t.add_column("Value",    style="bold white")

    hostname = socket.gethostname()
    t.add_row("Hostname", hostname)

    try:
        local_ip = socket.gethostbyname(hostname)
        t.add_row("Local IP", local_ip)
    except Exception:
        t.add_row("Local IP", "N/A")

    try:
        ext_ip = _get_external_ip()
        t.add_row("External IP", ext_ip or "N/A")
    except Exception:
        t.add_row("External IP", "N/A")

    t.add_row("Platform", platform.system() + " " + platform.release())
    t.add_row("Python",   platform.python_version())

    console.print(t)
    console.input("\n  Press Enter to continue...")


def _get_external_ip():
    import requests
    try:
        r = requests.get("https://api.ipify.org", timeout=5)
        return r.text.strip()
    except Exception:
        return None


def _device_discovery(subnet):
    console.clear()
    theme.section_header("DEVICE DISCOVERY")

    if not subnet:
        try:
            local_ip = socket.gethostbyname(socket.gethostname())
            parts = local_ip.rsplit(".", 1)
            subnet = parts[0] + ".0/24"
        except Exception:
            subnet = "192.168.1.0/24"

    console.print(f"  [cyan]Scanning:[/cyan] {subnet}\n")
    live_hosts = []

    try:
        network = ipaddress.ip_network(subnet, strict=False)
        hosts   = list(network.hosts())[:254]

        with Progress(SpinnerColumn(), TextColumn(f"[cyan]Pinging {len(hosts)} hosts..."),
                      transient=True) as p:
            p.add_task("")
            for host in hosts:
                ip = str(host)
                param = "-n" if platform.system().lower() == "windows" else "-c"
                result = subprocess.run(
                    ["ping", param, "1", "-W", "1", ip],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2
                )
                if result.returncode == 0:
                    try:
                        name = socket.gethostbyaddr(ip)[0]
                    except Exception:
                        name = ""
                    live_hosts.append({"ip": ip, "hostname": name})

        if live_hosts:
            t = Table(box=box.SIMPLE, header_style="bold cyan", border_style="dim cyan")
            t.add_column("#",        width=4,  style="dim")
            t.add_column("IP",       style="bold white")
            t.add_column("Hostname", style="cyan")
            t.add_column("Status",   width=10)
            for i, h in enumerate(live_hosts, 1):
                t.add_row(str(i), h["ip"], h["hostname"] or "—", "[green]UP[/green]")
            console.print(t)
            theme.success(f"{len(live_hosts)} host(s) found.")
        else:
            theme.warn("No live hosts found.")

    except ValueError as e:
        theme.error(f"Invalid subnet: {e}")
    except Exception as e:
        theme.error(f"Discovery failed: {e}")

    console.input("\n  Press Enter to continue...")


def _service_info(host):
    console.clear()
    theme.section_header(f"SERVICE INFO — {host}")

    common_ports = {
        21: "FTP",    22: "SSH",    23: "Telnet",  25: "SMTP",
        53: "DNS",    80: "HTTP",   110: "POP3",   143: "IMAP",
        443: "HTTPS", 445: "SMB",   3306: "MySQL", 3389: "RDP",
        5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt",
        27017: "MongoDB", 1433: "MSSQL", 5900: "VNC",
    }

    t = Table(box=box.SIMPLE, header_style="bold cyan", border_style="dim cyan")
    t.add_column("Port",    style="bold white", width=8)
    t.add_column("Service", style="cyan",       width=15)
    t.add_column("Status",  width=10)
    t.add_column("Banner",  style="dim")

    with Progress(SpinnerColumn(), TextColumn("[cyan]Checking ports..."), transient=True) as p:
        p.add_task("")
        for port, service in common_ports.items():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.8)
                if s.connect_ex((host, port)) == 0:
                    banner = ""
                    try:
                        s.send(b"\r\n")
                        banner = s.recv(64).decode(errors="replace").strip()[:40]
                    except Exception:
                        pass
                    s.close()
                    t.add_row(str(port), service, "[green]OPEN[/green]", banner)
                else:
                    s.close()
            except Exception:
                pass

    console.print(t)
    console.input("\n  Press Enter to continue...")


def _dns_resolve(host):
    console.clear()
    theme.section_header(f"DNS RESOLVER — {host}")
    try:
        results = socket.getaddrinfo(host, None)
        t = Table(box=box.SIMPLE, header_style="bold cyan")
        t.add_column("Family",  style="cyan")
        t.add_column("Address", style="bold white")
        seen = set()
        for item in results:
            addr = item[4][0]
            fam  = "IPv6" if ":" in addr else "IPv4"
            if addr not in seen:
                t.add_row(fam, addr)
                seen.add(addr)
        console.print(t)
        theme.success("Resolution complete.")
    except socket.gaierror as e:
        theme.error(f"Could not resolve: {e}")
    console.input("\n  Press Enter to continue...")


def _traceroute(host):
    console.clear()
    theme.section_header(f"TRACEROUTE — {host}")
    console.print("  [dim]Running traceroute (may take a moment)...[/dim]\n")

    cmd = ["tracert", "-d", "-w", "500", host] if platform.system().lower() == "windows" \
          else ["traceroute", "-n", "-w", "2", "-q", "1", host]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        output = result.stdout or result.stderr
        for line in output.splitlines()[:25]:
            if line.strip():
                console.print(f"  [dim]{line}[/dim]")
    except FileNotFoundError:
        theme.warn("traceroute not available on this system.")
    except subprocess.TimeoutExpired:
        theme.warn("Traceroute timed out.")
    except Exception as e:
        theme.error(f"Traceroute failed: {e}")

    console.input("\n  Press Enter to continue...")


def _ip_geo(ip):
    console.clear()
    theme.section_header(f"IP GEOLOCATION — {ip}")
    import requests as req
    try:
        r = req.get(f"https://ipapi.co/{ip}/json/", timeout=8)
        if r.status_code == 200:
            data = r.json()
            if "error" in data:
                theme.error(f"API error: {data.get('reason', 'Unknown')}")
            else:
                t = Table(box=box.SIMPLE, header_style="bold cyan", border_style="dim cyan")
                t.add_column("Field",  style="cyan",       min_width=20)
                t.add_column("Value",  style="bold white")
                fields = [
                    ("IP",           data.get("ip")),
                    ("City",         data.get("city")),
                    ("Region",       data.get("region")),
                    ("Country",      data.get("country_name")),
                    ("Postal Code",  data.get("postal")),
                    ("Latitude",     data.get("latitude")),
                    ("Longitude",    data.get("longitude")),
                    ("ISP / Org",    data.get("org")),
                    ("ASN",          data.get("asn")),
                    ("Timezone",     data.get("timezone")),
                ]
                for k, v in fields:
                    if v:
                        t.add_row(k, str(v))
                console.print(t)
        else:
            theme.error(f"HTTP {r.status_code}")
    except Exception as e:
        theme.error(f"Geolocation failed: {e}")

    console.input("\n  Press Enter to continue...")


def _network_report(project=None):
    console.clear()
    theme.section_header("NETWORK REPORT")

    hostname  = socket.gethostname()
    ext_ip    = _get_external_ip() or "N/A"
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    report = f"""CyberMint Network Report
========================
Generated: {timestamp}

Host:      {hostname}
Ext IP:    {ext_ip}
Platform:  {platform.system()} {platform.release()}
"""
    console.print(report)

    if project:
        db.save_scan(project["id"], "network_report", hostname,
                     "Network report generated", {"hostname": hostname, "ext_ip": ext_ip})
        theme.success("Report saved to project.")

    console.input("  Press Enter to continue...")
