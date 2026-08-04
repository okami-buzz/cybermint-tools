"""
CyberMint UI Theme — Dark Cyan Terminal Aesthetic
"""
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

console = Console()


class CyberMintTheme:

    BANNER_LINES = [
        "  ██████╗██╗   ██╗██████╗ ███████╗██████╗ ███╗   ███╗██╗███╗   ██╗████████╗",
        "  ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗████╗ ████║██║████╗  ██║╚══██╔══╝",
        "  ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██╔████╔██║██║██╔██╗ ██║   ██║   ",
        "  ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██║╚██╔╝██║██║██║╚██╗██║   ██║   ",
        "  ╚██████╗   ██║   ██████╔╝███████╗██║  ██║██║ ╚═╝ ██║██║██║ ╚████║   ██║   ",
        "   ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝   ╚═╝  ",
    ]

    def banner(self, title: str = "", subtitle: str = ""):
        console.clear()
        console.print()
        for line in self.BANNER_LINES:
            console.print(f"[bold cyan]{line}[/bold cyan]")
        console.print()
        if title:
            console.print(
                Panel(
                    f"[bold cyan]{title}[/bold cyan]\n[dim]{subtitle}[/dim]",
                    border_style="cyan",
                    padding=(0, 4),
                    expand=False,
                )
            )
            console.print()

    def section_header(self, title: str):
        console.print()
        console.print(f"  [bold cyan]╔{'═' * (len(title) + 4)}╗[/bold cyan]")
        console.print(f"  [bold cyan]║  {title}  ║[/bold cyan]")
        console.print(f"  [bold cyan]╚{'═' * (len(title) + 4)}╝[/bold cyan]")
        console.print()

    def menu_table(self, options: list):
        t = Table(
            box=box.SIMPLE,
            show_header=False,
            padding=(0, 2),
            border_style="dim cyan",
        )
        t.add_column("Key",    style="bold cyan",  width=8)
        t.add_column("Label",  style="bold white", min_width=24)
        t.add_column("Desc",   style="dim")

        for key, label, desc in options:
            t.add_row(key, label, desc)
        console.print(t)

    def success(self, msg: str):
        console.print(f"\n  [bold green]✓[/bold green]  {msg}")

    def warn(self, msg: str):
        console.print(f"\n  [bold yellow]⚠[/bold yellow]  {msg}")

    def error(self, msg: str):
        console.print(f"\n  [bold red]✗[/bold red]  {msg}")

    def info(self, msg: str):
        console.print(f"\n  [bold cyan]ℹ[/bold cyan]  {msg}")

    def divider(self):
        console.print(f"  [dim cyan]{'─' * 60}[/dim cyan]")

    def main_menu(self, version: str, modules_count: int, plugins_count: int):
        self.banner()
        options = [
            ("[01]", "Intelligence",       "Asset intelligence & risk analysis"),
            ("[02]", "Recon Center",       "Information gathering & footprinting"),
            ("[03]", "Security Analysis",  "Config checks & vulnerability assessment"),
            ("[04]", "Network Center",     "Network analysis & device inventory"),
            ("[05]", "Digital Forensics",  "File analysis & integrity"),
            ("[06]", "Threat Intelligence","IOC management & threat research"),
            ("[07]", "Report Center",      "Professional security reports"),
            ("[08]", "Plugin Manager",     "Manage & load plugins"),
            ("[09]", "Settings",           "Configuration & system info"),
            ("[99]", "Exit",               ""),
        ]
        self.menu_table(options)
        console.print(
            f"\n  [dim]v{version} │ Modules: {modules_count} │ Plugins: {plugins_count}[/dim]"
        )


theme = CyberMintTheme()
