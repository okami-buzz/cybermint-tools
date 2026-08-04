"""
CyberMint Plugin Manager
Browse, inspect, and run loaded plugins.
"""
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt
from rich import box

from core.engine import engine
from ui.theme import theme

console = Console()


def show_menu(current_project=None):
    while True:
        console.clear()
        theme.banner("PLUGIN MANAGER", "Extend CyberMint with Custom Modules")

        plugins = engine.list_plugins()
        options = [
            ("[01]", "List Plugins",     "Show all loaded plugins"),
            ("[02]", "Plugin Details",   "View plugin information"),
            ("[03]", "Launch Plugin",    "Run a plugin module"),
            ("[04]", "Reload Plugins",   "Hot-reload plugin directory"),
            ("[00]", "Back to Main Menu",""),
        ]
        theme.menu_table(options)
        console.print(f"\n  [dim]Loaded plugins: {len(plugins)}[/dim]")

        choice = Prompt.ask("\n  [cyan]>[/cyan] Select option", default="00")

        if choice == "00":
            break
        elif choice == "01":
            _list_plugins()
        elif choice == "02":
            _plugin_details()
        elif choice == "03":
            _launch_plugin(current_project)
        elif choice == "04":
            engine._load_plugins()
            theme.success("Plugins reloaded.")
            console.input("  Press Enter...")


def _list_plugins():
    console.clear()
    theme.section_header("LOADED PLUGINS")
    plugins = engine.list_plugins()
    if not plugins:
        theme.warn("No plugins loaded.")
        console.input("  Press Enter...")
        return

    t = Table(box=box.SIMPLE, header_style="bold cyan", border_style="dim cyan")
    t.add_column("#",    width=4,  style="dim")
    t.add_column("Name", style="bold white", min_width=30)
    t.add_column("Info", style="dim")

    for i, name in enumerate(plugins, 1):
        mod  = engine.plugins.get(name)
        info = ""
        if mod and hasattr(mod, "get_info"):
            d = mod.get_info()
            info = f"v{d.get('version','')} — {d.get('description','')}"[:60]
        t.add_row(str(i), name, info)

    console.print(t)
    console.input("\n  Press Enter to continue...")


def _plugin_details():
    console.clear()
    theme.section_header("PLUGIN DETAILS")
    plugins = engine.list_plugins()
    if not plugins:
        theme.warn("No plugins loaded.")
        console.input("  Press Enter...")
        return

    for i, name in enumerate(plugins, 1):
        console.print(f"  [{i}] {name}")
    idx = Prompt.ask("  [cyan]Select plugin number[/cyan]", default="1")
    try:
        plugin_name = plugins[int(idx) - 1]
        mod = engine.plugins.get(plugin_name)
        if mod and hasattr(mod, "get_info"):
            info = mod.get_info()
            console.print(Panel(
                "\n".join(f"  [cyan]{k}:[/cyan] {v}" for k, v in info.items()),
                title=f"[bold cyan][ {plugin_name} ][/bold cyan]",
                border_style="cyan",
            ))
        else:
            theme.warn("Plugin has no info.")
    except (ValueError, IndexError):
        theme.error("Invalid selection.")

    console.input("\n  Press Enter to continue...")


def _launch_plugin(project=None):
    console.clear()
    theme.section_header("LAUNCH PLUGIN")
    plugins = engine.list_plugins()
    if not plugins:
        theme.warn("No plugins loaded.")
        console.input("  Press Enter...")
        return

    for i, name in enumerate(plugins, 1):
        console.print(f"  [{i}] {name}")
    idx = Prompt.ask("  [cyan]Select plugin number[/cyan]", default="1")
    try:
        plugin_name = plugins[int(idx) - 1]
        mod = engine.plugins.get(plugin_name)
        if mod and hasattr(mod, "show_menu"):
            mod.show_menu(project)
        else:
            theme.warn("This plugin has no interactive menu.")
            console.input("  Press Enter...")
    except (ValueError, IndexError):
        theme.error("Invalid selection.")
        console.input("  Press Enter...")
