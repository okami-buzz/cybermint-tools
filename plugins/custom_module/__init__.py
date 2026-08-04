"""
CyberMint Custom Module Plugin Template

To create your own plugin:
1. Copy this folder and rename it.
2. Implement `get_info()` and optionally `show_menu(project)`.
3. Your plugin will be auto-loaded by the Plugin Manager.
"""

PLUGIN_INFO = {
    "name":        "Custom Module Template",
    "version":     "1.0.0",
    "author":      "Your Name",
    "description": "A blank plugin template for custom CyberMint modules.",
    "category":    "custom",
}


def get_info():
    return PLUGIN_INFO


def show_menu(current_project=None):
    from rich.console import Console
    from rich.prompt import Prompt
    c = Console()
    c.print("\n  [bold cyan]Custom Module[/bold cyan]  — Edit plugins/custom_module/__init__.py to build your module.\n")
    Prompt.ask("  Press Enter to go back")
