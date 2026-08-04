#!/usr/bin/env python3
"""
CyberMint — Cybersecurity Command Hub
Entry point
"""
import sys
import os

# Ensure project root is on the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rich.console import Console
from rich.prompt import Prompt

from core.engine import engine
from ui.theme import theme
from core.logger import get_logger

console = Console()
logger  = get_logger("Main")


def main():
    # Bootstrap
    try:
        engine.initialize()
    except Exception as e:
        console.print(f"[bold red]Failed to initialize CyberMint engine: {e}[/bold red]")
        sys.exit(1)

    current_project = None

    while True:
        theme.main_menu(
            version=engine.get_version(),
            modules_count=len(engine.list_modules()),
            plugins_count=len(engine.list_plugins()),
        )

        choice = Prompt.ask("\n  [cyan]>[/cyan] Select option", default="99")

        if choice == "99":
            console.print("\n  [bold cyan]CyberMint — Goodbye.[/bold cyan]\n")
            sys.exit(0)

        elif choice == "01":
            from modules.intelligence.intelligence import show_menu
            show_menu(current_project)

        elif choice == "02":
            from modules.recon.recon import show_menu
            show_menu(current_project)

        elif choice == "03":
            from modules.analysis.analysis import show_menu
            show_menu(current_project)

        elif choice == "04":
            from modules.network.network import show_menu
            show_menu(current_project)

        elif choice == "05":
            from modules.forensics.forensics import show_menu
            show_menu(current_project)

        elif choice == "06":
            from modules.threat.threat import show_menu
            show_menu(current_project)

        elif choice == "07":
            from modules.reports.reports import show_menu
            show_menu(current_project)

        elif choice == "08":
            from modules.plugins_manager import show_menu
            show_menu(current_project)

        elif choice == "09":
            from modules.settings import show_menu
            show_menu()

        else:
            theme.warn("Invalid option. Please try again.")


if __name__ == "__main__":
    main()
