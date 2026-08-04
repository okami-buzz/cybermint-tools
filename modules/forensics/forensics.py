"""
CyberMint Digital Forensics Center
File analysis, hashing, metadata, integrity monitoring.
"""
import hashlib
import os
import json
import re
from pathlib import Path
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt
from rich import box
from rich.progress import Progress, SpinnerColumn, TextColumn

import core.database as db
from core.logger import get_logger
from ui.theme import theme

console = Console()
logger = get_logger("Forensics")


def show_menu(current_project=None):
    while True:
        console.clear()
        theme.banner("DIGITAL FORENSICS", "File Analysis & Integrity")

        options = [
            ("[01]", "File Hash Generator",  "MD5, SHA1, SHA256, SHA512"),
            ("[02]", "File Metadata",        "Timestamps, size, type"),
            ("[03]", "Hash Comparison",      "Compare file hashes"),
            ("[04]", "Directory Integrity",  "Hash all files in a directory"),
            ("[05]", "Log Analyzer",         "Search logs for patterns"),
            ("[06]", "String Extractor",     "Extract strings from a file"),
            ("[07]", "Saved Hashes",         "View stored hash records"),
            ("[00]", "Back to Main Menu",    ""),
        ]
        theme.menu_table(options)

        choice = Prompt.ask("\n  [cyan]>[/cyan] Select option", default="00")

        if choice == "00":
            break
        elif choice == "01":
            fp = Prompt.ask("  [cyan]File path[/cyan]")
            _hash_file(fp, current_project)
        elif choice == "02":
            fp = Prompt.ask("  [cyan]File path[/cyan]")
            _file_metadata(fp)
        elif choice == "03":
            fp1 = Prompt.ask("  [cyan]First file[/cyan]")
            fp2 = Prompt.ask("  [cyan]Second file[/cyan]")
            _compare_hashes(fp1, fp2)
        elif choice == "04":
            dp = Prompt.ask("  [cyan]Directory path[/cyan]")
            _directory_integrity(dp, current_project)
        elif choice == "05":
            lp = Prompt.ask("  [cyan]Log file path[/cyan]")
            _log_analyzer(lp)
        elif choice == "06":
            fp = Prompt.ask("  [cyan]File path[/cyan]")
            _string_extractor(fp)
        elif choice == "07":
            _show_saved_hashes(current_project)


def _compute_hashes(filepath):
    algos = {
        "MD5":    hashlib.md5(),
        "SHA1":   hashlib.sha1(),
        "SHA256": hashlib.sha256(),
        "SHA512": hashlib.sha512(),
    }
    size = 0
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            size += len(chunk)
            for h in algos.values():
                h.update(chunk)
    return {k: v.hexdigest() for k, v in algos.items()}, size


def _hash_file(filepath, project=None):
    console.clear()
    theme.section_header(f"FILE HASH — {filepath}")

    p = Path(filepath)
    if not p.exists():
        theme.error(f"File not found: {filepath}")
        console.input("  Press Enter...")
        return

    try:
        with Progress(SpinnerColumn(), TextColumn("[cyan]Hashing..."), transient=True) as prog:
            prog.add_task("")
            hashes, size = _compute_hashes(filepath)

        t = Table(box=box.SIMPLE, header_style="bold cyan", border_style="dim cyan")
        t.add_column("Algorithm", style="cyan",       width=10)
        t.add_column("Hash",      style="bold white", min_width=64)

        for alg, val in hashes.items():
            t.add_row(alg, val)

        console.print(t)
        console.print(f"\n  [cyan]File Size:[/cyan] {size:,} bytes")
        theme.success("Hashing complete.")

        if project and Prompt.ask("\n  Save to project?", choices=["y","n"], default="y") == "y":
            db.save_scan(project["id"], "file_hash", filepath,
                         f"Hashed {p.name}", hashes)
            theme.success("Saved.")

    except Exception as e:
        theme.error(f"Hashing failed: {e}")

    console.input("\n  Press Enter to continue...")


def _file_metadata(filepath):
    console.clear()
    theme.section_header(f"FILE METADATA — {filepath}")

    p = Path(filepath)
    if not p.exists():
        theme.error("File not found.")
        console.input("  Press Enter...")
        return

    stat = p.stat()
    t = Table(box=box.SIMPLE, header_style="bold cyan", border_style="dim cyan")
    t.add_column("Property",  style="cyan",       min_width=22)
    t.add_column("Value",     style="bold white")

    t.add_row("Name",          p.name)
    t.add_row("Path",          str(p.resolve()))
    t.add_row("Type",          "Directory" if p.is_dir() else "File")
    t.add_row("Extension",     p.suffix or "none")
    t.add_row("Size",          f"{stat.st_size:,} bytes")
    t.add_row("Created",       datetime.fromtimestamp(stat.st_ctime).strftime("%Y-%m-%d %H:%M:%S"))
    t.add_row("Modified",      datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"))
    t.add_row("Accessed",      datetime.fromtimestamp(stat.st_atime).strftime("%Y-%m-%d %H:%M:%S"))
    t.add_row("Permissions",   oct(stat.st_mode)[-3:])

    console.print(t)
    console.input("\n  Press Enter to continue...")


def _compare_hashes(fp1, fp2):
    console.clear()
    theme.section_header("HASH COMPARISON")

    for fp in [fp1, fp2]:
        if not Path(fp).exists():
            theme.error(f"File not found: {fp}")
            console.input("  Press Enter...")
            return

    with Progress(SpinnerColumn(), TextColumn("[cyan]Computing hashes..."), transient=True) as p:
        p.add_task("")
        h1, s1 = _compute_hashes(fp1)
        h2, s2 = _compute_hashes(fp2)

    t = Table(box=box.SIMPLE, header_style="bold cyan", border_style="dim cyan")
    t.add_column("Algorithm", style="cyan",  width=10)
    t.add_column("File 1",    min_width=32)
    t.add_column("File 2",    min_width=32)
    t.add_column("Match",     width=8)

    all_match = True
    for alg in ["MD5","SHA1","SHA256"]:
        match = h1[alg] == h2[alg]
        if not match:
            all_match = False
        status = "[green]✓[/green]" if match else "[red]✗[/red]"
        t.add_row(alg, h1[alg][:32]+"...", h2[alg][:32]+"...", status)

    console.print(t)
    console.print(f"\n  File 1: {s1:,} bytes  |  File 2: {s2:,} bytes")

    if all_match:
        console.print("\n  [bold green]✓ Files are IDENTICAL[/bold green]")
    else:
        console.print("\n  [bold red]✗ Files are DIFFERENT[/bold red]")

    console.input("\n  Press Enter to continue...")


def _directory_integrity(dirpath, project=None):
    console.clear()
    theme.section_header(f"DIRECTORY INTEGRITY — {dirpath}")

    d = Path(dirpath)
    if not d.exists() or not d.is_dir():
        theme.error("Directory not found.")
        console.input("  Press Enter...")
        return

    files = [f for f in d.rglob("*") if f.is_file()]
    results = {}

    with Progress(SpinnerColumn(), TextColumn("[cyan]Hashing files..."), transient=True) as p:
        task = p.add_task("", total=len(files))
        for f in files:
            try:
                hashes, _ = _compute_hashes(f)
                results[str(f.relative_to(d))] = hashes["SHA256"]
            except Exception:
                results[str(f.relative_to(d))] = "ERROR"
            p.advance(task)

    t = Table(box=box.SIMPLE, header_style="bold cyan", border_style="dim cyan")
    t.add_column("File",    style="bold white", min_width=40)
    t.add_column("SHA256",  style="dim",        min_width=64)
    for fname, sha in list(results.items())[:20]:
        t.add_row(fname, sha)
    if len(results) > 20:
        console.print(f"  [dim]... and {len(results)-20} more files[/dim]")
    console.print(t)

    if project:
        db.save_scan(project["id"], "dir_integrity", dirpath,
                     f"Hashed {len(results)} files in {dirpath}", results)
        theme.success("Integrity snapshot saved.")

    console.input("\n  Press Enter to continue...")


def _log_analyzer(logpath):
    console.clear()
    theme.section_header(f"LOG ANALYZER — {logpath}")

    p = Path(logpath)
    if not p.exists():
        theme.error("File not found.")
        console.input("  Press Enter...")
        return

    patterns = {
        "IP Address":     r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        "Email":          r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        "Error":          r"(?i)(error|exception|fail|traceback|critical)",
        "HTTP Status":    r"\b[45]\d{2}\b",
        "Date/Time":      r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}",
    }

    console.print(f"  [cyan]Analyzing:[/cyan] {p.name}  ({p.stat().st_size:,} bytes)\n")

    try:
        with open(logpath, "r", errors="replace") as f:
            content = f.read()

        t = Table(box=box.SIMPLE, header_style="bold cyan")
        t.add_column("Pattern",   style="cyan",       min_width=15)
        t.add_column("Matches",   justify="center",   width=10)
        t.add_column("Examples",  style="dim")

        for name, pattern in patterns.items():
            matches = re.findall(pattern, content)
            unique  = list(dict.fromkeys(matches))[:3]
            t.add_row(name, str(len(matches)), "  ".join(unique))

        console.print(t)
        theme.success("Log analysis complete.")

    except Exception as e:
        theme.error(f"Failed to analyze log: {e}")

    console.input("\n  Press Enter to continue...")


def _string_extractor(filepath):
    console.clear()
    theme.section_header(f"STRING EXTRACTOR — {filepath}")

    if not Path(filepath).exists():
        theme.error("File not found.")
        console.input("  Press Enter...")
        return

    min_len = 4
    strings = []
    try:
        with open(filepath, "rb") as f:
            data = f.read()
        pattern = re.compile(rb"[ -~]{%d,}" % min_len)
        for m in pattern.finditer(data):
            s = m.group().decode(errors="replace").strip()
            if s:
                strings.append(s)

        console.print(f"  [cyan]Found {len(strings)} strings (min length {min_len})[/cyan]\n")
        for s in strings[:50]:
            console.print(f"  [dim]{s[:100]}[/dim]")
        if len(strings) > 50:
            console.print(f"\n  [dim]... and {len(strings)-50} more[/dim]")

    except Exception as e:
        theme.error(f"Failed: {e}")

    console.input("\n  Press Enter to continue...")


def _show_saved_hashes(project=None):
    console.clear()
    theme.section_header("SAVED HASH RECORDS")
    pid = project["id"] if project else None
    history = [h for h in db.get_scan_history(pid) if h["module"] == "file_hash"]
    if not history:
        theme.warn("No saved hashes found.")
        console.input("  Press Enter...")
        return

    t = Table(box=box.SIMPLE, header_style="bold cyan")
    t.add_column("Date",  style="dim",        width=17)
    t.add_column("File",  style="bold white", min_width=30)
    t.add_column("Summary")
    for h in history:
        t.add_row(h["created_at"][:16], h["target"] or "", h["result_summary"] or "")
    console.print(t)
    console.input("\n  Press Enter to continue...")
