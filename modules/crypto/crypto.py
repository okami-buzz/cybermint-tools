"""
CyberMint Password & Crypto Module
Hash ID, hash cracking, password gen, encoder/decoder, strength checker.
"""
import hashlib
import base64
import urllib.parse
import html
import random
import string
import re
import os
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt
from rich import box

from core.logger import get_logger
from ui.theme import theme

console = Console()
logger  = get_logger("Crypto")

HASH_SIGNATURES = {
    32:  ["MD5", "NTLM", "LM"],
    40:  ["SHA1", "MySQL", "SHA1(SHA1)"],
    56:  ["SHA224", "SHA3-224"],
    64:  ["SHA256", "SHA3-256", "BLAKE2s"],
    96:  ["SHA384", "SHA3-384"],
    128: ["SHA512", "Whirlpool", "SHA3-512", "BLAKE2b"],
    60:  ["bcrypt"],
    34:  ["MD5crypt ($1$)"],
}

MINI_WORDLIST = [
    "password","123456","password1","admin","letmein","qwerty","monkey","dragon",
    "master","hello","shadow","sunshine","princess","football","baseball","welcome",
    "login","pass","test","root","toor","abc123","111111","iloveyou","1234567890",
    "superman","batman","access","michael","charlie","jordan","ranger","solo",
    "trustno1","whatever","hunter","freedom","hockey","passw0rd","ninja","mustang",
    "123456789","1234","12345","1234567","password123","admin123","root123",
    "letmein123","qwerty123","dragon123","shadow123","master123","hello123",
]

LEET_MAP = {"a":"@","e":"3","i":"1","o":"0","s":"$","t":"7"}


def show_menu(current_project=None):
    while True:
        console.clear()
        theme.banner("PASSWORD & CRYPTO", "Hash Analysis, Cracking & Encoding")

        options = [
            ("[01]", "Hash Identifier",      "Detect hash type by length/format"),
            ("[02]", "Hash Generator",       "Generate hashes from any input"),
            ("[03]", "Hash Cracker",         "Crack hashes with wordlist"),
            ("[04]", "Password Generator",   "Strong random password builder"),
            ("[05]", "Wordlist Generator",   "Build target-based wordlists"),
            ("[06]", "Password Strength",    "Analyze password strength"),
            ("[07]", "Encoder / Decoder",    "Base64, Hex, URL, HTML, ROT13, Binary"),
            ("[08]", "String to Hashes",     "Hash a string in all algorithms"),
            ("[09]", "Brute Force Preview",  "Estimate brute-force crack time"),
            ("[00]", "Back to Main Menu",    ""),
        ]
        theme.menu_table(options)
        choice = theme.get_choice()

        if choice == "00":
            break
        elif choice == "01":
            h = Prompt.ask("  [cyan]Enter hash[/cyan]")
            _hash_identifier(h)
        elif choice == "02":
            text = Prompt.ask("  [cyan]Input string[/cyan]")
            _hash_generator(text)
        elif choice == "03":
            h  = Prompt.ask("  [cyan]Hash to crack[/cyan]")
            wl = Prompt.ask("  [cyan]Wordlist file (blank = built-in)[/cyan]", default="")
            _hash_cracker(h, wl)
        elif choice == "04":
            _password_generator()
        elif choice == "05":
            _wordlist_generator()
        elif choice == "06":
            pw = Prompt.ask("  [cyan]Password to analyze[/cyan]")
            _password_strength(pw)
        elif choice == "07":
            _encoder_decoder()
        elif choice == "08":
            text = Prompt.ask("  [cyan]Input string[/cyan]")
            _all_hashes(text)
        elif choice == "09":
            _bruteforce_estimate()


# ── Hash Identifier ───────────────────────────────────────────────────────────

def _hash_identifier(h):
    console.clear()
    theme.section_header("HASH IDENTIFIER")
    h = h.strip()

    console.print(f"  [cyan]Hash:[/cyan]   {h}")
    console.print(f"  [cyan]Length:[/cyan] {len(h)}\n")

    possibilities = []

    # By length
    if len(h) in HASH_SIGNATURES:
        possibilities += HASH_SIGNATURES[len(h)]

    # By pattern
    if h.startswith("$2"):
        possibilities = ["bcrypt"]
    elif h.startswith("$6$"):
        possibilities = ["SHA-512 crypt"]
    elif h.startswith("$5$"):
        possibilities = ["SHA-256 crypt"]
    elif h.startswith("$1$"):
        possibilities = ["MD5crypt"]
    elif h.startswith("$apr1$"):
        possibilities = ["Apache MD5"]
    elif re.match(r"^[a-fA-F0-9]+$", h):
        pass  # hex only — already handled by length
    elif re.match(r"^[a-zA-Z0-9+/=]+$", h):
        possibilities.append("Base64 encoded")

    if possibilities:
        t = Table(box=box.SIMPLE, header_style="bold cyan")
        t.add_column("#",       width=4, style="dim")
        t.add_column("Algorithm", style="bold white")
        t.add_column("Confidence", style="cyan")
        for i, p in enumerate(possibilities, 1):
            conf = "HIGH" if i == 1 else "MED"
            t.add_row(str(i), p, conf)
        console.print(t)
        theme.success(f"Most likely: {possibilities[0]}")
    else:
        theme.warn("Unknown hash type or not a standard hash.")
    console.input("\n  Press Enter to continue...")


# ── Hash Generator ────────────────────────────────────────────────────────────

def _hash_generator(text):
    console.clear()
    theme.section_header("HASH GENERATOR")

    algos = ["md5","sha1","sha224","sha256","sha384","sha512","sha3_256","sha3_512","blake2b","blake2s"]
    t = Table(box=box.SIMPLE, header_style="bold cyan", border_style="dim cyan")
    t.add_column("Algorithm", style="cyan",       min_width=12)
    t.add_column("Hash",      style="bold white")

    for a in algos:
        try:
            h = hashlib.new(a, text.encode()).hexdigest()
            t.add_row(a.upper(), h)
        except Exception:
            pass
    console.print(t)
    console.input("\n  Press Enter to continue...")


# ── Hash Cracker ──────────────────────────────────────────────────────────────

def _hash_cracker(target_hash, wordlist_path=""):
    console.clear()
    theme.section_header("HASH CRACKER")

    target_hash = target_hash.strip().lower()
    console.print(f"  [cyan]Target:[/cyan] {target_hash}  [dim](len={len(target_hash)})[/dim]\n")

    # Identify algorithm
    length_map = {32:"md5", 40:"sha1", 56:"sha224", 64:"sha256", 96:"sha384", 128:"sha512"}
    algo = length_map.get(len(target_hash), "md5")
    console.print(f"  [cyan]Guessed algorithm:[/cyan] {algo.upper()}\n")

    # Load wordlist
    if wordlist_path and os.path.exists(wordlist_path):
        with open(wordlist_path, "r", errors="replace") as f:
            words = [l.strip() for l in f if l.strip()]
    else:
        words = MINI_WORDLIST
        console.print(f"  [dim]Using built-in wordlist ({len(words)} words)[/dim]\n")

    # Also generate leet-speak variants
    extended = list(words)
    for w in words[:100]:
        leet = "".join(LEET_MAP.get(c, c) for c in w.lower())
        extended.extend([leet, w + "123", w + "!", w.capitalize(), w.upper()])

    cracked = None
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    with Progress(SpinnerColumn(), TextColumn("[cyan]Cracking... {task.completed}/{task.total}"),
                  BarColumn(), transient=True) as p:
        task = p.add_task("", total=len(extended))
        for word in extended:
            p.advance(task)
            try:
                h = hashlib.new(algo, word.encode()).hexdigest()
                if h == target_hash:
                    cracked = word
                    break
            except Exception:
                continue

    if cracked:
        console.print(Panel(
            f"  [bold green]✓ CRACKED![/bold green]\n\n"
            f"  Hash:      {target_hash}\n"
            f"  Plaintext: [bold white]{cracked}[/bold white]",
            border_style="green",
        ))
    else:
        theme.warn(f"Not cracked. Tried {len(extended):,} combinations.")
        console.print("  [dim]Tip: Provide a larger wordlist (e.g. rockyou.txt)[/dim]")
    console.input("\n  Press Enter to continue...")


# ── Password Generator ────────────────────────────────────────────────────────

def _password_generator():
    console.clear()
    theme.section_header("PASSWORD GENERATOR")

    length = int(Prompt.ask("  [cyan]Length[/cyan]", default="16"))
    ptype  = Prompt.ask("  [cyan]Type[/cyan]",
                         choices=["random","passphrase","pin","hex","base64"],
                         default="random")
    count  = int(Prompt.ask("  [cyan]Count[/cyan]", default="5"))

    WORDS = ["correct","horse","battery","staple","cloud","river","mountain",
             "dragon","storm","echo","falcon","ghost","hollow","iron","jade",
             "knight","lunar","marble","noble","ocean","polar","quick","raven",
             "silver","thunder","ultra","violet","winter","xray","yellow","zenith"]

    console.print()
    for i in range(count):
        if ptype == "random":
            chars = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
            pw    = "".join(random.choice(chars) for _ in range(length))
        elif ptype == "passphrase":
            pw = "-".join(random.choice(WORDS) for _ in range(max(4, length // 5)))
        elif ptype == "pin":
            pw = "".join(random.choice(string.digits) for _ in range(length))
        elif ptype == "hex":
            pw = os.urandom(length // 2).hex()
        elif ptype == "base64":
            pw = base64.b64encode(os.urandom(length)).decode()[:length]
        else:
            pw = ""

        console.print(f"  [bold cyan]{i+1:2}.[/bold cyan]  [bold white]{pw}[/bold white]")

    console.input("\n  Press Enter to continue...")


# ── Wordlist Generator ────────────────────────────────────────────────────────

def _wordlist_generator():
    console.clear()
    theme.section_header("WORDLIST GENERATOR")
    console.print("  [dim]Build a targeted wordlist from known information.[/dim]\n")

    name     = Prompt.ask("  [cyan]Name / username[/cyan]", default="")
    birthday = Prompt.ask("  [cyan]Birthday (DDMMYYYY or blank)[/cyan]", default="")
    keywords = Prompt.ask("  [cyan]Keywords (comma-separated)[/cyan]", default="")
    outfile  = Prompt.ask("  [cyan]Output file[/cyan]", default="wordlist.txt")

    base_words = [w.strip() for w in keywords.split(",") if w.strip()]
    if name:
        base_words += [name, name.lower(), name.upper(), name.capitalize()]
    if birthday:
        base_words += [birthday, birthday[:4], birthday[-4:], birthday[-2:]]

    generated = set()
    suffixes  = ["", "123", "1234", "!", "@", "2024", "2025", "2026",
                  "123!", "1", "12", "#", "pass", "pwd"]
    for w in base_words:
        for s in suffixes:
            generated.add(w + s)
            generated.add(w.capitalize() + s)
            generated.add(w.upper() + s)
            leet = "".join(LEET_MAP.get(c, c) for c in w.lower())
            generated.add(leet + s)

    with open(outfile, "w") as f:
        for w in sorted(generated):
            f.write(w + "\n")

    theme.success(f"Generated {len(generated)} words → {outfile}")
    console.input("  Press Enter to continue...")


# ── Password Strength ─────────────────────────────────────────────────────────

def _password_strength(pw):
    console.clear()
    theme.section_header("PASSWORD STRENGTH ANALYZER")

    score  = 0
    checks = []

    checks.append(("Length ≥ 8",   len(pw) >= 8,  1))
    checks.append(("Length ≥ 12",  len(pw) >= 12, 1))
    checks.append(("Length ≥ 16",  len(pw) >= 16, 1))
    checks.append(("Uppercase",    any(c.isupper() for c in pw), 1))
    checks.append(("Lowercase",    any(c.islower() for c in pw), 1))
    checks.append(("Digits",       any(c.isdigit() for c in pw), 1))
    checks.append(("Special chars",any(c in "!@#$%^&*()-_=+[]{}|;:',.<>?" for c in pw), 2))
    checks.append(("No common word",not any(w in pw.lower() for w in MINI_WORDLIST[:20]), 1))

    for label, passed, pts in checks:
        icon = "[green]✓[/green]" if passed else "[red]✗[/red]"
        console.print(f"  {icon}  {label}")
        if passed:
            score += pts

    max_score = sum(pts for _, _, pts in checks)
    pct = int(score / max_score * 100)
    color = "green" if pct >= 80 else "yellow" if pct >= 50 else "red"
    label = "STRONG" if pct >= 80 else "MODERATE" if pct >= 50 else "WEAK"

    console.print(f"\n  [bold cyan]Score:[/bold cyan] [{color}]{score}/{max_score}  {pct}%  — {label}[/{color}]")
    console.input("\n  Press Enter to continue...")


# ── Encoder / Decoder ─────────────────────────────────────────────────────────

def _encoder_decoder():
    while True:
        console.clear()
        theme.section_header("ENCODER / DECODER")

        options = [
            ("[01]", "Base64 Encode"),
            ("[02]", "Base64 Decode"),
            ("[03]", "Hex Encode"),
            ("[04]", "Hex Decode"),
            ("[05]", "URL Encode"),
            ("[06]", "URL Decode"),
            ("[07]", "HTML Encode"),
            ("[08]", "HTML Decode"),
            ("[09]", "ROT13"),
            ("[10]", "Binary Encode"),
            ("[11]", "Binary Decode"),
            ("[12]", "Caesar Cipher"),
            ("[00]", "Back"),
        ]
        for key, label in options:
            console.print(f"  [bold cyan]{key}[/bold cyan]  {label}")

        choice = theme.get_choice()
        if choice == "00":
            break

        text = Prompt.ask("  [cyan]Input[/cyan]")
        result = ""
        try:
            if choice == "01":
                result = base64.b64encode(text.encode()).decode()
            elif choice == "02":
                result = base64.b64decode(text.encode()).decode(errors="replace")
            elif choice == "03":
                result = text.encode().hex()
            elif choice == "04":
                result = bytes.fromhex(text).decode(errors="replace")
            elif choice == "05":
                result = urllib.parse.quote(text)
            elif choice == "06":
                result = urllib.parse.unquote(text)
            elif choice == "07":
                result = html.escape(text)
            elif choice == "08":
                result = html.unescape(text)
            elif choice == "09":
                result = text.translate(str.maketrans(
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
                    "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"))
            elif choice == "10":
                result = " ".join(format(ord(c), "08b") for c in text)
            elif choice == "11":
                result = "".join(chr(int(b, 2)) for b in text.split())
            elif choice == "12":
                shift  = int(Prompt.ask("  Shift (1-25)", default="13"))
                result = "".join(
                    chr((ord(c) - (65 if c.isupper() else 97) + shift) % 26
                        + (65 if c.isupper() else 97)) if c.isalpha() else c
                    for c in text)
        except Exception as e:
            result = f"Error: {e}"

        console.print(Panel(f"  [bold white]{result}[/bold white]",
                            title="[bold cyan][ Result ][/bold cyan]",
                            border_style="cyan"))
        console.input("  Press Enter to continue...")


# ── All Hashes ────────────────────────────────────────────────────────────────

def _all_hashes(text):
    console.clear()
    theme.section_header(f"ALL HASHES — '{text[:30]}'")
    algos = ["md5","sha1","sha224","sha256","sha384","sha512",
             "sha3_256","sha3_512","blake2b","blake2s"]
    t = Table(box=box.SIMPLE, header_style="bold cyan")
    t.add_column("Algorithm", style="cyan",       width=15)
    t.add_column("Hash",      style="bold white")
    for a in algos:
        try:
            t.add_row(a.upper(), hashlib.new(a, text.encode()).hexdigest())
        except Exception:
            pass
    console.print(t)
    console.input("\n  Press Enter to continue...")


# ── Brute Force Estimate ──────────────────────────────────────────────────────

def _bruteforce_estimate():
    console.clear()
    theme.section_header("BRUTE FORCE TIME ESTIMATE")

    length  = int(Prompt.ask("  [cyan]Password length[/cyan]", default="8"))
    charset = Prompt.ask("  [cyan]Charset[/cyan]",
                          choices=["digits","lower","upper","mixed","full"],
                          default="full")
    speed   = int(Prompt.ask("  [cyan]Guesses/sec (e.g. 1000000)[/cyan]", default="1000000"))

    sizes = {"digits":10,"lower":26,"upper":26,"mixed":52,"full":95}
    chars = sizes.get(charset, 95)
    combinations = chars ** length

    seconds = combinations / speed
    minutes = seconds / 60
    hours   = minutes / 60
    days    = hours / 24
    years   = days / 365

    t = Table(box=box.SIMPLE, header_style="bold cyan")
    t.add_column("Metric",  style="cyan",       min_width=25)
    t.add_column("Value",   style="bold white")

    t.add_row("Password Length",    str(length))
    t.add_row("Charset Size",       f"{chars} chars")
    t.add_row("Total Combinations", f"{combinations:,}")
    t.add_row("Guesses/Second",     f"{speed:,}")
    t.add_row("Time (seconds)",     f"{seconds:,.0f}")
    t.add_row("Time (hours)",       f"{hours:,.2f}")
    t.add_row("Time (days)",        f"{days:,.2f}")
    t.add_row("Time (years)",       f"{years:,.2f}")

    console.print(t)
    if years > 1000:
        console.print("\n  [green]✓ Effectively uncrackable by brute force.[/green]")
    elif years > 1:
        console.print(f"\n  [yellow]⚠ Crackable in {years:.0f} year(s).[/yellow]")
    else:
        console.print(f"\n  [red]✗ Crackable in {days:.1f} day(s)![/red]")
    console.input("\n  Press Enter to continue...")
