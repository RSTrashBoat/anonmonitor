#!/usr/bin/env python3
import subprocess
import sys
import os
import time
import shutil
import random

try:
    import requests
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "requests", "--break-system-packages", "-q"])
    import requests

R      = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
WHITE  = "\033[97m"
CLEAR  = "\033[2J\033[H"

REFRESH = 10

LOGO = [
    "   █████╗ ███╗   ██╗ ██████╗ ███╗   ██╗███╗   ███╗ ██████╗ ███╗   ██╗██╗████████╗ ██████╗ ██████╗ ",
    "  ██╔══██╗████╗  ██║██╔═══██╗████╗  ██║████╗ ████║██╔═══██╗████╗  ██║██║╚══██╔══╝██╔═══██╗██╔══██╗",
    "  ███████║██╔██╗ ██║██║   ██║██╔██╗ ██║██╔████╔██║██║   ██║██╔██╗ ██║██║   ██║   ██║   ██║██████╔╝",
    "  ██╔══██║██║╚██╗██║██║   ██║██║╚██╗██║██║╚██╔╝██║██║   ██║██║╚██╗██║██║   ██║   ██║   ██║██╔══██╗",
    "  ██║  ██║██║ ╚████║╚██████╔╝██║ ╚████║██║ ╚═╝ ██║╚██████╔╝██║ ╚████║██║   ██║   ╚██████╔╝██║  ██║",
    "  ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝",
]

GLITCH_CHARS = "!@#$%^&*<>?/\\|~0123456789ァアィイゥウェエォオカキクケコ"

def glitch(text, intensity=0.06):
    out = ""
    for ch in text:
        if ch not in (" ", "╗", "╔", "║", "╝", "╚", "═") and random.random() < intensity:
            out += f"{RED}{random.choice(GLITCH_CHARS)}{GREEN}"
        else:
            out += ch
    return out

def ok(label, val=""):
    return f"  {GREEN}●{R} {WHITE}{label:<28}{R} {DIM}{val}{R}"

def warn(label, val=""):
    return f"  {YELLOW}●{R} {YELLOW}{label:<28}{R} {DIM}{val}{R}"

def fail(label, val=""):
    return f"  {RED}●{R} {RED}{label:<28}{R} {val}"

def div(w):
    return f"  {DIM}{'─' * (w - 4)}{R}"

def check_tor():
    try:
        r = subprocess.run(["service", "tor", "status"], capture_output=True, text=True)
        return "active (running)" in r.stdout or "running" in r.stdout.lower()
    except:
        return False

def check_protonvpn():
    try:
        r = subprocess.run(["protonvpn", "info"], capture_output=True, text=True, timeout=8)
        out = r.stdout
        connected = "connected" in out.lower()
        server = country = ""
        for line in out.splitlines():
            l = line.lower()
            if "server" in l:
                server = line.split(":")[-1].strip()
            if "country" in l:
                country = line.split(":")[-1].strip()
        return connected, server, country
    except:
        return False, "", ""

def check_proxychains():
    conf = "/etc/proxychains4.conf"
    if not os.path.exists(conf):
        return False, False, False
    with open(conf) as f:
        lines = f.readlines()
    active  = [l.strip() for l in lines if not l.strip().startswith("#")]
    content = "\n".join(active)
    dynamic   = "dynamic_chain" in content
    proxy_dns = "proxy_dns" in content
    socks5    = "socks5  127.0.0.1" in content or "socks5 127.0.0.1" in content
    return dynamic, proxy_dns, socks5

def get_real_ip():
    try:
        r = requests.get("https://ifconfig.me", timeout=5)
        return r.text.strip()
    except:
        return None

def get_masked_ip():
    try:
        r = subprocess.run(
            ["proxychains", "-q", "curl", "-s", "--max-time", "10", "https://ifconfig.me"],
            capture_output=True, text=True, timeout=20
        )
        out = r.stdout.strip().split("\n")[-1].strip()
        if out and len(out) < 40:
            return out
    except:
        pass
    return None

def check_dns_leak(real_ip):
    try:
        r = requests.get("https://dns.google/resolve?name=whoami.akamai.net&type=A", timeout=6)
        dns_ip = r.json().get("Answer", [{}])[0].get("data", "")
        if real_ip and real_ip in dns_ip:
            return False, dns_ip
        return True, dns_ip
    except:
        return None, "unavailable"

def score_bar(score, total, width=20):
    filled = int((score / total) * width)
    col = GREEN if score == total else YELLOW if score >= total * 0.6 else RED
    bar = f"{col}{'█' * filled}{DIM}{'░' * (width - filled)}{R}"
    return bar, f"{col}{BOLD}{score}/{total}{R}"

def render(real_ip, masked_ip, vpn, vpn_server, vpn_country,
           tor, dynamic, proxy_dns, socks5, dns_ok, dns_ip,
           last_checked, tick):

    w    = min(shutil.get_terminal_size().columns, 66)
    spin = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"][tick % 10]
    do_glitch = (tick % 50) < 3

    lines = [CLEAR]

    for line in LOGO:
        gl = glitch(line) if do_glitch else line
        lines.append(f"{GREEN}{gl}{R}")

    lines.append(f"\n  {DIM}live anonymity dashboard  //  kali linux{R}  {CYAN}{spin}{R}")
    lines.append(div(w))
    lines.append("")

    lines.append(f"  {DIM}IP {'─'*(w-7)}{R}")
    lines.append(ok("real IP",   real_ip or "unavailable"))
    if masked_ip and masked_ip != real_ip:
        lines.append(ok("masked IP", masked_ip))
        lines.append(ok("IPs differ", "you are hidden"))
    elif masked_ip == real_ip:
        lines.append(fail("masked IP", f"{RED}{masked_ip}  ← SAME AS REAL!{R}"))
    else:
        lines.append(warn("masked IP", "checking..."))
    lines.append("")

    lines.append(f"  {DIM}VPN {'─'*(w-8)}{R}")
    if vpn:
        lines.append(ok("ProtonVPN",  "connected"))
        if vpn_server:  lines.append(ok("server",  vpn_server))
        if vpn_country: lines.append(ok("country", vpn_country))
    else:
        lines.append(fail("ProtonVPN", f"{RED}disconnected  ← WARNING{R}"))
    lines.append("")

    lines.append(f"  {DIM}Tor {'─'*(w-8)}{R}")
    lines.append(ok("Tor service", "running") if tor else
                 fail("Tor service", f"{RED}not running  →  sudo service tor start{R}"))
    lines.append("")

    lines.append(f"  {DIM}Proxychains {'─'*(w-16)}{R}")
    lines.append(ok("dynamic_chain",  "on")         if dynamic   else fail("dynamic_chain",  f"{RED}off{R}"))
    lines.append(ok("proxy_dns",      "on")         if proxy_dns else warn("proxy_dns",      "off  ← DNS leak risk"))
    lines.append(ok("socks5 :9050",   "configured") if socks5    else fail("socks5 :9050",   f"{RED}missing{R}"))
    lines.append("")

    lines.append(f"  {DIM}DNS {'─'*(w-8)}{R}")
    if dns_ok is True:
        lines.append(ok("DNS leak", f"none  ({dns_ip})"))
    elif dns_ok is False:
        lines.append(fail("DNS leak", f"{RED}LEAK DETECTED  {dns_ip}{R}"))
    else:
        lines.append(warn("DNS leak", "check unavailable"))
    lines.append("")

    score = sum([bool(vpn), bool(tor), bool(dynamic), bool(proxy_dns),
                 bool(socks5), (dns_ok is True),
                 bool(masked_ip and masked_ip != real_ip)])
    bar, score_str = score_bar(score, 7)

    lines.append(div(w))
    lines.append(f"  {BOLD}protection score{R}  {bar}  {score_str}")
    lines.append(div(w))
    lines.append(f"  {DIM}last checked: {last_checked}   refresh: {REFRESH}s   ctrl+c to exit{R}")
    lines.append(f"  {DIM}created by {R}{GREEN}{BOLD}LuffyHacks{R}{DIM}  //  anonmonitor v1.0{R}")
    lines.append("")

    return "\n".join(lines)

def main():
    real_ip = masked_ip = vpn_server = vpn_country = dns_ip = None
    vpn = tor = dynamic = proxy_dns = socks5 = False
    dns_ok = None
    last_checked = "—"
    tick = 0
    last_full_check = 0

    try:
        while True:
            now = time.time()
            if now - last_full_check >= REFRESH:
                real_ip                      = get_real_ip()
                masked_ip                    = get_masked_ip()
                vpn, vpn_server, vpn_country = check_protonvpn()
                tor                          = check_tor()
                dynamic, proxy_dns, socks5   = check_proxychains()
                dns_ok, dns_ip               = check_dns_leak(real_ip)
                last_checked                 = time.strftime("%H:%M:%S")
                last_full_check              = now

            out = render(real_ip, masked_ip, vpn, vpn_server, vpn_country,
                         tor, dynamic, proxy_dns, socks5, dns_ok, dns_ip,
                         last_checked, tick)
            print(out, end="", flush=True)
            tick += 1
            time.sleep(1)

    except KeyboardInterrupt:
        print(f"\n\n  {DIM}anonmonitor stopped.  //  LuffyHacks{R}\n")

if __name__ == "__main__":
    main()
