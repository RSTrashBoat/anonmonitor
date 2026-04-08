#!/usr/bin/env python3
import subprocess
import sys
import os
import time
import shutil
import random
import threading
import socket
import struct
import re
from collections import deque, defaultdict
from datetime import datetime

# ── auto-install deps ────────────────────────────────────────────────────────
for pkg in ["requests", "psutil", "scapy"]:
    try:
        __import__(pkg)
    except ImportError:
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", pkg,
             "--break-system-packages", "-q"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )

import requests
import psutil

# ── colors ───────────────────────────────────────────────────────────────────
R      = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
MAGENTA= "\033[95m"
WHITE  = "\033[97m"
BLINK  = "\033[5m"
CLEAR  = "\033[2J\033[H"

REFRESH        = 10     # seconds between full checks
TRAFFIC_HIST   = 30     # seconds of bandwidth history
ALERT_TTL      = 60     # seconds an alert stays visible
PROBE_THRESH   = 5      # distinct ports hit in window = trace suspect
PROBE_WINDOW   = 20     # seconds

# ── logo ─────────────────────────────────────────────────────────────────────
LOGO = [
    "   █████╗ ███╗   ██╗ ██████╗ ███╗   ██╗███╗   ███╗ ██████╗ ███╗   ██╗██╗████████╗ ██████╗ ██████╗ ",
    "  ██╔══██╗████╗  ██║██╔═══██╗████╗  ██║████╗ ████║██╔═══██╗████╗  ██║██║╚══██╔══╝██╔═══██╗██╔══██╗",
    "  ███████║██╔██╗ ██║██║   ██║██╔██╗ ██║██╔████╔██║██║   ██║██╔██╗ ██║██║   ██║   ██║   ██║██████╔╝",
    "  ██╔══██║██║╚██╗██║██║   ██║██║╚██╗██║██║╚██╔╝██║██║   ██║██║╚██╗██║██║   ██║   ██║   ██║██╔══██╗",
    "  ██║  ██║██║ ╚████║╚██████╔╝██║ ╚████║██║ ╚═╝ ██║╚██████╔╝██║ ╚████║██║   ██║   ╚██████╔╝██║  ██║",
    "  ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝",
]

GLITCH_CHARS = "!@#$%^&*<>?/\\|~0123456789ァアィイゥウェエォオカキクケコ"

# ── shared state ─────────────────────────────────────────────────────────────
class State:
    lock          = threading.Lock()
    real_ip       = None
    masked_ip     = None
    vpn           = False
    vpn_server    = ""
    vpn_country   = ""
    tor           = False
    dynamic       = False
    proxy_dns     = False
    socks5        = False
    dns_ok        = None
    dns_ip        = ""
    dns_servers   = []          # NEW: resolved DNS servers
    last_checked  = "—"
    # traffic
    bw_sent_hist  = deque(maxlen=TRAFFIC_HIST)
    bw_recv_hist  = deque(maxlen=TRAFFIC_HIST)
    bw_sent_rate  = 0           # bytes/s
    bw_recv_rate  = 0           # bytes/s
    top_conns     = []          # list of (raddr, status, pid_name)
    # alerts
    alerts        = deque(maxlen=20)
    # trace detection
    inbound_probes = defaultdict(list)   # src_ip -> [timestamps]
    traced_ips    = {}                    # src_ip -> last_seen timestamp
    suspected_trace = False

state = State()

# ── helpers ──────────────────────────────────────────────────────────────────
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

def alert_line(msg, level="warn"):
    col = RED if level == "critical" else YELLOW
    ts  = datetime.now().strftime("%H:%M:%S")
    return f"  {col}{BOLD}[!]{R} {col}{msg}{R}  {DIM}{ts}{R}"

def div(w):
    return f"  {DIM}{'─' * (w - 4)}{R}"

def bytes_human(b):
    for unit in ["B","KB","MB","GB"]:
        if b < 1024:
            return f"{b:.1f} {unit}/s"
        b /= 1024
    return f"{b:.1f} TB/s"

def mini_sparkline(vals, width=20, col=GREEN):
    if not vals:
        return f"{DIM}{'▁'*width}{R}"
    m = max(vals) or 1
    bars = "▁▂▃▄▅▆▇█"
    out  = ""
    for v in list(vals)[-width:]:
        idx = min(int((v / m) * (len(bars)-1)), len(bars)-1)
        out += bars[idx]
    # pad left
    out = out.rjust(width, "▁")
    return f"{col}{out}{R}"

def score_bar(score, total, width=20):
    filled = int((score / total) * width)
    col = GREEN if score == total else YELLOW if score >= total * 0.6 else RED
    bar = f"{col}{'█' * filled}{DIM}{'░' * (width - filled)}{R}"
    return bar, f"{col}{BOLD}{score}/{total}{R}"

# ── push alert ────────────────────────────────────────────────────────────────
def push_alert(msg, level="warn"):
    with state.lock:
        state.alerts.appendleft((time.time(), level, msg))

# ── check functions ───────────────────────────────────────────────────────────
def check_tor():
    try:
        r = subprocess.run(["service", "tor", "status"],
                           capture_output=True, text=True)
        return "active (running)" in r.stdout or "running" in r.stdout.lower()
    except:
        return False

def check_protonvpn():
    try:
        r = subprocess.run(["protonvpn", "info"],
                           capture_output=True, text=True, timeout=8)
        out = r.stdout
        connected  = "connected" in out.lower()
        server = country = ""
        for line in out.splitlines():
            l = line.lower()
            if "server"  in l: server  = line.split(":")[-1].strip()
            if "country" in l: country = line.split(":")[-1].strip()
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
    proxy_dns = "proxy_dns"     in content
    socks5    = ("socks5  127.0.0.1" in content or
                 "socks5 127.0.0.1"  in content)
    return dynamic, proxy_dns, socks5

def get_real_ip():
    for url in ["https://ifconfig.me", "https://api.ipify.org",
                "https://icanhazip.com"]:
        try:
            r = requests.get(url, timeout=5)
            ip = r.text.strip()
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
                return ip
        except:
            pass
    return None

def get_masked_ip():
    try:
        r = subprocess.run(
            ["proxychains", "-q", "curl", "-s", "--max-time", "10",
             "https://ifconfig.me"],
            capture_output=True, text=True, timeout=20
        )
        out = r.stdout.strip().split("\n")[-1].strip()
        if out and len(out) < 40 and re.match(r"^\d{1,3}(\.\d{1,3}){3}$", out):
            return out
    except:
        pass
    return None

def check_dns_leak_enhanced(real_ip):
    """
    Multi-server DNS leak check.
    Returns (ok_bool, detected_dns_ip_str, [all_dns_servers])
    """
    servers_seen = []
    leak_detected = False

    # Method 1: Google DoH whoami
    try:
        r = requests.get(
            "https://dns.google/resolve?name=whoami.akamai.net&type=A",
            timeout=6
        )
        dns_ip = r.json().get("Answer", [{}])[0].get("data", "")
        if dns_ip:
            servers_seen.append(dns_ip)
            if real_ip and real_ip in dns_ip:
                leak_detected = True
    except:
        pass

    # Method 2: bash dig to detect local resolver
    try:
        r = subprocess.run(
            ["dig", "+short", "whoami.ds.akahelp.net"],
            capture_output=True, text=True, timeout=5
        )
        for line in r.stdout.strip().splitlines():
            ip = line.strip()
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
                if ip not in servers_seen:
                    servers_seen.append(ip)
                if real_ip and real_ip == ip:
                    leak_detected = True
    except:
        pass

    # Method 3: check /etc/resolv.conf for local DNS
    try:
        with open("/etc/resolv.conf") as f:
            for line in f:
                if line.startswith("nameserver"):
                    ns = line.split()[-1].strip()
                    # flag private-range resolvers as potential leak
                    if not (ns.startswith("127.") or ns.startswith("10.")
                            or ns.startswith("192.168.")):
                        if ns not in servers_seen:
                            servers_seen.append(ns + "⚠")
    except:
        pass

    if not servers_seen:
        return None, "unavailable", []

    primary = servers_seen[0].replace("⚠", "")
    return (not leak_detected), primary, servers_seen

# ── traffic monitoring (background) ──────────────────────────────────────────
_prev_net = None

def traffic_loop():
    global _prev_net
    _prev_net = psutil.net_io_counters()
    while True:
        time.sleep(1)
        cur = psutil.net_io_counters()
        sent_rate = cur.bytes_sent - _prev_net.bytes_sent
        recv_rate = cur.bytes_recv - _prev_net.bytes_recv
        _prev_net = cur

        with state.lock:
            state.bw_sent_rate = max(sent_rate, 0)
            state.bw_recv_rate = max(recv_rate, 0)
            state.bw_sent_hist.append(state.bw_sent_rate)
            state.bw_recv_hist.append(state.bw_recv_rate)

        # top connections
        try:
            conns = psutil.net_connections(kind="inet")
            active = []
            proc_map = {}
            for p in psutil.process_iter(["pid","name"]):
                try: proc_map[p.pid] = p.info["name"]
                except: pass
            for c in conns:
                if c.status == "ESTABLISHED" and c.raddr:
                    rip   = c.raddr.ip
                    rport = c.raddr.port
                    pname = proc_map.get(c.pid, "?")
                    active.append((f"{rip}:{rport}", c.status, pname))
            with state.lock:
                state.top_conns = active[:8]
        except:
            pass

# ── trace / probe detection (background) ─────────────────────────────────────
def probe_detection_loop():
    """
    Watches for rapid inbound connections from a single external IP
    to multiple local ports — classic port-scan / trace signature.
    """
    while True:
        time.sleep(2)
        now = time.time()
        try:
            conns = psutil.net_connections(kind="inet")
            for c in conns:
                # look at SYN_RECV or short-lived connections from external IPs
                if c.status in ("SYN_RECV", "CLOSE_WAIT", "TIME_WAIT", "LISTEN"):
                    continue
                if not c.raddr:
                    continue
                rip   = c.raddr.ip
                rport = c.laddr.port if c.laddr else 0
                # ignore loopback and private-only
                if rip.startswith("127.") or rip.startswith("::"):
                    continue

                with state.lock:
                    state.inbound_probes[rip].append((now, rport))
                    # prune old entries
                    state.inbound_probes[rip] = [
                        (t, p) for (t, p) in state.inbound_probes[rip]
                        if now - t < PROBE_WINDOW
                    ]
                    distinct_ports = len(set(
                        p for (_, p) in state.inbound_probes[rip]
                    ))
                    if distinct_ports >= PROBE_THRESH:
                        if rip not in state.traced_ips:
                            state.suspected_trace = True
                            state.traced_ips[rip] = now
                            push_alert(
                                f"POSSIBLE TRACE DETECTED from {rip} "
                                f"({distinct_ports} ports in {PROBE_WINDOW}s)",
                                level="critical"
                            )

            # expire old traced IPs
            with state.lock:
                state.traced_ips = {
                    ip: t for ip, t in state.traced_ips.items()
                    if now - t < 120
                }
                if not state.traced_ips:
                    state.suspected_trace = False
        except:
            pass

# ── IP exposure alert checker ─────────────────────────────────────────────────
def ip_exposure_loop():
    while True:
        time.sleep(REFRESH)
        with state.lock:
            real   = state.real_ip
            masked = state.masked_ip
        if real and masked:
            if real == masked:
                push_alert(
                    "IP EXPOSED — masked IP matches real IP! "
                    "Anonymity is BROKEN.",
                    level="critical"
                )
        # also alert if VPN down but tor also down
        with state.lock:
            vpn = state.vpn
            tor = state.tor
        if not vpn and not tor:
            push_alert(
                "No VPN and no Tor running — traffic is fully exposed!",
                level="critical"
            )

# ── full-check loop ───────────────────────────────────────────────────────────
def check_loop():
    while True:
        real_ip   = get_real_ip()
        masked_ip = get_masked_ip()
        vpn, vpn_server, vpn_country = check_protonvpn()
        tor       = check_tor()
        dynamic, proxy_dns, socks5 = check_proxychains()
        dns_ok, dns_ip, dns_servers = check_dns_leak_enhanced(real_ip)

        with state.lock:
            state.real_ip     = real_ip
            state.masked_ip   = masked_ip
            state.vpn         = vpn
            state.vpn_server  = vpn_server
            state.vpn_country = vpn_country
            state.tor         = tor
            state.dynamic     = dynamic
            state.proxy_dns   = proxy_dns
            state.socks5      = socks5
            state.dns_ok      = dns_ok
            state.dns_ip      = dns_ip
            state.dns_servers = dns_servers
            state.last_checked = time.strftime("%H:%M:%S")

        if dns_ok is False:
            push_alert(f"DNS LEAK detected — server: {dns_ip}", level="critical")

        time.sleep(REFRESH)

# ── render ────────────────────────────────────────────────────────────────────
def render(tick):
    with state.lock:
        real_ip     = state.real_ip
        masked_ip   = state.masked_ip
        vpn         = state.vpn
        vpn_server  = state.vpn_server
        vpn_country = state.vpn_country
        tor         = state.tor
        dynamic     = state.dynamic
        proxy_dns   = state.proxy_dns
        socks5      = state.socks5
        dns_ok      = state.dns_ok
        dns_ip      = state.dns_ip
        dns_servers = list(state.dns_servers)
        last_checked= state.last_checked
        bw_sent     = state.bw_sent_rate
        bw_recv     = state.bw_recv_rate
        sent_hist   = list(state.bw_sent_hist)
        recv_hist   = list(state.bw_recv_hist)
        top_conns   = list(state.top_conns)
        alerts      = list(state.alerts)
        traced_ips  = dict(state.traced_ips)
        suspected   = state.suspected_trace

    now = time.time()
    w   = min(shutil.get_terminal_size().columns, 100)
    spin = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"][tick % 10]
    do_glitch = (tick % 50) < 3

    lines = [CLEAR]

    for line in LOGO:
        gl = glitch(line) if do_glitch else line
        lines.append(f"{GREEN}{gl}{R}")

    lines.append(
        f"\n  {DIM}live anonymity dashboard v2.0  //  kali linux{R}  {CYAN}{spin}{R}"
    )
    lines.append(div(w))

    # ── ACTIVE ALERTS ────────────────────────────────────────────────────────
    active_alerts = [(t, lvl, msg) for (t, lvl, msg) in alerts
                     if now - t < ALERT_TTL]
    if active_alerts:
        lines.append(f"\n  {RED}{BOLD}{'━'*6} ACTIVE ALERTS {'━'*6}{R}")
        for (_, lvl, msg) in active_alerts[:5]:
            lines.append(alert_line(msg, lvl))
        lines.append("")

    # ── IP SECTION ───────────────────────────────────────────────────────────
    lines.append(f"  {DIM}IP {'─'*(w-7)}{R}")
    lines.append(ok("real IP",   real_ip   or "checking..."))

    if masked_ip and masked_ip != real_ip:
        lines.append(ok("masked IP", masked_ip))
        lines.append(ok("exposure", f"{GREEN}hidden ✓{R}"))
    elif masked_ip == real_ip:
        lines.append(fail("masked IP",
            f"{RED}{BLINK}⚠ EXPOSED — same as real IP!{R}"))
    else:
        lines.append(warn("masked IP", "checking..."))
    lines.append("")

    # ── VPN ──────────────────────────────────────────────────────────────────
    lines.append(f"  {DIM}VPN {'─'*(w-8)}{R}")
    if vpn:
        lines.append(ok("ProtonVPN",  "connected ✓"))
        if vpn_server:  lines.append(ok("server",  vpn_server))
        if vpn_country: lines.append(ok("country", vpn_country))
    else:
        lines.append(fail("ProtonVPN",
            f"{RED}disconnected  ← WARNING{R}"))
    lines.append("")

    # ── TOR ──────────────────────────────────────────────────────────────────
    lines.append(f"  {DIM}Tor {'─'*(w-8)}{R}")
    lines.append(
        ok("Tor service", "running ✓") if tor else
        fail("Tor service", f"{RED}not running  →  sudo service tor start{R}")
    )
    lines.append("")

    # ── PROXYCHAINS ──────────────────────────────────────────────────────────
    lines.append(f"  {DIM}Proxychains {'─'*(w-16)}{R}")
    lines.append(ok("dynamic_chain",  "on")         if dynamic   else
                 fail("dynamic_chain",  f"{RED}off{R}"))
    lines.append(ok("proxy_dns",      "on")         if proxy_dns else
                 warn("proxy_dns",      "off  ← DNS leak risk"))
    lines.append(ok("socks5 :9050",   "configured") if socks5    else
                 fail("socks5 :9050",   f"{RED}missing{R}"))
    lines.append("")

    # ── DNS LEAK (enhanced) ──────────────────────────────────────────────────
    lines.append(f"  {DIM}DNS {'─'*(w-8)}{R}")
    if dns_ok is True:
        lines.append(ok("DNS leak",      f"none detected ✓"))
        lines.append(ok("resolver",      dns_ip))
    elif dns_ok is False:
        lines.append(fail("DNS leak",    f"{RED}{BLINK}LEAK DETECTED ⚠{R}"))
        lines.append(fail("resolver",    f"{RED}{dns_ip}{R}"))
    else:
        lines.append(warn("DNS status",  "check unavailable"))
    if dns_servers:
        servers_str = "  ".join(dns_servers[:4])
        lines.append(warn("DNS servers seen", servers_str[:60]))
    lines.append("")

    # ── LIVE TRAFFIC DASHBOARD ───────────────────────────────────────────────
    lines.append(f"  {DIM}Live Traffic {'─'*(w-17)}{R}")
    spark_send = mini_sparkline(sent_hist, width=24, col=CYAN)
    spark_recv = mini_sparkline(recv_hist, width=24, col=GREEN)
    lines.append(
        f"  {CYAN}↑{R} {bytes_human(bw_sent):<14} {spark_send}"
    )
    lines.append(
        f"  {GREEN}↓{R} {bytes_human(bw_recv):<14} {spark_recv}"
    )
    lines.append("")

    if top_conns:
        lines.append(f"  {DIM}Active Connections{R}")
        for (raddr, status, pname) in top_conns[:6]:
            col = YELLOW if status == "ESTABLISHED" else DIM
            lines.append(
                f"  {DIM}│{R} {col}{raddr:<38}{R} {DIM}{pname[:16]}{R}"
            )
        lines.append("")

    # ── TRACE / PROBE ALERT ──────────────────────────────────────────────────
    lines.append(f"  {DIM}Trace Detection {'─'*(w-20)}{R}")
    if suspected and traced_ips:
        lines.append(fail("status",
            f"{RED}{BLINK}⚠ POSSIBLE TRACE IN PROGRESS!{R}"))
        for ip in list(traced_ips.keys())[:3]:
            lines.append(fail("suspect IP", f"{RED}{ip}{R}"))
    else:
        lines.append(ok("status", "no suspicious probes detected"))
    lines.append("")

    # ── PROTECTION SCORE ─────────────────────────────────────────────────────
    score = sum([
        bool(vpn),
        bool(tor),
        bool(dynamic),
        bool(proxy_dns),
        bool(socks5),
        (dns_ok is True),
        bool(masked_ip and masked_ip != real_ip),
        not suspected,
    ])
    bar, score_str = score_bar(score, 8)

    lines.append(div(w))
    lines.append(f"  {BOLD}protection score{R}  {bar}  {score_str}")
    lines.append(div(w))
    lines.append(
        f"  {DIM}last checked: {last_checked}   "
        f"refresh: {REFRESH}s   ctrl+c to exit{R}"
    )
    lines.append(
        f"  {DIM}created by {R}{GREEN}{BOLD}LuffyHacks{R}"
        f"{DIM}  //  anonmonitor v2.0{R}"
    )
    lines.append("")

    return "\n".join(lines)

# ── main ──────────────────────────────────────────────────────────────────────
def main():
    if os.geteuid() != 0:
        print(f"{YELLOW}[!] Some features (trace detection) work best as root.{R}")
        time.sleep(1)

    # start background threads
    for fn in [check_loop, traffic_loop, probe_detection_loop, ip_exposure_loop]:
        t = threading.Thread(target=fn, daemon=True)
        t.start()

    tick = 0
    try:
        while True:
            out = render(tick)
            print(out, end="", flush=True)
            tick += 1
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n\n  {DIM}anonmonitor stopped.  //  LuffyHacks{R}\n")

if __name__ == "__main__":
    main()
