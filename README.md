# AnonMonitor 🛡️

> Real-time anonymity monitoring dashboard for Kali Linux — built for the terminal.

![Python](https://img.shields.io/badge/Python-3.x-green?style=flat-square&logo=python)
![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-blue?style=flat-square&logo=linux)
![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)
![Version](https://img.shields.io/badge/Version-2.0-red?style=flat-square)

---

## Features

- 🔍 **Live traffic dashboard** — real-time bandwidth with sparkline graphs
- 🌐 **VPN monitor** — ProtonVPN status, server & country
- 🧅 **Tor monitor** — checks if Tor service is running
- ⛓️ **Proxychains validator** — checks dynamic chain, proxy_dns, socks5
- 🔓 **DNS leak detection** — 3-method check (DoH, dig, resolv.conf)
- ⚠️ **IP exposure alerts** — fires instantly if your real IP is exposed
- 🎯 **Trace detection** — detects port scan / probe patterns from external IPs
- 📊 **Protection score** — live score out of 8

---

## Preview
██████╗ ...ANONMONITOR...
live anonymity dashboard v2.0  //  kali linux  ⠋
── IP ──────────────────────────────────
● real IP         103.45.67.89
● masked IP       185.220.101.45
● exposure        hidden ✓
── protection score ────────────────────
████████████████░░░░  7/8

---

## Requirements

- Kali Linux
- Python 3.x
- `tor` — `sudo apt install tor`
- `proxychains4` — `sudo apt install proxychains4`
- ProtonVPN CLI (optional)

---

## Installation

```bash
git clone https://github.com/RSTrashBoat/anonmonitor.git
cd anonmonitor
pip install -r requirements.txt --break-system-packages
```

---

## Usage

```bash
sudo python3 anonmonitor.py
```

> Root is recommended for full trace detection capability.

---

## Created by

**LuffyHacks** — anonmonitor v2.0
