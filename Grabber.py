import getpass
import json
import socket
import subprocess
import uuid

import requests
from tkinter import TclError, Tk
from PIL import ImageGrab


def fetch_wifi_profiles() -> str:
    """Retrieve a list of WiFi profile SSIDs using Windows netsh."""
    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "profiles", "key=clear"],
            check=True,
            capture_output=True,
            text=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        return "Unavailable"

    ssids = []
    for line in result.stdout.splitlines():
        if "All User Profile" in line:
            parts = line.split(":", 1)
            if len(parts) == 2:
                ssid = parts[1].strip()
                if ssid:
                    ssids.append(ssid)

    return ", ".join(ssids) if ssids else "None Found"

def fetch_public_ip() -> str:
    """Fetch the current public IP address using ipify."""
    response = requests.get("https://api.ipify.org", timeout=5)
    response.raise_for_status()
    return response.text.strip()


def fetch_private_ip() -> str:
    """Determine the current machine's primary private IP address."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]


def fetch_mac_address() -> str:
    """Retrieve the MAC address for the primary network interface."""
    mac = uuid.getnode()
    mac_hex = f"{mac:012x}"
    return ":".join(mac_hex[i : i + 2] for i in range(0, 12, 2))


def fetch_clipboard_content() -> str:
    """Return current clipboard contents if available."""
    try:
        root = Tk()
        root.withdraw()
        content = root.clipboard_get()
        root.destroy()
        return content
    except TclError:
        return "Unavailable"


def capture_screenshot(path: str = "screenshot.png") -> str:
    """Capture a screenshot of the current screen and save it to the provided path."""
    try:
        screenshot = ImageGrab.grab()
        screenshot.save(path)
        return f"Saved to {path}"
    except OSError:
        return "Unavailable"


def main() -> None:
    public_ip = fetch_public_ip()
    private_ip = fetch_private_ip()
    mac_address = fetch_mac_address()
    clipboard_content = fetch_clipboard_content()
    wifi_profiles = fetch_wifi_profiles()
    screenshot_status = capture_screenshot()
    username = getpass.getuser()
    hostname = socket.gethostname()

    data = {
        "username": username,
        "computer_name": hostname,
        "mac_address": mac_address,
        "private_ip": private_ip,
        "public_ip": public_ip,
        "clipboard": clipboard_content,
        "wifi_profiles": wifi_profiles,
        "screenshot": screenshot_status,
    }

    print(json.dumps(data, indent=2))


if __name__ == "__main__":
    main()
