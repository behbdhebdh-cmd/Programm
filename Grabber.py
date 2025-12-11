import getpass
import socket
import uuid

import requests
from tkinter import TclError, Tk

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


def main() -> None:
    public_ip = fetch_public_ip()
    private_ip = fetch_private_ip()
    mac_address = fetch_mac_address()
    clipboard_content = fetch_clipboard_content()
    username = getpass.getuser()
    hostname = socket.gethostname()

    print(f"Username: {username}")
    print(f"Computer Name: {hostname}")
    print(f"MAC Address: {mac_address}")
    print(f"Private IP: {private_ip}")
    print(f"Public IP: {public_ip}")
    print(f"Clipboard: {clipboard_content}")


if __name__ == "__main__":
    main()
