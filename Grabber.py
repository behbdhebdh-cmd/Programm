import getpass
import socket

import requests

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


def main() -> None:
    public_ip = fetch_public_ip()
    private_ip = fetch_private_ip()
    username = getpass.getuser()
    hostname = socket.gethostname()

    print(f"Username: {username}")
    print(f"Computer Name: {hostname}")
    print(f"Private IP: {private_ip}")
    print(f"Public IP: {public_ip}")


if __name__ == "__main__":
    main()
