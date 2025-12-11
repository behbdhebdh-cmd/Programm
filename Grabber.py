import requests

def fetch_public_ip() -> str:
    """Fetch the current public IP address using ipify."""
    response = requests.get("https://api.ipify.org", timeout=5)
    response.raise_for_status()
    return response.text.strip()


def main() -> None:
    ip_address = fetch_public_ip()
    print(ip_address)


if __name__ == "__main__":
    main()
