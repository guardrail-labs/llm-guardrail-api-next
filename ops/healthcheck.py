"""Container runtime health check."""
import os
from urllib.request import urlopen


def main() -> None:
    port = os.getenv("PORT", "8000")
    url = f"http://127.0.0.1:{port}/healthz"
    urlopen(url, timeout=2)


if __name__ == "__main__":
    main()
