from __future__ import annotations

import os
from urllib.request import urlopen


def main() -> None:
    port = os.getenv("PORT", "8000")
    url = f"http://127.0.0.1:{port}/healthz"
    with urlopen(url, timeout=2):
        pass


if __name__ == "__main__":
    main()
