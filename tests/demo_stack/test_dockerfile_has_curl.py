import re
from pathlib import Path


def test_dockerfile_installs_curl():
    p = Path("docker/Dockerfile")
    s = p.read_text(encoding="utf-8")
    assert re.search(r"apt-get.*install.*curl", s), (
        "Dockerfile should install curl for healthcheck"
    )
