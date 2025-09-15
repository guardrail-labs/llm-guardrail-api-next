from pathlib import Path


def test_no_duplicate_demo_traffic_module():
    assert Path("scripts/demo_traffic.py").exists()
    assert not Path("docker/tools/demo_traffic.py").exists()
    assert Path("docker/tools/traffic_seed.py").exists()
