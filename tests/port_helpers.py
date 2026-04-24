"""Port allocation helpers for pytest-xdist parallel test runs."""
import os


def xdist_port_base(base, stride=200):
    """Return base offset for test ports, unique per xdist worker."""
    w = os.environ.get("PYTEST_XDIST_WORKER", "")
    try:
        n = int(w.replace("gw", "")) if w else 0
    except ValueError:
        n = 0
    return base + n * stride
