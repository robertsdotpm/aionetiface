"""Test configuration for aionetiface test suite."""
import os
import sys
import unittest

import pytest

from aionetiface import aionetiface_setup_event_loop
from aionetiface.testing import AsyncTestCase, allow_windows_firewall, remove_windows_firewall


aionetiface_setup_event_loop()

if not hasattr(unittest, "IsolatedAsyncioTestCase"):
    unittest.IsolatedAsyncioTestCase = AsyncTestCase

# See p2pd/tests/conftest.py for explanation.
if sys.version_info >= (3, 12):
    import linecache
    linecache.checkcache = lambda filename=None: None


def xdist_port_base(base, stride=200):
    """Return base offset for test ports, unique per xdist worker."""
    w = os.environ.get("PYTEST_XDIST_WORKER", "")
    try:
        n = int(w.replace("gw", "")) if w else 0
    except ValueError:
        n = 0
    return base + n * stride


@pytest.fixture(scope="session", autouse=True)
def windows_firewall_rule():
    allow_windows_firewall("python-test-suite")
    yield
    remove_windows_firewall("python-test-suite")
