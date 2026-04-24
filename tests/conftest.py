"""Test configuration for aionetiface test suite."""
import sys
import unittest

import pytest

from aionetiface import aionetiface_setup_event_loop
from aionetiface.testing import AsyncTestCase, allow_windows_firewall, remove_windows_firewall
from port_helpers import xdist_port_base  # noqa: F401 — re-exported for conftest consumers


aionetiface_setup_event_loop()

if not hasattr(unittest, "IsolatedAsyncioTestCase"):
    unittest.IsolatedAsyncioTestCase = AsyncTestCase

# See p2pd/tests/conftest.py for explanation.
if sys.version_info >= (3, 12):
    import linecache
    linecache.checkcache = lambda filename=None: None


@pytest.fixture(scope="session", autouse=True)
def windows_firewall_rule():
    allow_windows_firewall("python-test-suite")
    yield
    remove_windows_firewall("python-test-suite")
