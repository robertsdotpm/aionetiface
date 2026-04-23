"""Test configuration for aionetiface test suite."""
import unittest

from aionetiface import aionetiface_setup_event_loop
from aionetiface.testing import AsyncTestCase


aionetiface_setup_event_loop()

if not hasattr(unittest, "IsolatedAsyncioTestCase"):
    unittest.IsolatedAsyncioTestCase = AsyncTestCase
