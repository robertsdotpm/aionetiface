"""Test configuration: install the aionetiface event-loop policy for all tests.

Previously the library applied its custom event-loop policy, multiprocessing
start method, and selector transport patch implicitly at import time. That
behaviour is now opt-in via ``aionetiface_setup_event_loop()``; the test suite
invokes it here so every test sees the same runtime environment the library
expects in production code.
"""
import asyncio
import sys
import unittest

from aionetiface import aionetiface_setup_event_loop


aionetiface_setup_event_loop()


def _get_pending_tasks(loop):
    """Return pending tasks for loop, compatible with Python 3.5+."""
    if sys.version_info >= (3, 7):
        return asyncio.all_tasks(loop)
    return asyncio.Task.all_tasks(loop)


if not hasattr(unittest, "IsolatedAsyncioTestCase"):
    class _IsolatedAsyncioTestCase(unittest.TestCase):
        """Minimal backport of IsolatedAsyncioTestCase for Python < 3.8."""

        def _callAsync(self, coro):
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                return loop.run_until_complete(coro)
            finally:
                try:
                    pending = _get_pending_tasks(loop)
                    for t in pending:
                        t.cancel()
                    if pending:
                        loop.run_until_complete(
                            asyncio.gather(*pending, return_exceptions=True)
                        )
                finally:
                    loop.close()
                    asyncio.set_event_loop(None)

        def setUp(self):
            if hasattr(self, "asyncSetUp"):
                self._callAsync(self.asyncSetUp())

        def tearDown(self):
            if hasattr(self, "asyncTearDown"):
                self._callAsync(self.asyncTearDown())

        def run(self, result=None):
            method = getattr(self, self._testMethodName)
            if asyncio.iscoroutinefunction(method):
                original = method
                def sync_wrap():
                    return self._callAsync(original())
                setattr(self, self._testMethodName, sync_wrap)
            return super(_IsolatedAsyncioTestCase, self).run(result)

    unittest.IsolatedAsyncioTestCase = _IsolatedAsyncioTestCase
