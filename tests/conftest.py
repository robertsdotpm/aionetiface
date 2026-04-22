"""Test configuration: install the aionetiface event-loop policy for all tests.

Previously the library applied its custom event-loop policy, multiprocessing
start method, and selector transport patch implicitly at import time. That
behaviour is now opt-in via ``aionetiface_setup_event_loop()``; the test suite
invokes it here so every test sees the same runtime environment the library
expects in production code.
"""
from aionetiface import aionetiface_setup_event_loop


aionetiface_setup_event_loop()
