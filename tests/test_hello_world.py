import uuid
from aionetiface import *
from aionetiface.testing import AsyncTestCase


class TestHelloWorld(AsyncTestCase):
    async def test_hello_world(self):
        print("hello")
