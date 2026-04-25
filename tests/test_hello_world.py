import uuid
from typing import Any
from aionetiface import *
from aionetiface.testing import AsyncTestCase


class TestHelloWorld(AsyncTestCase):
    async def test_hello_world(self) -> None:
        print("hello")
