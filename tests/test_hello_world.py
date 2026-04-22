import uuid
from typing import Any
from aionetiface import *


class TestHelloWorld(unittest.IsolatedAsyncioTestCase):
    async def test_hello_world(self) -> None:
        print("hello")
