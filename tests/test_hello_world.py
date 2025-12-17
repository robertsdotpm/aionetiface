import uuid
from aionetiface import *

class TestHelloWorld(unittest.IsolatedAsyncioTestCase):
    async def test_hello_world(self):
        print("hello")