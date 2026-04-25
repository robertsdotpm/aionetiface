from typing import Any
from aionetiface import *
from aionetiface.testing import AsyncTestCase

import asyncio


class TestEventLoops(AsyncTestCase):
    async def test_event_loops_a(self) -> None:
        running_loop = asyncio.get_event_loop()


if __name__ == "__main__":
    main()
