from aionetiface import *

# set event loop to ProactorEventLoop
#asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

async def workspace():
    loop = asyncio.get_event_loop()
    print("Event loop:", loop)
    nic = await Interface()
    print(nic)

async_run(workspace())