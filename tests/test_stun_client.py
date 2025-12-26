"""
nc -4 -u aionetiface.net 7

"""



import os
from aionetiface import *


env = os.environ.copy()
class TestStunClient(unittest.IsolatedAsyncioTestCase):
    """
    Disabled for now (theres enough indirect tests for stun.)
    """
    async def test_stun_client(self):
        i = await Interface("default")
        print(i)
    
        dest = ("52.24.174.49", 3478)
        s = STUNClient(IP4, dest, i, mode=RFC5389)
        out = await s.get_wan_ip()
        print(out)
        return
    

        ctup = ("3.135.212.85", 3479)
        #out = await s.get_change_port_reply(ctup, p)
        #print(out)

        out = await s.get_change_tup_reply(ctup)
        print(out)

if __name__ == '__main__':
    main()