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
        return
        i = await Interface()
        print(i)
    
        dest = ("3.132.228.249", 3478)
        s = STUNClient(IP4, dest, i)
        _, _, p = await s.get_mapping()
    

        ctup = ("3.135.212.85", 3479)
        #out = await s.get_change_port_reply(ctup, p)
        #print(out)

        out = await s.get_change_tup_reply(ctup)
        print(out)

if __name__ == '__main__':
    main()