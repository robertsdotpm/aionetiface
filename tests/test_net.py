from aionetiface import *


class TestNet(unittest.IsolatedAsyncioTestCase):
    async def test_ip_norm(self):
        tests = [
            ["1.1.1.1%test", "1.1.1.1"],
            ["1.1.1.1/24", "1.1.1.1"],
            ["1.1.1.1%test/24", "1.1.1.1"],
            ["::", ("0000:" * 8)[:-1]],
            ["::%test/24", ("0000:" * 8)[:-1]],
            ["::", ("0000:" * 8)[:-1]],
            ["2402:1f00:8101:083f:0000:0000:0000:0001", "2402:1f00:8101:083f:0000:0000:0000:0001"]
        ]

        for src_ip, out_ip in tests:
            self.assertEqual(ip_norm(src_ip), out_ip)

    async def test_netmask_to_cidr(self):
        nm = "255.255.255.255"
        out = netmask_to_cidr(nm)
        self.assertEqual(32, out)

    async def test_toggle_host_bits(self):
        nm = "255.255.0.0"
        out = toggle_host_bits(nm, "192.168.0.0", toggle=1)
        self.assertEqual(out, "192.168.255.255")


    """
    TODO: 
    async def test_nt_net(self):
        if platform.system() == "Windows":
            out = await nt_ipconfig()
            print(out)

            out = await nt_route_print(desc=None)
            print(out)
    """



if __name__ == '__main__':
    main()