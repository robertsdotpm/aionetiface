"""Global tunables and infrastructure address constants."""
import socket

__all__ = [
    "IP4",
    "IP6",
    "UDP",
    "TCP",
    "ENABLE_STUN",
    "ENABLE_UDP",
    "aionetiface_TEST_INFRASTRUCTURE",
    "PNP_SERVERS",
]

IP4 = socket.AF_INET
IP6 = socket.AF_INET6
UDP = socket.SOCK_DGRAM
TCP = socket.SOCK_STREAM

ENABLE_STUN = True
ENABLE_UDP = True
aionetiface_TEST_INFRASTRUCTURE = False


"""
To keep things simple aionetiface uses a number of services to
help facilitate peer-to-peer connections. At the moment
there is no massive list of servers to use because
(as I've learned) -- you need to also have a way to
monitor the integrity of servers to provide high-quality
server lists to peers. That would be too complex to provide
starting out so this may be added down the road.

Note to any engineers:

If you wanted to run aionetiface privately you could simply
point all of these servers to your private infrastructure.

https://github.com/pradt2/always-online-stun/tree/master
https://datatracker.ietf.org/doc/html/rfc8489
"""

PNP_SERVERS = {
    IP4: [
        {
            "host": "ovh1.p2pd.net",
            "ip": "158.69.27.176",
            "port": 5300,
            "pk": "03f20b5dcfa5d319635a34f18cb47b339c34f515515a5be733cd7a7f8494e97136",
        },
    ],
    IP6: [
        {
            "host": "ovh1.p2pd.net",
            "ip": "2607:5300:0060:80b0:0000:0000:0000:0001",
            "port": 5300,
            "pk": "03f20b5dcfa5d319635a34f18cb47b339c34f515515a5be733cd7a7f8494e97136",
        },
    ],
}
