import socket
import copy
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
            "host": "ovh1.aionetiface.net",
            "ip": "158.69.27.176",
            "port": 5300,
            "pk": "03f20b5dcfa5d319635a34f18cb47b339c34f515515a5be733cd7a7f8494e97136"
        },
        {
            "host": "hetzner1.aionetiface.net",
            "ip": "88.99.211.216",
            "port": 5300,
            "pk": "0249fb385ed71aee6862fdb3c0d4f8b193592eca4d61acc983ac5d6d3d3893689f"
        },
    ],
    IP6: [
        {
            "host": "ovh1.aionetiface.net",
            "ip": "2607:5300:0060:80b0:0000:0000:0000:0001",
            "port": 5300,
            "pk": "03f20b5dcfa5d319635a34f18cb47b339c34f515515a5be733cd7a7f8494e97136"
        },
        {
            "host": "hetzner1.aionetiface.net",
            "ip": "2a01:04f8:010a:3ce0:0000:0000:0000:0003",
            "port": 5300,
            "pk": "0249fb385ed71aee6862fdb3c0d4f8b193592eca4d61acc983ac5d6d3d3893689f"
        },
    ],
}


"""
Used to lookup what a nodes IP is and do NAT enumeration.
Supports IPv6 / IPv4 / TCP / UDP -- change IP and port requests.

STUNT servers support TCP.
STUND servers support UDP.
"""


MQTT_SERVERS = [{'host': None, 'port': 1883, IP4: '54.36.178.49', IP6: None}, {'host': None, 'port': 1883, IP4: '34.243.217.54', IP6: None}, {'host': None, 'port': 1883, IP4: '158.69.27.176', IP6: None}, {'host': None, 'port': 1883, IP4: '159.223.240.227', IP6: None}, {'host': None, 'port': 1883, IP4: '5.2.79.70', IP6: None}, {'host': None, 'port': 1883, IP4: '34.253.103.94', IP6: None}, {'host': None, 'port': 1883, IP4: '119.42.55.129', IP6: None}, {'host': None, 'port': 1883, IP4: '3.120.233.97', IP6: None}, {'host': None, 'port': 1883, IP4: '3.122.9.99', IP6: None}, {'host': None, 'port': 1883, IP4: '35.156.25.69', IP6: None}, {'host': None, 'port': 1883, IP4: '35.172.255.228', IP6: None}, {'host': None, 'port': 1883, IP4: '161.35.233.32', IP6: None}, {'host': None, 'port': 1883, IP4: '161.35.233.32', IP6: None}, {'host': None, 'port': 1883, IP4: None, IP6: '2001:41d0:0303:4831:0000:0000:0000:0001'}, {'host': None, 'port': 1883, IP4: None, IP6: '2a04:52c0:0101:0a90:0000:0000:0000:0000'}, {'host': None, 'port': 1883, IP4: None, IP6: '2607:5300:0060:80b0:0000:0000:0000:0001'}]



"""
These are TURN servers used as fallbacks (if configured by a P2P pipe.)
They are not used for 'p2p connections' by default due to their use of
UDP and unordered delivery but it can be enabled by adding 'P2P_RELAY'
to the strategies list in open_pipe().

Please do not abuse these servers. If you need proxies use Shodan or Google
to find them. If you're looking for a TURN server for your production
Web-RTC application you should be running your own infrastructure and not
rely on public infrastructure (like these) which will be unreliable anyway.

Testing:

It seems that recent versions of Coturn no longer allow you to relay data
from your own address back to yourself. This makes sense -- after-all
-- TURN is used to relay endpoints and it doesn't make sense to be
relaying information back to yourself. But it has meant to designing a
new way to test these relay addresses that relies on an external server
to send packets to the relay address.

Note:
-----------------------------------------------------------------------
These servers don't seem to return a reply on the relay address.
Most likely this is due to the server using a reply port that is different
to the relay port and TURN server port. This will effect most types of 
NATs, unfortunately. So they've been removed from the server list for now.

{
    "host": b"webrtc.free-solutions.org",
    "port": 3478,
    "afs": [IP4],
    "ip": {
        IP4: "94.103.99.223"
    },
    "user": b"tatafutz",
    "pass": b"turnuser",
    "realm": None
},


{
    "host": b"openrelay.metered.ca",
    "port": 80,
    "afs": [IP4],
    "
    "user": b"openrelayproject",
    "pass": b"openrelayproject",
    "realm": None
}
    
    {
        "host": b"aionetiface.net",
        "port": 3478,
        "afs": [IP4, IP6],
        "user": None,
        "pass": None,
        "realm": b"aionetiface.net"
    },
"""
TURN_SERVERS = [{'host': None, 'port': 3478, IP4: '152.67.9.43', IP6: None, 'afs': [IP4], 'user': 'contus', 'pass': 'SAE@admin', 'realm': None}, {'host': None, 'port': 3477, IP4: '45.81.18.104', IP6: None, 'afs': [IP4], 'user': 'melodymine', 'pass': 'melodymine', 'realm': None}, {'host': None, 'port': 3478, IP4: '146.190.244.213', IP6: None, 'afs': [IP4], 'user': 'quickblox', 'pass': 'baccb97ba2d92d71e26eb9886da5f1e0', 'realm': None}, {'host': None, 'port': 443, IP4: '203.56.114.226', IP6: None, 'afs': [IP4], 'user': 'threema-angular', 'pass': 'Uv0LcCq3kyx6EiRwQW5jVigkhzbp70CjN2CJqzmRxG3UGIdJHSJV6tpo7Gj7YnGB', 'realm': None}, {'host': None, 'port': 443, IP4: '51.195.101.185', IP6: None, 'afs': [IP4], 'user': 'steve', 'pass': 'setupYourOwnPlease', 'realm': None}, {'host': None, 'port': 3478, IP4: '47.96.130.35', IP6: None, 'afs': [IP4], 'user': 'webrtc', 'pass': 'Webrtc987123654', 'realm': None}, {'host': None, 'port': 3478, IP4: '94.103.99.223', IP6: None, 'afs': [IP4], 'user': 'tatafutz', 'pass': 'turnuser', 'realm': None}, {'host': None, 'port': 3478, IP4: '188.40.107.24', IP6: None, 'afs': [IP4], 'user': 'M9DRVaByiujoXeuYAAAG', 'pass': 'TpHR9HQNZ8taxjb3', 'realm': None}, {'host': None, 'port': 4589, IP4: '158.69.27.176', IP6: None, 'afs': [IP4], 'user': None, 'pass': None, 'realm': None}]

# Port is ignored for now.
NTP_SERVERS = [
    {
        "host": "time.google.com",
        "port": 123,
        IP4: "216.239.35.4",
        IP6: "2001:4860:4806::"
    },
    {
        "host": "pool.ntp.org",
        "port": 123,
        IP4: "162.159.200.123",
        IP6: None
    },
    {
        "host": "time.cloudflare.com",
        "port": 123,
        IP4: "162.159.200.123",
        IP6: "2606:4700:f1::1"
    },
    {
        "host": "time.facebook.com",
        "port": 123,
        IP4: "129.134.26.123",
        IP6: "2a03:2880:ff0a::123"
    },
    {
        "host": "time.windows.com",
        "port": 123,
        IP4: "52.148.114.188",
        IP6: None
    },
    {
        "host": "time.apple.com",
        "port": 123,
        IP4: "17.253.66.45",
        IP6: "2403:300:a08:3000::31"
    },
    {
        "host": "time.nist.gov",
        "port": 123,
        IP4: "129.6.15.27",
        IP6: "2610:20:6f97:97::4"
    },
    {
        "host": "utcnist.colorado.edu",
        "port": 123,
        IP4: "128.138.140.44",
        IP6: None
    },
    {
        "host": "ntp2.net.berkeley.edu",
        "port": 123,
        IP4: "169.229.128.142",
        IP6: "2607:f140:ffff:8000:0:8003:0:a"
    },
    {
        "host": "time.mit.edu",
        "port": 123,
        IP4: "18.7.33.13",
        IP6: None
    },
    {
        "host": "time.stanford.edu",
        "port": 123,
        IP4: "171.64.7.67",
        IP6: None
    },
    {
        "host": "ntp.nict.jp",
        "port": 123,
        IP4: "133.243.238.243",
        IP6: "2001:df0:232:eea0::fff4"
    },
    {
        "host": "ntp1.hetzner.de",
        "port": 123,
        IP4: "213.239.239.164",
        IP6: "2a01:4f8:0:a0a1::2:1"
    },
    {
        "host": "ntp.ripe.net",
        "port": 123,
        IP4: "193.0.0.229",
        IP6: "2001:67c:2e8:14:ffff::229"
    },
    {
        "host": "clock.isc.org",
        "port": 123,
        IP4: "64.62.194.188",
        IP6: "2001:470:1:b07::123:2000"
    },
    {
        "host": "ntp.ntsc.ac.cn",
        "port": 123,
        IP4: "114.118.7.163",
        IP6: None
    },
    {
        "host": "1.amazon.pool.ntp.org",
        "port": 123,
        IP4: "103.152.64.212",
        IP6: None
    },
    {
        "host": "0.android.pool.ntp.org",
        "port": 123,
        IP4: "159.196.44.158",
        IP6: None
    },
    {
        "host": "0.pfsense.pool.ntp.org",
        "port": 123,
        IP4: "27.124.125.250",
        IP6: None
    },
    {
        "host": "0.debian.pool.ntp.org",
        "port": 123,
        IP4: "139.180.160.82",
        IP6: None
    },
    {
        "host": "0.gentoo.pool.ntp.org",
        "port": 123,
        IP4: "14.202.65.230",
        IP6: None
    },
    {
        "host": "0.arch.pool.ntp.org",
        "port": 123,
        IP4: "110.232.114.22",
        IP6: None
    },
    {
        "host": "0.fedora.pool.ntp.org",
        "port": 123,
        IP4: "139.180.160.82",
        IP6: None
    }
]


