# aionetiface

Python: >= 3.5 asyncio Windows, Linux, Mac, BSD, Android

Event loops: Selector, Proactor (Windows), "CustomEventLoop" (aionetifaces
slightly better version of selector), uvloop

Aionetiface is a networking library for >= Python 3.5 that supports
multi-interface networking on most modern OSes. It includes back-ported patches from recent Python versions to make asyncio work better on older versions of Python as well as new features that aren't possible with asyncio today. 

```python3
   from aionetiface import *
   nic = await Interface() # Or add a name there "eth0"
   # nic_list = await list_interfaces()
```

You can use aionetiface to write software that works across multiple networks (like VPNs, proxies, file software, servers, etc.) The
software has many interesting features that set it apart from other libraries like being able to correctly identify external addressing
information and making that easy to use.

```python3
   # Bind to the first external IPv6 available
   route = nic.rp[IP6][0]
   pipe = await Pipe(TCP, ("example.com", 80), route).connect()
```

Above, shows an example of a unified interface for both client and server code based around the idea of "pipes." Programming can be done
in a similar way to Python's regular protocol classes (callback style)
or awaiting the pipe directly.

That's the tip of the ice berg though -- and the deeper you go -- the
more interesting (and maybe bizarre) things you will discover.

python3 -m pip install aionetiface

https://aionetiface.readthedocs.io/en/latest/

