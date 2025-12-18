Documentation
====================

Aionetiface is a networking library for >= Python 3.5 that supports
multi-interface networking.

.. code-block:: python

   nic = await Interface("eth0")

You can use it to write software that works across multiple networks. The
software is also designed around correctly identifying external IP addressing
information and making that easy to use. So you can write code like this:

.. code-block:: python

   # Bind to the first external IPv6 available
   route = nic.rp[IP6][0]
   pipe = await Pipe(TCP, ("example.com", 80), route).connect()

As shown already -- the software is heavily based on "pipes" which provide
a single, unified interface for writing clients and servers across transports.

.. toctree::
   general/index
   articles/index
   built/index
   dev/index

