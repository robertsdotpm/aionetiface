Queues
========

If you want to use the push / pull APIs there are some details
you might find useful. In order to support these APIs the
software must be able to save messages. It does this by using queues.
Each queue may be indexed by a message regex and an
optional tuple for a reply address.

These queues only exist when a subscription is made. **By default aionetiface
subscribes to all messages when a destination is provided for a pipe and
so does the REST API.**

Why use message subscriptions?
--------------------------------

You may know already that UDP offers no delivery guarantees. What this means is most UDP
protocols (like STUN) end up using randomized IDs in
requests / responses as kind of an asynchronous form of 'ordering.'
There is also the case of UDP being 'connectionless.' This means
you can have a single socket send packets to many destinations.

What ends up happening is you get messages [on the same socket] that:

    1. **... Are from different hosts and or ports.**
    2. **... Match different requests.**

So I had the idea of being able to sort messages into queues.
Such an approach is flexible and is already used by the STUN client.
Here's what that looks like in practice.

TODO: finish queues section.

Final conclusions
----------------------

Messages are delivered to every matching subscription queues. If you subscribe to
a specific pattern / tup you may end up with copies of every message because by
default pipes with a destination subscribe to all messages. To unsubscribe
from all messages:

.. code-block:: python

    pipe.unsubscribe(SUB_ALL)

