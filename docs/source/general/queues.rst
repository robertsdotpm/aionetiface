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

Using queues
---------------

A subscription consists of:

.. code-block:: python
    
    (
        b"optional regex msg pattern", 
        (b"optional IP, optional reply port)
    )

A good way to show queue usage is to look at how its used already by the STUN
client. Since UDP packets arrives out of order: the TXID of a reply message along
with the expected reply address is subscribed to. Note that reply addresses
passed for matching are normalised so IPv6 addresses are fully expanded.

.. code-block:: python

    sub = (re.escape(msg.txn_id), reply_addr)
    pipe.subscribe(sub)

By default if you await pipe.recv() -- what you're really doing is awaiting
the queue for SUB_ALL -- a queue that matches all messages and senders --
that gets setup automatically when no message handers are setup for a pipe
and the pipe has a destination set.

Final conclusions
----------------------

Messages are delivered to every matching subscription queues. If you subscribe to
a specific pattern / tup you may end up with copies of every message because by
default pipes with a destination (and no associated msg_cb handlers) subscribe
to all messages. To unsubscribe from all messages:

.. code-block:: python

    pipe.unsubscribe(SUB_ALL)

This design is probably a terrible idea but it's meant for control, not speed.