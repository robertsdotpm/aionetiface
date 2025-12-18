Socket close
================

In Python3 with asyncio, the "correct" way to close a protocol transport
is to call close on the transport. You can also await an event set in
connection_lost. You would think that would be enough to indicate that
the underlying socket was closed (but it's not.)

At some nebulous point later: the event loop still has to close the socket
and delete it from being monitored. The advice to make sure this happens
is to await asyncio.sleep(0) to ensure the event loop runs to process
the transport.close() properly. But ah... wait, no, that also doesn't
work. The issue is you have no control on what happens when an
event loop runs / what it prioritized / which is a race condition.
That's the whole thing with coroutines and concurrency -- ordering
is unpredictable. So the whole await sleep ... pattern doesn't work.

This is also the reason why almost all Python network code in the wild
is wrong and littered with resource bugs about unclosed sockets.
So how to properly solve the issue? Just my view, but I think the right
way is to make the event loop set an event when a socket is closed. Then
you can get the awaitable and await when the event loop closes it. 

Some caveats in implementing this though: a first attempt might try to
overload internal reader / writer close functions. But the thing with
internal APIs is they can change between Python versions. For 3.13 APIs
like _remove_reader didn't exist in Python 3.5 (and this project is going
for heavy backwards compatibility.) So the approach I take is this: go
one level deeper -- and create a custom Selector. Then it's possible to
--only-- use public APIs to signal socket close behavior: unregister
and modify (available since Python 3.4.)

BTW: this is for asyncio.SelectorEventLoop only. There are other event loops,
this project only uses Selector though as its the one that works with
complex code like TCP hole punching.