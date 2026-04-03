Socket Close Determinism
=============================

In Python 3 with asyncio, the "correct" way to close a protocol transport
is to call close() on the transport. You might also await an event set
in the connection_lost callback. Most developers assume this indicates
the underlying socket is closed and resources are freed.

They are wrong.

The "Ghost FD" Problem
-----------------------------

At some nebulous point after connection_lost fires, the event loop still
has to physically close the socket and unregister it from being monitored
by the OS kernel. This creates "Ghost FDs"—file descriptors that are
logically dead in your code but physically open in the OS.

The common advice to "fix" this is:
await asyncio.sleep(0)  # Yield to the loop

This is a fallacy. sleep(0) only yields for one loop "tick." If the TCP
stack is waiting on a FIN/ACK handshake, or if an SSL/TLS "Close Notify"
handshake is in progress, one tick is meaningless. Because coroutines
are concurrent, ordering is unpredictable. You have zero control over
what the loop prioritizes.

The SSL/TLS Handshake Trap
----------------------------------

When closing an encrypted transport, asyncio must perform a cryptographic
handshake to terminate the session securely.

Application calls transport.close()

Transport stays active to send/receive Close Notify packets

Only AFTER the handshake completes does the loop release the FD

If the peer is slow, the FD remains "leaked" in the selector's interest
set indefinitely, regardless of sleep(0) or connection_lost.

The Solution: Selector Interception
---------------------------------------------

To solve this, we must go one level deeper than the Protocol API. By
creating a custom ProxySelector, we can intercept the exact moment the
event loop decides it is finished with a resource.

Determinism: We only signal "closed" when the loop calls unregister().

Stability: Unlike internal loop APIs (like _remove_reader), the
selectors module (PEP 443) is a stable public API (since Python 3.4).

Accuracy: This is the only way to ensure the OS has actually released
the FD, preventing resource exhaustion (EMFILE) in high-churn
environments like TCP hole punching.

Note: This is specifically for SelectorEventLoop. Proactor (Windows)
and other loops handle FDs differently, but Selector remains the
requirement for complex, low-level networking where timing is critical.