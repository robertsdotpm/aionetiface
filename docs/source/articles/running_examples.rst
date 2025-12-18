Running examples
-------------------

**Running async examples**

aionetiface uses Python's 'asynchronous' features to run everything in an event loop.
One way to try out code is to run it in an interactive prompt.
For convenience aionetiface includes an interactive prompt that lets you run async
code. It handles having to choose the right event loop, setup multiprocessing,
and import aionetiface so code works more consistently across platforms.

.. code-block:: shell

    python3 -m aionetiface

.. code-block:: python3

    aionetiface 2.7.9 REPL on Python 3.8 / win32
    Loop = selector, Process = spawn
    Use "await" directly instead of "asyncio.run()".
    >>> from aionetiface import *

Now you can type `await some_function()` in the prompt to execute it.
If you experience errors in the prompt you'll have to use a regular Python
file for the examples.

**All example code assumes that:**

    1. The custom event loop is used (based on selector.)
    2. The 'spawn' method is used as the multiprocessing start method.
    3. You are familiar with how to run asynchronous code.
    4. The string encoding is "UTF-8."

This keeps execution consistent across platforms. The package sets
these by default so if your application is using a different configuration
it may not work properly with aionetiface.