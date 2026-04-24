# aionetiface — project instructions

## Python compatibility

`requires-python = ">=3.5"` is intentional and must not be changed. Do not raise the minimum Python version under any circumstances.

## String formatting

Never use f-string literals (`f"..."`). They require Python 3.6+ and break the 3.5 constraint. Use the `fstr(template, args_tuple)` helper from `aionetiface.utility.fstr` instead:

```python
fstr("value is {0}", (val,))
```

## Naming

Never use leading-underscore names for variables, attributes, methods, or functions (e.g. no `_foo`, `_cancel_tasks`, `_private`). Use plain names: `cancel_tasks`, `idle_pipe_closer`, etc. The single exception is dunder names (`__init__`, `__all__`, etc.) which are required by Python itself.

## Print statements

Never remove or comment out `print()` calls. They are intentional debugging and observability hooks — leave them exactly as found.

## Error handling

- Use `ValueError` for invalid input at API boundaries.
- Use `AssertionError` (or bare `assert`) for internal invariants that should never be false.
- Do not use `RuntimeError` as a catch-all for invariant violations.
- At network/IO boundaries, catch specific exceptions (`OSError`, `ConnectionError`, `asyncio.TimeoutError`) rather than broad `Exception` sweeps.
- Pick one error idiom per function: either return a sentinel value or raise — not both.

## Event loop — CustomEventLoop everywhere

Always use `CustomEventLoop` (defined in `net/asyncio/event_loop.py`) on all platforms including Windows. It extends `asyncio.SelectorEventLoop` and installs a `ProxySelector` that signals socket-close futures.

**Never set `ProactorEventLoop` or `WindowsProactorEventLoopPolicy`.** ProactorEventLoop is not needed:

- **UDP on Windows**: handled by `PolledDatagramTransport` in `net/pipe/pipe.py`, which works with any loop type.
- **`asyncio.create_subprocess_shell` on Windows**: raises `NotImplementedError` on SelectorEventLoop, but `cmd()` in `utility/cmd_tools.py` already catches that and falls back to `subprocess.run` in a thread executor.
- **No Windows named pipes or other Proactor-specific IPC** is used anywhere in the codebase.

The entry point is `aionetiface_setup_event_loop()` in `entrypoint.py`, which installs `CustomEventLoopPolicy` globally. Call it once at process startup (tests do this in `conftest.py`). Do not call it at module import time.

## Multiprocessing start method — spawn

`aionetiface_setup_event_loop()` sets the multiprocessing start method to `"spawn"` (not `"fork"`). This is intentional and must not be changed:

- `"fork"` copies the parent's open sockets and event-loop state into the child, which causes subtle corruption when the child creates its own event loop — especially on Windows where fork isn't available at all.
- `"spawn"` starts a clean interpreter with no inherited file descriptors or loop state, matching the behaviour you get on Windows and macOS by default.
- All platforms in the test matrix (Windows XP–11, Linux, macOS, FreeBSD, Android) support `"spawn"`.

## Pyflakes false positives in re-export hubs

`do_imports.py` and `__init__.py` are intentional re-export hubs: they import everything from submodules solely to make those names available on the top-level `aionetiface` namespace. Pyflakes cannot distinguish "imported to re-export" from "imported but unused" unless the hub defines a comprehensive `__all__`.

Do not add `__all__` to `do_imports.py` or `__init__.py` to silence these warnings. The namespace currently exports ~456 public names (including stdlib modules re-exported by `test_init.py` for test convenience), and a static `__all__` would restrict what callers can import — breaking downstream code that does `from aionetiface import X` for any name not in the list. The 66 "imported but unused" warnings pyflakes emits for these two files are known false positives and should be ignored.

The two warnings from the `net/asyncio/` files (`selectors.SelectSelector`, `typing.List`) are similarly unfixable.

## Leading-underscore backwards-compatibility exceptions

Some methods and module-level names predate the no-leading-underscore convention and cannot be renamed because external code already calls them by their `_foo` names. These are **grandfathered** — do not rename them and do not add new ones:

- All names in `net/asyncio/`

## Test agents — Windows firewall checks

After running tests on Windows, check the system event log for firewall notifications related to bind/listen failures:

- Event Viewer → Windows Logs → Security — look for blocked inbound/outbound connections (Event ID 5152, 5157)
- Also check the Windows Security Center / Action Center tray for queued blocked-app alerts
- Cross-reference any TURN/STUN/UDP test timeouts against bind tuples that were blocked

## Test agents — interface checks

When running tests on a remote machine, parse `ip addr` / `ipconfig /all` output carefully: ensure **all** interfaces are reported, not just the first. When a second adapter is added (e.g. a second NIC for external connectivity), it must be detected and included in the ENV vs BUG categorisation for any test that depends on interface count, routing, or address selection.

## Running tests

Always run with pytest-xdist for parallel execution and `--timeout=30` to prevent hung network tests from blocking the session forever. Use Python 3.5 from pyenv so breakage on the minimum supported version is caught immediately:

```sh
~/.pyenv/versions/3.5.10/bin/python -m pytest tests/ -n auto --dist=loadfile --timeout=30 -q
```

On Windows (pyenv-win), use the versioned python.exe directly:

```cmd
C:\Users\<user>\.pyenv\pyenv-win\versions\<ver>\python.exe -m pytest tests/ -n auto --dist=loadfile --timeout=30 -q
```

## Test dependencies

These packages are required to run the test suite but are not package dependencies. Install them separately:

```text
pytest-xdist     # parallel workers (-n auto --dist=loadfile)
pytest-timeout   # per-test timeout (--timeout=30) — without this, hung network tests block forever
```

```sh
pip install pytest-xdist pytest-timeout
```

### Python 3.5 install quirks

`setuptools>=68` uses Python 3.8+ syntax (walrus operator). On Python 3.5, bypass the build system:

```sh
pip install wheel "setuptools<50"
pip install --no-build-isolation --no-deps -e .
```

The same `--no-build-isolation --no-deps` flags apply when installing any of these sibling repos from a local checkout (do **not** install them from PyPI — they must come from the local source):

- `aionetiface` — core networking library
- `p2pd` — peer-to-peer daemon
- `namebump` — name resolution
- `sidewire` — transport layer

### Python 3.5.0 specifically (not 3.5.1+)

`typing.Type` was added in Python 3.5.3. Packages importing it crash on 3.5.0. Pin these:

```sh
pip install "pathlib2==2.2.1" "pytest==4.6.11" "pytest-xdist==1.34.0"
```

If pip was accidentally upgraded past 21.x on a 3.5.0 interpreter, restore it first:

```sh
python -m ensurepip
python -m pip install "pip==20.3.4" "setuptools<50"
```
