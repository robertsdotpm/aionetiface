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

## Off-limits files

**Never modify any file under `src/aionetiface/net/asyncio/`** — these files patch CPython asyncio internals for Python 3.5 backwards compatibility and are extremely sensitive to change. This includes:

- `asyncio_patches.py`
- `async_run.py`
- `event_loop.py`
- `create_udp_fallback.py`

## Pyflakes false positives in re-export hubs

`do_imports.py` and `__init__.py` are intentional re-export hubs: they import everything from submodules solely to make those names available on the top-level `aionetiface` namespace. Pyflakes cannot distinguish "imported to re-export" from "imported but unused" unless the hub defines a comprehensive `__all__`.

Do not add `__all__` to `do_imports.py` or `__init__.py` to silence these warnings. The namespace currently exports ~456 public names (including stdlib modules re-exported by `test_init.py` for test convenience), and a static `__all__` would restrict what callers can import — breaking downstream code that does `from aionetiface import X` for any name not in the list. The 66 "imported but unused" warnings pyflakes emits for these two files are known false positives and should be ignored.

The two warnings from the off-limits `net/asyncio/` files (`selectors.SelectSelector`, `typing.List`) are similarly unfixable.

## Leading-underscore backwards-compatibility exceptions

Some methods and module-level names predate the no-leading-underscore convention and cannot be renamed because external code already calls them by their `_foo` names. These are **grandfathered** — do not rename them and do not add new ones:

- All names in `net/asyncio/` (off-limits anyway)
