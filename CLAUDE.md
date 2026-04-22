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
