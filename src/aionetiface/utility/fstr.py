"""Indexed positional string formatter and legacy eval-based formatter."""

import inspect
import re
from typing import Any, Optional, Tuple

__all__ = ["fstr", "fstr2"]


def fstr(expr: str, params: Tuple[Any, ...] = ()) -> str:
    """Replace each {N} placeholder in expr with params[N] and return the result."""
    # Replace each {expression} with the variable value.
    def replacer(match):
        """Return str(params[index]) for the matched {index} placeholder."""
        index = int(match.group(1))
        try:
            return str(params[index])
        except (IndexError, TypeError) as e:
            raise ValueError("Error evaluating expression " + str(index) + str(e))

    out = re.sub(r"\{([^}]*)\}", replacer, expr)
    return out


class fstr2(object):
    """Legacy string formatter that uses eval() to expand {expr} placeholders.

    DEPRECATED — do not use in new code.  Use Python f-strings or fstr()
    instead.  This class is retained only for backward compatibility with
    any existing callers.

    Security note: _clean_and_eval() calls eval() against the caller's local
    and global namespaces.  Never pass untrusted input to this class.

    Attributes:
        _string: the original template string.
        text: the formatted string with all {expr} placeholders expanded.
    """

    _regex = re.compile(r"\{([^{}]+)\}", re.S)

    def __init__(self, s: str, regex: Optional[Any] = None) -> None:
        """Init `F` with string `s`"""
        import warnings

        warnings.warn(
            "fstr2 is deprecated and uses eval() — use f-strings or fstr() instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        self.regex = regex or self._regex
        self._string = s
        self.f_locals = self.original_caller.f_locals
        self.f_globals = self.original_caller.f_globals
        self.text = self._find_and_replace(s)

    @property
    def original_caller(self) -> Any:
        names = []
        frames = []
        frame = inspect.currentframe()
        while True:
            try:
                frame = frame.f_back
                name = frame.f_code.co_name
                names.append(name)
                frames.append(frame)
            except AttributeError:
                break
        return frames[-2]

    def _find_and_replace(self, s: str) -> str:
        """Evaluates and returns all occurrences of `regex` in `s`"""
        return re.sub(self._regex, self._clean_and_eval, s)

    def _clean_and_eval(self, m: Any) -> str:
        """Remove surrounding braces and whitespace from regex match `m`,
        evaluate, and return the result as a string.

        """
        replaced = m.group()[1:][:-1].strip()
        try:
            result = str(eval(replaced))
            return result
        except (TypeError, NameError, SyntaxError):
            try:
                result = str(eval(replaced, self.f_locals, self.f_globals))
                return result
            except (TypeError, NameError, SyntaxError):
                raise ValueError("Can't find replacement for { %s }, sorry." % replaced)

    def __str__(self) -> str:
        return str(self.text)

    def __repr__(self) -> str:
        return str(self._string)
