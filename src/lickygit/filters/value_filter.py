"""Value-level filtering to reduce false positives."""

from __future__ import annotations


_DEFAULT_EXCLUDED_LOWER: set[str] = {
    "true", "false", "null", "none", "nil", "undefined", "nan",
    "todo", "fixme", "change_me", "changeme", "replace_me",
    "placeholder", "example", "test", "dummy", "sample",
    "your_api_key_here", "your-api-key-here", "insert_here",
    "xxx", "yyy", "zzz", "abc", "abcdef", "foobar", "foo", "bar",
    "password", "secret", "token", "passw0rd", "value", "val", "values",
    "string", "text", "var", "variable", "lambda", "function", "func", "callback", "handler",
}

_FALSE_PREFIXES: tuple[str, ...] = (
    "your-", "your_", "my-", "my_", "<", "${", "%(", "{{",
    "example", "test", "dummy", "sample", "fake", "mock", "lambda", "func",
)

_FALSE_SUFFIXES: tuple[str, ...] = (
    ">", "}", ")", "...", "here", "_test", "-test",
)


class ValueFilter:
    """Filter out values that are obviously **not** real secrets.

    Catches placeholders (``TODO``, ``your-xxx-here``), overly-short
    values, and values composed of a single repeated character.
    """

    def __init__(
        self,
        min_length: int = 4,
        excluded_values: list[str] | None = None,
    ) -> None:
        self.min_length = min_length
        self._excluded: set[str] = set(_DEFAULT_EXCLUDED_LOWER)
        if excluded_values:
            self._excluded.update(v.lower() for v in excluded_values)

    def is_valid_secret(self, value: str) -> bool:
        """Return *True* if *value* looks like it could be a real secret."""
        v = value.strip().strip("'\"` ")

        if len(v) < self.min_length:
            return False

        v_lower = v.lower()

        if v_lower in self._excluded:
            return False

        if v_lower.startswith(_FALSE_PREFIXES):
            return False

        if v_lower.endswith(_FALSE_SUFFIXES):
            return False

        # All identical characters (e.g. "xxxxxxxx", "0000000")
        if len(set(v)) <= 1:
            return False

        # All asterisks (masked values)
        if set(v) == {"*"}:
            return False

        return True
