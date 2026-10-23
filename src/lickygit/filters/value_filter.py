"""Value-level filtering to reduce false positives."""

from __future__ import annotations

_DEFAULT_EXCLUDED_LOWER: set[str] = {
    "",
    "true",
    "false",
    "null",
    "none",
    "nil",
    "undefined",
    "nan",
    "todo",
    "fixme",
    "change_me",
    "changeme",
    "replace_me",
    "placeholder",
    "example",
    "test",
    "dummy",
    "sample",
    "your_api_key_here",
    "your-api-key-here",
    "insert_here",
    "xxx",
    "yyy",
    "zzz",
    "abc",
    "abcdef",
    "foobar",
    "foo",
    "bar",
    "password",
    "secret",
    "token",
    "passw0rd",
    "value",
    "val",
    "values",
    "string",
    "text",
    "var",
    "variable",
    "lambda",
    "function",
    "func",
    "callback",
    "handler",
    "latest",
    "stable",
    "nightly",
    "write",
    "read",
    "all",
    "root",
    "nobody",
    "required",
    "optional",
    "needed",
    "needed.",
    "default",
}

_FALSE_PREFIXES: tuple[str, ...] = (
    "your-",
    "your_",
    "my-",
    "my_",
    "<",
    "${",
    "%(",
    "{{",
    "example",
    "test",
    "dummy",
    "sample",
    "fake",
    "mock",
    "lambda",
    "func",
    # Python env loaders
    "os.getenv",
    "os.environ",
    "process.env",
    "sys.getenv",
    "system.getenv",
    # Rust env loaders
    "std::env::var",
    "std::env::var_os",
    "env::var",
    "env::var_os",
    # Go env loaders
    "os.lookupenv",
    # Java / C# env loaders
    "environment.getenvironmentvariable",
    # Generic config loaders
    "env(",
    "getenv(",
    "config(",
    "config.",
    "dotenv(",
    "settings.",
    "params.",
    "cfg.",
    "conf.",
    "options.",
    "opts.",
    "props.",
    "properties.",
    "self.",
    "this.",
    "request.",
    "update.",
    "ctx.",
    "context.",
    "auth.",
    "str(",
    "int(",
    "bool(",
    "dict(",
    "list(",
    "set(",
    # Type annotations
    "&str",
    "&[",
    "option<",
    "some(",
    "vec<",
    "box<",
    "arc<",
    "rc<",
    "string>",
    "result<",
    "hashmap<",
    # Doc / placeholder
    "...",
    "your ",
    "insert ",
)

_FALSE_SUFFIXES: tuple[str, ...] = (
    ">",
    "}",
    ")",
    "...",
    "here",
    "_test",
    "-test",
    ">()",
    ">>",
    ">();",
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

        # Plain HTTP(S) URLs without embedded credentials (user:pass@host)
        if v_lower.startswith(("http://", "https://")) and "@" not in v_lower:
            return False

        # Numbers or UID:GID / port mappings (e.g. 1000:1000, 8080:8080)
        if v.replace(":", "").replace("-", "").isdigit():
            return False

        # All identical characters (e.g. "xxxxxxxx", "0000000", "********")
        if len(set(v)) <= 1:
            return False

        # Value looks like a code expression (has parens, angle brackets, pipes)
        code_chars = sum(1 for c in v if c in "<>(){}|&;")
        if code_chars >= 2:
            return False

        # Natural language / documentation sentences (3+ words or English articles)
        words = v.split()
        if len(words) >= 3:
            return False
        return not v_lower.startswith(("the ", "a ", "an ", "this ", "that "))
