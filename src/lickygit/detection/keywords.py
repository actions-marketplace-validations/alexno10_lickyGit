"""Keyword + assignment detection (improved from gittyleaks)."""

from __future__ import annotations

import re
from dataclasses import dataclass

# --------------------------------------------------------------------------- #
# Default keyword list
# --------------------------------------------------------------------------- #

DEFAULT_KEYWORDS: list[str] = [
    "api_key", "apikey", "api",
    "access_key", "access_token",
    "auth_token", "auth", "authorization",
    "client_secret", "client_id",
    "connection_string", "conn_str",
    "credential", "credentials",
    "database_url", "db_password", "db_pass",
    "email",
    "encryption_key",
    "key",
    "login",
    "password", "passwd", "pwd", "pass",
    "private_key", "private-key",
    "secret", "secret_key",
    "token",
    "user", "username",
]

# --------------------------------------------------------------------------- #
# Values to ignore (false positives)
# --------------------------------------------------------------------------- #

_FALSE_POSITIVE_VALUES: set[str] = {
    "", "true", "false", "null", "none", "nil", "undefined",
    "todo", "fixme", "change_me", "changeme", "replace_me",
    "placeholder", "example", "test", "dummy", "sample",
    "your_api_key_here", "your-api-key-here", "insert_here",
    "xxx", "yyy", "zzz", "value", "val", "values", "string", "text", "var", "variable",
    "lambda", "function", "func", "callback", "handler",
}

_FALSE_POSITIVE_PREFIXES: tuple[str, ...] = (
    "your-", "your_", "my-", "my_", "<", "${", "%(", "{{",
    "example", "test", "dummy", "sample", "fake", "lambda", "func",
)

_FALSE_POSITIVE_SUFFIXES: tuple[str, ...] = (
    ">", "}", ")", "...", "here",
)


# --------------------------------------------------------------------------- #
# Assignment patterns (covers most config formats)
# --------------------------------------------------------------------------- #

# Each pattern has named groups: `keyword` and `value`
_ASSIGNMENT_PATTERNS: list[re.Pattern[str]] = [
    # key = "value"  |  key = 'value'  |  key = value
    re.compile(
        r"""(?:^|[\s._-])(?P<keyword>{kw})"""
        r"""\s*[=:]\s*['"]?(?P<value>[^'"\s,;#][^'"\n]{{0,200}})['"]?""",
        re.IGNORECASE,
    ),
    # "key": "value"  (JSON)
    re.compile(
        r"""['"](?P<keyword>{kw})['"]"""
        r"""\s*:\s*['"](?P<value>[^'"]+)['"]""",
        re.IGNORECASE,
    ),
    # export KEY=value
    re.compile(
        r"""export\s+(?P<keyword>{kw})\s*=\s*['"]?(?P<value>[^'"\s]+)['"]?""",
        re.IGNORECASE,
    ),
    # key => value  (Ruby, PHP)
    re.compile(
        r"""['"]?(?P<keyword>{kw})['"]?\s*=>\s*['"]?(?P<value>[^'"\s,;]+)['"]?""",
        re.IGNORECASE,
    ),
]


@dataclass(frozen=True, slots=True)
class KeywordMatch:
    """A keyword-assignment match."""

    keyword: str
    value: str
    line_number: int
    line_content: str
    assignment_type: str  # "equals", "colon", "export", "arrow"


class KeywordDetector:
    """Detect secrets via keyword-assignment pattern matching.

    Looks for lines like ``PASSWORD = 's3cret'`` and captures the value,
    filtering out common placeholder / false-positive values.
    """

    def __init__(
        self,
        keywords: list[str] | None = None,
        case_sensitive: bool = False,
        min_value_length: int = 4,
    ) -> None:
        self.keywords = keywords or DEFAULT_KEYWORDS
        self.case_sensitive = case_sensitive
        self.min_value_length = min_value_length

        # Build compiled patterns with the keyword alternation baked in
        kw_alt = "|".join(re.escape(k) for k in self.keywords)
        flags = 0 if case_sensitive else re.IGNORECASE
        self._patterns: list[tuple[re.Pattern[str], str]] = []
        for idx, pat in enumerate(_ASSIGNMENT_PATTERNS):
            compiled = re.compile(pat.pattern.format(kw=kw_alt), flags)
            label = ["equals", "colon/json", "export", "arrow"][idx]
            self._patterns.append((compiled, label))

    # ------------------------------------------------------------------ #

    def _is_false_positive(self, value: str) -> bool:
        """Return *True* if the value is a known false-positive."""
        v = value.strip().strip("'\"").strip()

        if len(v) < self.min_value_length:
            return True

        v_lower = v.lower()
        if v_lower in _FALSE_POSITIVE_VALUES:
            return True
        if v_lower.startswith(_FALSE_POSITIVE_PREFIXES):
            return True
        if v_lower.endswith(_FALSE_POSITIVE_SUFFIXES):
            return True

        # All identical characters (e.g. "xxxxxxxx")
        if len(set(v)) == 1:
            return True

        return False

    # ------------------------------------------------------------------ #

    def scan_line(self, line: str, line_number: int = 0) -> list[KeywordMatch]:
        """Return all keyword-assignment matches found in *line*."""
        matches: list[KeywordMatch] = []
        for pattern, assign_type in self._patterns:
            for m in pattern.finditer(line):
                keyword = m.group("keyword")
                value = m.group("value").strip().rstrip("'\"`,;")

                if self._is_false_positive(value):
                    continue

                matches.append(
                    KeywordMatch(
                        keyword=keyword,
                        value=value,
                        line_number=line_number,
                        line_content=line,
                        assignment_type=assign_type,
                    )
                )
        return matches

    def scan_content(self, content: str) -> list[KeywordMatch]:
        """Scan every line of *content* and return all matches."""
        all_matches: list[KeywordMatch] = []
        for line_no, line in enumerate(content.splitlines(), start=1):
            all_matches.extend(self.scan_line(line, line_number=line_no))
        return all_matches
