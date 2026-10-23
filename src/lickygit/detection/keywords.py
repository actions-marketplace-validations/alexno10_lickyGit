"""Keyword + assignment detection (improved from gittyleaks)."""

from __future__ import annotations

import re
from dataclasses import dataclass

from lickygit.filters.value_filter import ValueFilter

# --------------------------------------------------------------------------- #
# Default keyword list
# --------------------------------------------------------------------------- #

DEFAULT_KEYWORDS: list[str] = [
    "api_key",
    "apikey",
    "access_key",
    "access_token",
    "auth_token",
    "client_secret",
    "connection_string",
    "conn_str",
    "database_url",
    "db_password",
    "db_pass",
    "encryption_key",
    "password",
    "passwd",
    "pwd",
    "private_key",
    "private-key",
    "secret",
    "secret_key",
    "token",
]

# --------------------------------------------------------------------------- #
# Line-level heuristics: skip entire lines matching these patterns
# --------------------------------------------------------------------------- #

# Comment-only lines (Python/Shell #, C/Rust //, SQL --, Lua --)
_COMMENT_RE = re.compile(
    r"^\s*(?://|#|--|/\*|\*|;|%|<!--)",
    re.MULTILINE,
)

# Function / method signatures across languages
_FUNC_SIGNATURE_RE = re.compile(
    r"(?:"
    r"\bfn\s+\w+\s*\("  # Rust: fn name(
    r"|\bfunc\s+[\w(]"  # Go: func name( or func (receiver)
    r"|\bdef\s+\w+\s*\("  # Python: def name(
    r"|\bfunction\s+\w+\s*\("  # JS/PHP: function name(
    r"|\b(?:public|private|protected|static|async|override|virtual)\s+"  # Java/C#/TS modifiers
    r"|\)\s*->\s*"  # Rust/Python return type: ) -> Type
    r"|\)\s*:\s*\w+"  # TypeScript return type: ): Type
    r")",
    re.IGNORECASE,
)

# Import / use / include / require lines
_IMPORT_RE = re.compile(
    r"^\s*(?:import\s|from\s|use\s|require\s|include\s|#include\s)",
    re.IGNORECASE,
)

# Struct / class / type / interface / enum definitions
_TYPE_DEF_RE = re.compile(
    r"^\s*(?:struct\s|class\s|type\s|interface\s|enum\s|trait\s|impl\s)",
    re.IGNORECASE,
)


# --------------------------------------------------------------------------- #
# Assignment patterns (covers most config formats)
# --------------------------------------------------------------------------- #

# Each pattern has named groups: `keyword` and either `qvalue` (quoted) or `uvalue` (unquoted)
_ASSIGNMENT_PATTERNS: list[tuple[str, str]] = [
    # "key": "value"  (JSON / quoted dict)
    (
        r"""['"](?P<keyword>{kw})['"]"""
        r"""\s*:\s*(?P<quote>['"])(?P<qvalue>[^'"\n]{{1,200}})(?P=quote)""",
        "colon/json",
    ),
    # export KEY=value or export KEY="value"
    (
        r"""export\s+(?P<keyword>{kw})\s*=\s*(?:"""
        r"""(?P<quote>['"])(?P<qvalue>[^'"\n]{{1,200}})(?P=quote)"""
        r"""|(?P<uvalue>[^'"\s;#][^\s;#]{{0,200}}))""",
        "export",
    ),
    # key => value  (Ruby, PHP)
    (
        r"""['"]?(?P<keyword>{kw})['"]?\s*=>\s*(?:"""
        r"""(?P<quote>['"])(?P<qvalue>[^'"\n]{{1,200}})(?P=quote)"""
        r"""|(?P<uvalue>[^'"\s,;#][^\s,;#]{{0,200}}))""",
        "arrow",
    ),
    # key = "value"  |  key = 'value'  |  key = value
    (
        r"""(?:^|[\s._-])(?P<keyword>{kw})\s*[=:]\s*(?:"""
        r"""(?P<quote>['"])(?P<qvalue>[^'"\n]{{1,200}})(?P=quote)"""
        r"""|(?P<uvalue>[^'"\s,;#][^'"\n]{{0,200}}))""",
        "equals",
    ),
]


@dataclass(frozen=True, slots=True)
class KeywordMatch:
    """A keyword-assignment match."""

    keyword: str
    value: str
    line_number: int
    line_content: str
    assignment_type: str  # "equals", "colon/json", "export", "arrow"


class KeywordDetector:
    """Detect secrets via keyword-assignment pattern matching.

    Looks for lines like ``PASSWORD = 's3cret'`` and captures the value,
    filtering out common placeholder / false-positive values via :class:`ValueFilter`.
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
        self._value_filter = ValueFilter(min_length=min_value_length)

        # Build compiled patterns with the keyword alternation baked in
        kw_alt = "|".join(re.escape(k) for k in self.keywords)
        flags = 0 if case_sensitive else re.IGNORECASE
        self._patterns: list[tuple[re.Pattern[str], str]] = []
        for pat_str, label in _ASSIGNMENT_PATTERNS:
            compiled = re.compile(pat_str.format(kw=kw_alt), flags)
            self._patterns.append((compiled, label))

    # ------------------------------------------------------------------ #

    @staticmethod
    def _is_noise_line(line: str) -> bool:
        """Return *True* if the entire line is structural code, not config."""
        stripped = line.strip()
        if not stripped:
            return True

        # Comment-only lines
        if _COMMENT_RE.match(stripped):
            return True

        # Function / method signatures
        if _FUNC_SIGNATURE_RE.search(stripped):
            return True

        # Import / use / require lines
        if _IMPORT_RE.match(stripped):
            return True

        # Struct / class / type definitions
        return bool(_TYPE_DEF_RE.match(stripped))

    def _is_false_positive(self, value: str) -> bool:
        """Return *True* if the value is a known false-positive."""
        return not self._value_filter.is_valid_secret(value)

    # ------------------------------------------------------------------ #

    def scan_line(self, line: str, line_number: int = 0) -> list[KeywordMatch]:
        """Return all keyword-assignment matches found in *line*."""
        # Skip entire lines that are comments, function sigs, imports, etc.
        if self._is_noise_line(line):
            return []

        matches: list[KeywordMatch] = []
        seen_in_line: set[tuple[str, str]] = set()

        for pattern, assign_type in self._patterns:
            for m in pattern.finditer(line):
                keyword = m.group("keyword")
                groups = m.groupdict()
                qval = groups.get("qvalue")
                if qval is not None:
                    # Quoted value: preserve '//' and '#' inside quotes (e.g. database URLs)
                    value = qval.strip()
                else:
                    # Unquoted value: strip inline comments (# or //) and trailing punctuation
                    raw_val = (groups.get("uvalue") or "").strip()
                    raw_val = raw_val.split("#")[0].split("//")[0]
                    value = raw_val.strip().rstrip("'\"`,;")

                if self._is_false_positive(value):
                    continue

                dedup_key = (keyword.lower(), value)
                if dedup_key in seen_in_line:
                    continue
                seen_in_line.add(dedup_key)

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
