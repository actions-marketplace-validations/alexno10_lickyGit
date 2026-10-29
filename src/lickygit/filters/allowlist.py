"""Allowlist manager for suppressing known false-positive findings."""

from __future__ import annotations

import re
import warnings
from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from lickygit.core.finding import Finding


@dataclass(frozen=True, slots=True)
class AllowListEntry:
    """A single allowlist rule."""

    pattern: str  # exact substring or regex
    reason: str = ""
    scope: str | None = None  # optional file path glob
    is_regex: bool = False


class AllowList:
    """Manage a list of patterns that suppress matching findings.

    Entries can match against the ``matched_text`` of a finding (exact
    substring or regex) and optionally be scoped to specific file paths.
    """

    def __init__(self, entries: list[AllowListEntry] | None = None) -> None:
        self._entries: list[AllowListEntry] = []
        self._compiled: list[tuple[AllowListEntry, re.Pattern[str] | None]] = []
        if entries:
            for entry in entries:
                self.add(entry)

    @staticmethod
    def _prepare(
        entry: AllowListEntry,
    ) -> tuple[AllowListEntry, re.Pattern[str] | None] | None:
        if not entry.pattern:
            return None
        if entry.is_regex:
            try:
                return entry, re.compile(entry.pattern)
            except re.error:
                warnings.warn(
                    f"Invalid regex in allowlist, skipping: '{entry.pattern}'",
                    stacklevel=2,
                )
                return None
        return entry, None

    # ------------------------------------------------------------------ #
    # File loading
    # ------------------------------------------------------------------ #

    @classmethod
    def load_from_file(cls, path: str | Path) -> AllowList:
        """Load from a ``.lickygit-allow`` text file.

        Format (one entry per line)::

            # comment lines start with #
            exact-text-to-allow  # optional reason
            regex:AKIA[A-Z]{16}  # reason, uses regex
            scope:*.test.js exact-text  # scoped to test files

        Blank lines and ``#``-only lines are skipped.
        """
        filepath = Path(path)
        if not filepath.is_file():
            return cls()

        entries: list[AllowListEntry] = []
        for raw_line in filepath.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            reason = ""
            if " #" in line or "\t#" in line:
                line, reason = re.split(r"\s+#", line, maxsplit=1)
                line = line.strip()
                reason = reason.strip()

            is_regex = False
            scope: str | None = None

            # Handle scope: prefix
            if line.startswith("scope:"):
                rest = line[len("scope:") :]
                parts = rest.split(None, 1)
                if len(parts) == 2:
                    scope, line = parts[0], parts[1].strip()
                else:
                    continue  # malformed

            # Handle regex: prefix
            if line.startswith("regex:"):
                line = line[len("regex:") :].strip()
                is_regex = True

            if not line:
                continue

            entries.append(
                AllowListEntry(
                    pattern=line,
                    reason=reason,
                    scope=scope,
                    is_regex=is_regex,
                )
            )

        return cls(entries)

    # ------------------------------------------------------------------ #
    # Check
    # ------------------------------------------------------------------ #

    def is_allowed(self, finding: Finding) -> bool:
        """Return *True* if the finding matches any allowlist entry."""
        file_path = finding.file_path.replace("\\", "/")
        name = file_path.rsplit("/", 1)[-1]
        for entry, compiled_re in self._compiled:
            # Scope check (matches either full normalized path or basename)
            if entry.scope and not (
                fnmatch(file_path, entry.scope) or fnmatch(name, entry.scope)
            ):
                continue

            # Match check
            if compiled_re is not None:
                if compiled_re.search(finding.matched_text):
                    return True
            elif entry.pattern in finding.matched_text:
                return True

        return False

    # ------------------------------------------------------------------ #
    # Mutation
    # ------------------------------------------------------------------ #

    def add(self, entry: AllowListEntry) -> None:
        """Add a new entry to the allowlist."""
        prepared = self._prepare(entry)
        if prepared is not None:
            self._entries.append(entry)
            self._compiled.append(prepared)

    def __len__(self) -> int:
        return len(self._entries)
