"""Regex-based pattern matching engine."""

from __future__ import annotations

import bisect
import re
from dataclasses import dataclass

from lickygit.core.finding import Severity


@dataclass(frozen=True, slots=True)
class PatternRule:
    """A compiled regex rule for detecting a specific secret type."""

    id: str
    name: str
    pattern: re.Pattern[str]
    severity: Severity
    description: str = ""

    def __hash__(self) -> int:
        return hash(self.id)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, PatternRule):
            return NotImplemented
        return self.id == other.id


@dataclass(frozen=True, slots=True)
class PatternMatch:
    """A single match produced by :class:`PatternMatcher`."""

    rule: PatternRule
    matched_text: str
    line_number: int
    line_content: str
    start_pos: int
    end_pos: int


class PatternMatcher:
    """Run a set of :class:`PatternRule` rules against text content."""

    def __init__(self, rules: list[PatternRule]) -> None:
        self.rules = rules

    # ------------------------------------------------------------------ #
    # Single-line scan
    # ------------------------------------------------------------------ #

    def scan_line(self, line: str, line_number: int = 0) -> list[PatternMatch]:
        """Return all :class:`PatternMatch`es found in a single *line*."""
        matches: list[PatternMatch] = []
        for rule in self.rules:
            for m in rule.pattern.finditer(line):
                matches.append(
                    PatternMatch(
                        rule=rule,
                        matched_text=m.group(),
                        line_number=line_number,
                        line_content=line,
                        start_pos=m.start(),
                        end_pos=m.end(),
                    )
                )
        return matches

    # ------------------------------------------------------------------ #
    # Multi-line content scan (high-performance)
    # ------------------------------------------------------------------ #

    def scan_content(self, content: str) -> list[PatternMatch]:
        """Scan *content* across all rules efficiently in C-speed finditer passes.

        Avoids splitting lines into Python strings up front and avoids repeating
        N rules for M lines. Line positions are computed lazily only when matches occur.
        """
        if not content or not self.rules:
            return []

        all_matches: list[PatternMatch] = []
        line_starts: list[int] | None = None

        for rule in self.rules:
            for m in rule.pattern.finditer(content):
                # Lazily index line start offsets only if a match is detected
                if line_starts is None:
                    line_starts = [0]
                    for nl in re.finditer(r"\n", content):
                        line_starts.append(nl.end())

                start_pos = m.start()
                end_pos = m.end()

                # Binary search to find the exact 1-indexed line number in O(log N)
                line_idx = bisect.bisect_right(line_starts, start_pos) - 1
                line_no = line_idx + 1

                # Extract line content without splitting the whole file
                l_start = line_starts[line_idx]
                l_end = (
                    line_starts[line_idx + 1] - 1
                    if line_idx + 1 < len(line_starts)
                    else len(content)
                )
                line_content = content[l_start:l_end].rstrip("\r\n")

                all_matches.append(
                    PatternMatch(
                        rule=rule,
                        matched_text=m.group(),
                        line_number=line_no,
                        line_content=line_content,
                        start_pos=start_pos,
                        end_pos=end_pos,
                    )
                )

        return all_matches
