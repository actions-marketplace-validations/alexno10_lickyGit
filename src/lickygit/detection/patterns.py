"""Regex-based pattern matching engine."""

from __future__ import annotations

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
        """Return all :class:`PatternMatch` es found in *line*."""
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
    # Multi-line content scan
    # ------------------------------------------------------------------ #

    def scan_content(self, content: str) -> list[PatternMatch]:
        """Scan every line of *content* and return all matches."""
        all_matches: list[PatternMatch] = []
        for line_no, line in enumerate(content.splitlines(), start=1):
            all_matches.extend(self.scan_line(line, line_number=line_no))
        return all_matches
