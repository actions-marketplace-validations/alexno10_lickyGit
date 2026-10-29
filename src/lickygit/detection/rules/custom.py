"""Load custom detection rules from TOML or YAML files."""

from __future__ import annotations

import re
import warnings
from pathlib import Path

from lickygit.config import _load_toml
from lickygit.core.finding import Severity
from lickygit.detection.patterns import PatternRule


def _parse_severity(value: str) -> Severity:
    """Parse a severity string into a :class:`Severity` enum member."""
    try:
        return Severity[value.upper()]
    except KeyError:
        valid = ", ".join(s.name for s in Severity)
        raise ValueError(f"Invalid severity '{value}'. Expected one of: {valid}") from None


def _rules_from_dicts(raw_rules: list[dict[str, str]]) -> list[PatternRule]:
    """Convert a list of plain dicts into :class:`PatternRule` instances."""
    rules: list[PatternRule] = []
    for entry in raw_rules:
        rule_id = entry.get("id", "")
        name = entry.get("name", rule_id)
        pattern_str = entry.get("pattern", "")
        severity_str = entry.get("severity", "MEDIUM")
        description = entry.get("description", "")

        if not rule_id or not pattern_str:
            continue  # skip incomplete entries

        try:
            compiled = re.compile(pattern_str)
        except re.error as exc:
            warnings.warn(
                f"Skipping rule '{rule_id}': invalid regex: {exc}",
                stacklevel=2,
            )
            continue

        try:
            severity = _parse_severity(severity_str)
        except ValueError as exc:
            warnings.warn(
                f"Skipping rule '{rule_id}': {exc}",
                stacklevel=2,
            )
            continue

        rules.append(
            PatternRule(
                id=rule_id,
                name=name,
                pattern=compiled,
                severity=severity,
                description=description,
            )
        )
    return rules


# ---------------------------------------------------------------------- #
# TOML loader
# ---------------------------------------------------------------------- #


def load_rules_from_toml(path: str | Path) -> list[PatternRule]:
    """Load custom rules from a TOML file.

    Expected format::

        [[rules]]
        id = "my-rule"
        name = "My Custom Secret"
        pattern = "CUSTOM_[A-Z0-9]{32}"
        severity = "HIGH"
        description = "A custom secret pattern."
    """
    filepath = Path(path)
    if not filepath.is_file():
        raise FileNotFoundError(f"Rules file not found: {filepath}")

    data = _load_toml(filepath)
    raw_rules: list[dict[str, str]] = data.get("rules", [])
    return _rules_from_dicts(raw_rules)


# ---------------------------------------------------------------------- #
# YAML loader (optional dependency)
# ---------------------------------------------------------------------- #


def load_rules_from_yaml(path: str | Path) -> list[PatternRule]:
    """Load custom rules from a YAML file.

    Expected format::

        rules:
          - id: my-rule
            name: My Custom Secret
            pattern: "CUSTOM_[A-Z0-9]{32}"
            severity: HIGH
            description: A custom secret pattern.

    Requires ``pyyaml`` to be installed.
    """
    try:
        import yaml  # type: ignore[import-untyped]
    except ImportError as exc:
        raise ImportError(
            "PyYAML is required for YAML rules: pip install lickygit[yaml]"
        ) from exc

    filepath = Path(path)
    if not filepath.is_file():
        raise FileNotFoundError(f"Rules file not found: {filepath}")

    with open(filepath, encoding="utf-8") as fh:
        data = yaml.safe_load(fh)

    raw_rules: list[dict[str, str]] = data.get("rules", []) if data else []
    return _rules_from_dicts(raw_rules)
