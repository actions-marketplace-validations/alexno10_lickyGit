"""Unit tests for detection rules, keyword detector, entropy, and DetectionEngine."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from lickygit.core.finding import DetectionType, Severity
from lickygit.detection.engine import DetectionEngine
from lickygit.detection.entropy import (
    calculate_base64_entropy,
    calculate_hex_entropy,
    calculate_shannon_entropy,
    find_high_entropy_strings,
)
from lickygit.detection.keywords import KeywordDetector
from lickygit.detection.patterns import PatternMatcher
from lickygit.detection.rules.builtin import get_builtin_rules
from lickygit.detection.rules.custom import load_rules_from_toml

if TYPE_CHECKING:
    from pathlib import Path


def _tok(prefix: str, body: str) -> str:
    """Build test secret tokens dynamically so static self-scans stay clean."""
    return prefix + body


class TestBuiltinRules:
    """Verify built-in regex rules including newly added provider patterns."""

    def test_builtin_rules_detect_cloud_and_ai_tokens(self) -> None:
        matcher = PatternMatcher(get_builtin_rules())

        samples = {
            "aws-access-key-id": _tok("AKIA", "IOSFODNN7EXAMPLE"),
            "aws-session-token": _tok("ASIA", "IOSFODNN7EXAMPLE"),
            "github-pat-classic": _tok("ghp_", "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8"),
            "openai-api-key": _tok("sk-proj-", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4"),
            "anthropic-api-key": _tok("sk-ant-api03-", "A" * 82),
            "huggingface-token": _tok("hf_", "aBcDeFgHiJkLmNoPqRsTuVwXyZ01234567"),
            "digitalocean-token": _tok("dop_v1_", "a1b2c3d4" * 8),
            "hashicorp-vault-token": _tok("hvs.", "CAESIJ1234567890abcdefghijklmnop"),
            "databricks-pat": _tok("dapi", "0123456789abcdef" * 2),
            "postman-api-key": _tok("PMAK-", "0123456789abcdef01234567-" + "a" * 34),
            "private-key": _tok("-----BEGIN ENCRYPTED ", "PRIVATE KEY-----"),
            "jwt-token": _tok(
                "eyJhbGciOiJIUzI1NiJ9.",
                "eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
            ),
            "discord-bot-token": _tok("OTk5OTk5OTk5OTk5OTk5OTk5OTk5OQ.", "G1a2B3." + "x" * 28),
        }

        for expected_rule_id, token in samples.items():
            matches = matcher.scan_content(f'const secret = "{token}";\n')
            matched_ids = {m.rule.id for m in matches}
            assert expected_rule_id in matched_ids, f"Failed to detect {expected_rule_id}"

    def test_jwt_rejects_short_false_positive(self) -> None:
        matcher = PatternMatcher(get_builtin_rules())
        assert matcher.scan_content("eyJ.eyJ.a") == []


class TestKeywordDetector:
    """Verify keyword assignment detection and false-positive heuristics."""

    def test_database_url_preserves_double_slash_and_hash(self) -> None:
        kd = KeywordDetector()
        url = _tok("postgres://admin:", "S3cr3t#Pass@db.internal:5432/prod")
        matches = kd.scan_line(f'database_url = "{url}"', line_number=5)
        assert len(matches) == 1
        assert matches[0].keyword == "database_url"
        assert matches[0].value == url

    def test_unquoted_value_strips_inline_comment(self) -> None:
        kd = KeywordDetector()
        val = _tok("prod_live_", "s3cr3t_98765")
        matches = kd.scan_line(f"api_key = {val} # inline comment", line_number=1)
        assert len(matches) == 1
        assert matches[0].value == val

    def test_export_line_not_duplicated(self) -> None:
        kd = KeywordDetector()
        val = _tok("super_secret_", "val_999")
        matches = kd.scan_line(f'export PASSWORD="{val}"', line_number=2)
        assert len(matches) == 1
        assert matches[0].value == val

    def test_false_positives_ignored(self) -> None:
        kd = KeywordDetector()
        noise_lines = [
            "# password = 'secret_in_comment'",
            "def validate_password(password: str) -> bool:",
            'password = "changeme"',
            "api_key = os.getenv('API_KEY')",
            'token = "https://github.com/alexno10/lickyGit"',
            "password = 1000:1000",
            'secret = "this is a normal documentation sentence"',
        ]
        for line in noise_lines:
            assert kd.scan_line(line) == [], f"Unexpected match on: {line}"


class TestEntropyAndEngine:
    """Verify Shannon entropy calculation, overlap deduplication, and DetectionEngine."""

    def test_entropy_calculations(self) -> None:
        assert calculate_shannon_entropy("") == 0.0
        assert calculate_shannon_entropy("aaaaaaaa") == 0.0
        assert calculate_hex_entropy("0123456789abcdef") == pytest.approx(4.0)
        assert calculate_base64_entropy("ABCDEFGHIJKLMNOP") == pytest.approx(4.0)

    def test_url_on_previous_line_does_not_suppress_secret(self) -> None:
        token = _tok("a1b2c3d4", "e5f60718293a4b5c")
        content = f"# See https://example.com/docs\nkey = {token}\n"
        matches = find_high_entropy_strings(content)
        assert any(m.text == token for m in matches)

    def test_engine_deduplicates_and_tracks_line_numbers(self) -> None:
        engine = DetectionEngine()
        tok1 = _tok("9f8e7d6c", "5b4a3f2e1d0c9b8a")
        tok2 = _tok("1a2b3c4d", "5e6f708192a3b4c5")
        content = f"first = {tok1}\nsecond = {tok1}\nthird = {tok2}\n"
        findings = engine.scan_content(content, file_path="app.py")
        lines_for_tok1 = [
            f.line_number for f in findings if f.matched_text == tok1
        ]
        assert lines_for_tok1 == [1, 2]

    def test_inline_ignore_comments_suppress_findings(self) -> None:
        engine = DetectionEngine()
        aws_key = _tok("AKIA", "IOSFODNN7EXAMPLE")
        content = (
            f'KEY1 = "{aws_key}"  # lickygit:ignore\n'
            f'KEY2 = "{aws_key}"  // pragma: allowlist secret\n'
        )
        assert engine.scan_content(content, file_path="config.py") == []


class TestCustomRules:
    """Verify TOML custom rules loading and validation warnings."""

    def test_load_custom_rules_from_toml(self, tmp_path: Path) -> None:
        rules_file = tmp_path / "rules.toml"
        rules_file.write_text(
            """
[[rules]]
id = "custom-token"
name = "Custom Token"
pattern = "CUST_[0-9]{8}"
severity = "HIGH"

[[rules]]
id = "bad-regex"
pattern = "[unclosed"
severity = "LOW"

[[rules]]
id = "bad-severity"
pattern = "FOO_[0-9]+"
severity = "UNKNOWN_SEV"
""",
            encoding="utf-8",
        )

        with pytest.warns(UserWarning):
            rules = load_rules_from_toml(rules_file)

        assert len(rules) == 1
        assert rules[0].id == "custom-token"
        assert rules[0].severity == Severity.HIGH
        matcher = PatternMatcher(rules)
        matches = matcher.scan_content("val = CUST_12345678")
        assert len(matches) == 1
        assert matches[0].rule.id == "custom-token"
        assert DetectionType.PATTERN.value == "PATTERN"
