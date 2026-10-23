"""Unit tests for PathFilter, AllowList, ValueFilter, and Baseline."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from lickygit.core.finding import DetectionType, Finding, Severity
from lickygit.filters.allowlist import AllowList
from lickygit.filters.baseline import Baseline
from lickygit.filters.path_filter import PathFilter
from lickygit.filters.value_filter import ValueFilter

if TYPE_CHECKING:
    from pathlib import Path


def _make_finding(
    matched_text: str = "AKIA1234567890ABCDEF",
    file_path: str = "src/config.py",
    line_number: int = 10,
) -> Finding:
    return Finding(
        rule_id="test-rule",
        rule_name="Test Rule",
        severity=Severity.HIGH,
        file_path=file_path,
        line_number=line_number,
        line_content=f"key = {matched_text}",
        matched_text=matched_text,
        commit_sha="1234567890abcdef",
        detection_type=DetectionType.PATTERN,
    )


class TestPathFilter:
    """Verify glob-based path exclusion and inclusion precedence."""

    def test_default_excludes(self) -> None:
        pf = PathFilter()
        assert not pf.should_scan("package-lock.json")
        assert not pf.should_scan("frontend/yarn.lock")
        assert not pf.should_scan("node_modules/pkg/index.js")
        assert not pf.should_scan("assets/logo.png")
        assert not pf.should_scan("config/.env.example")
        assert pf.should_scan("src/main.py")

    def test_include_overrides_exclude(self) -> None:
        pf = PathFilter(include_patterns=["*.lock"])
        assert pf.should_scan("poetry.lock")


class TestAllowList:
    """Verify allowlist exact, regex, scoped matching, and invalid regex safety."""

    def test_allowlist_file_loading_and_matching(self, tmp_path: Path) -> None:
        allow_file = tmp_path / ".lickygit-allow"
        allow_file.write_text(
            """
# Comment line
ALLOWED_EXACT_TOKEN # safe test token
regex:TEST_KEY_[0-9]{4}   # regex entry
scope:test_*.py SCOPED_SECRET_VALUE
regex:[invalid_regex_should_be_skipped
regex:
""",
            encoding="utf-8",
        )

        with pytest.warns(UserWarning, match="Invalid regex"):
            allow = AllowList.load_from_file(allow_file)

        assert allow.is_allowed(_make_finding("ALLOWED_EXACT_TOKEN"))
        assert allow.is_allowed(_make_finding("prefix_TEST_KEY_1234_suffix"))
        # Basename matching for scope:test_*.py on nested path
        assert allow.is_allowed(
            _make_finding("SCOPED_SECRET_VALUE", file_path="tests/unit/test_auth.py")
        )
        assert not allow.is_allowed(
            _make_finding("SCOPED_SECRET_VALUE", file_path="src/prod_auth.py")
        )
        # Unrelated secret must NOT be suppressed by invalid/empty regex lines
        assert not allow.is_allowed(_make_finding("REAL_PRODUCTION_SECRET_999"))


class TestValueFilter:
    """Verify value-level heuristics."""

    def test_url_with_credentials_is_valid_secret(self) -> None:
        vf = ValueFilter()
        assert not vf.is_valid_secret("https://example.com/api/v1")
        assert vf.is_valid_secret("https://user:s3cr3tPass@example.com/api")


class TestBaseline:
    """Verify baseline generation, loading, and suppression."""

    def test_baseline_roundtrip_and_filtering(self, tmp_path: Path) -> None:
        f1 = _make_finding("SECRET_ONE", file_path="a.py")
        f2 = _make_finding("SECRET_TWO", file_path="b.py")

        baseline_path = tmp_path / ".lickygit-baseline.json"
        Baseline.generate([f1], baseline_path)

        loaded = Baseline.load_from_file(baseline_path)
        remaining, suppressed = loaded.filter_findings([f1, f2])
        assert suppressed == 1
        assert remaining == [f2]

    def test_corrupted_baseline_warns_and_returns_empty(self, tmp_path: Path) -> None:
        bad_path = tmp_path / "corrupt.json"
        bad_path.write_text("{not valid json", encoding="utf-8")
        with pytest.warns(UserWarning, match="Failed to parse baseline"):
            b = Baseline.load_from_file(bad_path)
        assert len(b.fingerprints) == 0
