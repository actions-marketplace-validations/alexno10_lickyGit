"""Detection engine — orchestrates pattern, keyword, and entropy detectors."""

from __future__ import annotations

from lickygit.core.finding import DetectionType, Finding, Severity
from lickygit.detection.entropy import find_high_entropy_strings
from lickygit.detection.keywords import KeywordDetector
from lickygit.detection.patterns import PatternMatch, PatternMatcher
from lickygit.detection.rules.builtin import get_builtin_rules
from lickygit.detection.patterns import PatternRule


class DetectionEngine:
    """Unified facade that runs all configured detectors on file content.

    Internally manages a :class:`PatternMatcher`, a :class:`KeywordDetector`,
    and the entropy scanner, then merges and deduplicates results into a
    flat list of :class:`Finding` objects.
    """

    def __init__(
        self,
        *,
        use_builtin_rules: bool = True,
        custom_rules: list[PatternRule] | None = None,
        use_entropy: bool = True,
        use_keywords: bool = True,
        entropy_threshold: float = 4.5,
        keyword_config: dict[str, object] | None = None,
    ) -> None:
        # ── pattern matcher ────────────────────────────────────────────
        rules: list[PatternRule] = []
        if use_builtin_rules:
            rules.extend(get_builtin_rules())
        if custom_rules:
            rules.extend(custom_rules)
        self._pattern_matcher = PatternMatcher(rules) if rules else None

        # ── keyword detector ───────────────────────────────────────────
        self._keyword_detector: KeywordDetector | None = None
        if use_keywords:
            kw_kwargs = dict(keyword_config) if keyword_config else {}
            self._keyword_detector = KeywordDetector(**kw_kwargs)  # type: ignore[arg-type]

        # ── entropy settings ───────────────────────────────────────────
        self._use_entropy = use_entropy
        self._entropy_threshold = entropy_threshold

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def scan_content(
        self,
        content: str,
        file_path: str,
        commit_sha: str = "",
        commit_author: str = "",
        commit_date: str = "",
    ) -> list[Finding]:
        """Run all enabled detectors and return a deduplicated list of findings."""
        findings: list[Finding] = []
        seen: set[tuple[str, int | None, str]] = set()

        # ── 1. Pattern matching ────────────────────────────────────────
        if self._pattern_matcher:
            for pm in self._pattern_matcher.scan_content(content):
                key = (file_path, pm.line_number, pm.matched_text)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(self._pattern_match_to_finding(
                    pm, file_path, commit_sha, commit_author, commit_date,
                ))

        # ── 2. Keyword detection ───────────────────────────────────────
        if self._keyword_detector:
            for km in self._keyword_detector.scan_content(content):
                key = (file_path, km.line_number, km.value)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    Finding(
                        rule_id=f"keyword-{km.keyword.lower()}",
                        rule_name=f"Keyword: {km.keyword}",
                        severity=Severity.MEDIUM,
                        file_path=file_path,
                        line_number=km.line_number,
                        line_content=km.line_content,
                        matched_text=km.value,
                        commit_sha=commit_sha,
                        commit_author=commit_author,
                        commit_date=commit_date,
                        detection_type=DetectionType.KEYWORD,
                    )
                )

        # ── 3. Entropy detection ───────────────────────────────────────
        if self._use_entropy:
            lines = content.splitlines()
            for em in find_high_entropy_strings(
                content,
                base64_threshold=self._entropy_threshold,
            ):
                key = (file_path, None, em.text)
                if key in seen:
                    continue
                seen.add(key)

                # Find which line the match falls in
                line_no = content[:em.start_pos].count("\n") + 1
                line_content = lines[line_no - 1] if line_no <= len(lines) else ""

                findings.append(
                    Finding(
                        rule_id=f"entropy-{em.encoding}",
                        rule_name=f"High-Entropy {em.encoding.title()} String",
                        severity=Severity.LOW,
                        file_path=file_path,
                        line_number=line_no,
                        line_content=line_content,
                        matched_text=em.text,
                        commit_sha=commit_sha,
                        commit_author=commit_author,
                        commit_date=commit_date,
                        entropy=em.entropy,
                        detection_type=DetectionType.ENTROPY,
                    )
                )

        return findings

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _pattern_match_to_finding(
        pm: PatternMatch,
        file_path: str,
        commit_sha: str,
        commit_author: str,
        commit_date: str,
    ) -> Finding:
        return Finding(
            rule_id=pm.rule.id,
            rule_name=pm.rule.name,
            severity=pm.rule.severity,
            file_path=file_path,
            line_number=pm.line_number,
            line_content=pm.line_content,
            matched_text=pm.matched_text,
            commit_sha=commit_sha,
            commit_author=commit_author,
            commit_date=commit_date,
            detection_type=DetectionType.PATTERN,
        )
