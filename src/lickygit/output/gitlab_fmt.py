"""GitLab Code Quality Report formatter."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from lickygit.core.scanner import ScanResult

_SEVERITY_TO_GITLAB: dict[str, str] = {
    "CRITICAL": "blocker",
    "HIGH": "critical",
    "MEDIUM": "major",
    "LOW": "minor",
}


class GitlabCodeQualityFormatter:
    """Produce a `GitLab Code Quality Report
    <https://docs.gitlab.com/ee/ci/testing/code_quality.html>`_ JSON array.

    This format integrates directly with GitLab merge request widgets and
    pipeline reports.
    """

    def format(self, result: ScanResult) -> str:
        """Return a Code Quality JSON string."""
        issues: list[dict[str, object]] = []

        for f in result.findings:
            issues.append(
                {
                    "type": "issue",
                    "check_name": f.rule_id,
                    "description": f"Secret detected: {f.rule_name} ({f.redacted_value})",
                    "severity": _SEVERITY_TO_GITLAB.get(f.severity.value, "minor"),
                    "fingerprint": f.fingerprint,
                    "categories": ["Security"],
                    "location": {
                        "path": f.file_path.replace("\\", "/"),
                        "lines": {
                            "begin": f.line_number or 1,
                        },
                    },
                }
            )

        return json.dumps(issues, indent=2, ensure_ascii=False)

    def write(self, result: ScanResult, path: str | Path) -> None:
        """Write Code Quality report to a file."""
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(self.format(result), encoding="utf-8")
