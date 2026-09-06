"""Baseline management for ignoring known findings in CI/CD."""

from __future__ import annotations

import datetime
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from lickygit.core.finding import Finding


class Baseline:
    """Track known findings to suppress them during incremental CI/CD scans.

    Findings are matched by their unique, stable SHA-256 fingerprint
    (combination of rule_id, file_path, and matched_text).
    """

    def __init__(self, fingerprints: set[str] | None = None) -> None:
        self.fingerprints: set[str] = fingerprints or set()

    # ------------------------------------------------------------------ #
    # File I/O
    # ------------------------------------------------------------------ #

    @classmethod
    def load_from_file(cls, path: str | Path) -> Baseline:
        """Load a baseline JSON file and return a :class:`Baseline` instance."""
        p = Path(path)
        if not p.is_file():
            return cls()

        try:
            data: dict[str, Any] = json.loads(p.read_text(encoding="utf-8"))
            fps: set[str] = set()
            for item in data.get("findings", []):
                if isinstance(item, dict) and "fingerprint" in item:
                    fps.add(item["fingerprint"])
                elif isinstance(item, str):
                    fps.add(item)
            return cls(fps)
        except Exception:
            return cls()

    @classmethod
    def generate(cls, findings: list[Finding], path: str | Path) -> Baseline:
        """Generate a baseline JSON file from a list of findings and save it."""
        p = Path(path)
        fingerprints: set[str] = set()
        serialized_findings: list[dict[str, Any]] = []

        for f in findings:
            fp = f.fingerprint
            if fp not in fingerprints:
                fingerprints.add(fp)
                serialized_findings.append({
                    "fingerprint": fp,
                    "rule_id": f.rule_id,
                    "rule_name": f.rule_name,
                    "file_path": f.file_path,
                    "severity": f.severity.value,
                    "redacted_value": f.redacted_value,
                    "commit_sha": f.commit_sha[:8],
                })

        payload: dict[str, Any] = {
            "version": "1.0.0",
            "generator": "lickyGit",
            "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "total_findings": len(serialized_findings),
            "findings": serialized_findings,
        }

        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        return cls(fingerprints)

    # ------------------------------------------------------------------ #
    # Filtering
    # ------------------------------------------------------------------ #

    def is_suppressed(self, finding: Finding) -> bool:
        """Return *True* if *finding* is already recorded in the baseline."""
        return finding.fingerprint in self.fingerprints

    def filter_findings(self, findings: list[Finding]) -> tuple[list[Finding], int]:
        """Filter out baseline findings.

        Returns a tuple of ``(new_findings, suppressed_count)``.
        """
        if not self.fingerprints:
            return findings, 0

        new_findings: list[Finding] = []
        suppressed_count = 0
        for f in findings:
            if self.is_suppressed(f):
                suppressed_count += 1
            else:
                new_findings.append(f)

        return new_findings, suppressed_count
