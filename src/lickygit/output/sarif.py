"""SARIF 2.1.0 output for GitHub Code Scanning and IDE integration."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

from lickygit import __version__
from lickygit.core.finding import Severity

if TYPE_CHECKING:
    from lickygit.core.scanner import ScanResult

_SEVERITY_TO_SARIF: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}

_SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/"
    "sarif-2.1/schema/sarif-schema-2.1.0.json"
)


class SarifFormatter:
    """Produce `SARIF 2.1.0 <https://sarifweb.azurewebsites.net/>`_ JSON."""

    def format(self, result: ScanResult) -> str:
        """Return a SARIF JSON string."""
        # Collect unique rules with O(1) index lookup
        rules_seen: dict[str, dict[str, object]] = {}
        rule_to_index: dict[str, int] = {}
        sarif_results: list[dict[str, object]] = []

        for f in result.findings:
            if f.rule_id not in rule_to_index:
                rule_to_index[f.rule_id] = len(rule_to_index)
                rules_seen[f.rule_id] = {
                    "id": f.rule_id,
                    "name": f.rule_name,
                    "shortDescription": {"text": f.rule_name},
                }

            rule_index = rule_to_index[f.rule_id]

            # SARIF spec requires forward-slash URIs
            uri = f.file_path.replace("\\", "/")

            phys_loc: dict[str, object] = {
                "artifactLocation": {"uri": uri},
            }
            if f.line_number is not None:
                phys_loc["region"] = {"startLine": f.line_number}

            location: dict[str, object] = {"physicalLocation": phys_loc}

            sarif_results.append(
                {
                    "ruleId": f.rule_id,
                    "ruleIndex": rule_index,
                    "level": _SEVERITY_TO_SARIF.get(f.severity, "note"),
                    "message": {
                        "text": f"Potential secret detected: {f.rule_name} ({f.redacted_value})"
                    },
                    "locations": [location],
                    "properties": {
                        "commitSha": f.commit_sha or "",
                        "commitAuthor": f.commit_author,
                        "detectionType": f.detection_type.value,
                    },
                }
            )

        sarif: dict[str, object] = {
            "$schema": _SARIF_SCHEMA,
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "lickyGit",
                            "version": __version__,
                            "informationUri": "https://github.com/alexno10/lickyGit",
                            "rules": list(rules_seen.values()),
                        }
                    },
                    "results": sarif_results,
                }
            ],
        }

        return json.dumps(sarif, indent=2, ensure_ascii=False)

    def write(self, result: ScanResult, path: str | Path) -> None:
        """Write SARIF output to a file."""
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(self.format(result), encoding="utf-8")
