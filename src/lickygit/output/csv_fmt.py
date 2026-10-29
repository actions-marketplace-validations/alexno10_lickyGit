"""CSV output formatter."""

from __future__ import annotations

import csv
import io
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from lickygit.core.scanner import ScanResult

_COLUMNS = [
    "rule_id",
    "rule_name",
    "severity",
    "file_path",
    "line_number",
    "matched_text",
    "commit_sha",
    "commit_author",
    "commit_date",
    "detection_type",
]

_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _sanitize_csv_cell(val: object) -> object:
    """Prevent CSV formula injection in spreadsheet software."""
    if isinstance(val, str) and val.startswith(_FORMULA_PREFIXES):
        return f"'{val}"
    return val


class CsvFormatter:
    """Serialize scan results as CSV."""

    def __init__(self, *, redact: bool = False) -> None:
        self.redact = redact

    def format(self, result: ScanResult) -> str:
        """Return a CSV string."""
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        for f in result.findings:
            row = f.to_dict(redact=self.redact)
            writer.writerow({k: _sanitize_csv_cell(row.get(k, "")) for k in _COLUMNS})
        return buf.getvalue()

    def write(self, result: ScanResult, path: str | Path) -> None:
        """Write CSV output to a file."""
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(self.format(result), encoding="utf-8", newline="")
