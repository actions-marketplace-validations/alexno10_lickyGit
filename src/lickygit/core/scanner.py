"""Main scanner orchestrator — ties Git walking, detection, and filtering together."""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path

from lickygit.core.finding import Finding, Severity
from lickygit.core.git_walker import GitWalker
from lickygit.detection.engine import DetectionEngine
from lickygit.filters.allowlist import AllowList
from lickygit.filters.path_filter import PathFilter


@dataclass
class ScanConfig:
    """Configuration for a scan run."""

    repo_path: str = "."
    head_only: bool = False
    max_workers: int = 4
    exclude_paths: list[str] = field(default_factory=list)
    include_paths: list[str] = field(default_factory=list)
    min_severity: Severity = Severity.LOW


@dataclass
class ScanResult:
    """The outcome of a complete scan."""

    findings: list[Finding] = field(default_factory=list)
    scan_duration: float = 0.0
    total_commits: int = 0
    total_files: int = 0

    @property
    def counts_by_severity(self) -> dict[str, int]:
        """Finding counts grouped by severity."""
        counts: dict[str, int] = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    @property
    def has_findings(self) -> bool:
        return len(self.findings) > 0


class Scanner:
    """Orchestrate a full Git secret scan.

    Walks every revision (or HEAD only) through :class:`GitWalker`,
    detects secrets via :class:`DetectionEngine`, filters with
    :class:`PathFilter` and :class:`AllowList`, and returns a
    :class:`ScanResult`.
    """

    def __init__(
        self,
        config: ScanConfig,
        engine: DetectionEngine | None = None,
        allowlist: AllowList | None = None,
        path_filter: PathFilter | None = None,
    ) -> None:
        self.config = config
        self.engine = engine or DetectionEngine()
        self.allowlist = allowlist or AllowList()
        self.path_filter = path_filter or PathFilter(
            exclude_patterns=config.exclude_paths or None,
            include_patterns=config.include_paths or None,
        )

    # ------------------------------------------------------------------ #

    def scan(self) -> ScanResult:
        """Execute the scan and return results."""
        t0 = time.perf_counter()

        walker = GitWalker(self.config.repo_path, head_only=self.config.head_only)
        revisions = walker.get_revisions()

        all_findings: list[Finding] = []
        total_files = 0

        if self.config.max_workers <= 1:
            # Sequential
            for sha in revisions:
                findings, n_files = self._scan_revision(walker, sha)
                all_findings.extend(findings)
                total_files += n_files
        else:
            # Parallel (isolated GitWalker instance per thread)
            def _worker_scan(sha: str) -> tuple[list[Finding], int]:
                local_walker = GitWalker(self.config.repo_path, head_only=self.config.head_only)
                return self._scan_revision(local_walker, sha)

            with ThreadPoolExecutor(max_workers=self.config.max_workers) as pool:
                futures = {
                    pool.submit(_worker_scan, sha): sha
                    for sha in revisions
                }
                for future in as_completed(futures):
                    findings, n_files = future.result()
                    all_findings.extend(findings)
                    total_files += n_files

        # Deduplicate across commits (same file+line+match)
        unique = self._deduplicate(all_findings)

        # Severity filter
        unique = [f for f in unique if f.severity >= self.config.min_severity]

        elapsed = time.perf_counter() - t0

        return ScanResult(
            findings=sorted(unique, key=lambda f: f.severity, reverse=True),
            scan_duration=elapsed,
            total_commits=len(revisions),
            total_files=total_files,
        )

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #

    def _scan_revision(
        self, walker: GitWalker, commit_sha: str
    ) -> tuple[list[Finding], int]:
        """Scan all files in a single revision, return findings + file count."""
        commit_info = walker.get_commit_info(commit_sha)
        findings: list[Finding] = []
        n_files = 0

        for file_path, content in walker.get_file_contents(commit_sha):
            if not self.path_filter.should_scan(file_path):
                continue
            n_files += 1

            file_findings = self.engine.scan_content(
                content,
                file_path=file_path,
                commit_sha=commit_sha,
                commit_author=commit_info["author"],
                commit_date=commit_info["date"],
            )

            # Apply allowlist
            for f in file_findings:
                if not self.allowlist.is_allowed(f):
                    findings.append(f)

        return findings, n_files

    @staticmethod
    def _deduplicate(findings: list[Finding]) -> list[Finding]:
        """Remove duplicate findings (same file, line, matched text)."""
        seen: set[tuple[str, int | None, str]] = set()
        unique: list[Finding] = []
        for f in findings:
            key = (f.file_path, f.line_number, f.matched_text)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique
