"""Main scanner orchestrator — ties Git walking, detection, and filtering together."""

from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, replace

from lickygit.config import ScanConfig
from lickygit.core.finding import Finding, Severity
from lickygit.core.git_walker import GitWalker
from lickygit.detection.engine import DetectionEngine
from lickygit.filters.allowlist import AllowList
from lickygit.filters.baseline import Baseline
from lickygit.filters.path_filter import PathFilter

__all__ = ["ScanConfig", "ScanResult", "Scanner"]


@dataclass
class ScanResult:
    """The outcome of a complete scan."""

    findings: list[Finding] = field(default_factory=list)
    scan_duration: float = 0.0
    total_commits: int = 0
    total_files: int = 0
    suppressed_by_baseline: int = 0

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

    def has_findings_at_or_above(self, severity: Severity) -> bool:
        """Return *True* if any finding meets or exceeds *severity*."""
        return any(f.severity >= severity for f in self.findings)


class Scanner:
    """Orchestrate a full Git secret scan.

    Walks every revision (or HEAD only / staged only) through :class:`GitWalker`,
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
        baseline: Baseline | None = None,
    ) -> None:
        self.config = config
        self.engine = engine or DetectionEngine()
        self.allowlist = allowlist or AllowList()
        self.path_filter = path_filter or PathFilter(
            exclude_patterns=config.exclude_paths or None,
            include_patterns=config.include_paths or None,
        )
        self.baseline = baseline or (
            Baseline.load_from_file(config.baseline_path)
            if config.baseline_path
            else None
        )
        self._clean_blobs: set[str] = set()
        self._scanned_file_blobs: set[tuple[str, str]] = set()
        self._dirty_blob_findings: dict[str, list[Finding]] = {}
        self._blob_lock = threading.Lock()
        self._thread_local = threading.local()
        self._walkers: list[GitWalker] = []
        self._walker_lock = threading.Lock()

    # ------------------------------------------------------------------ #

    def _get_thread_walker(self) -> GitWalker:
        """Return a thread-local :class:`GitWalker`, creating one per worker thread."""
        walker: GitWalker | None = getattr(self._thread_local, "walker", None)
        if walker is None:
            walker = GitWalker(
                self.config.repo_path,
                head_only=self.config.head_only,
                staged=self.config.staged,
                since_commit=self.config.since_commit,
                diff_base=self.config.diff_base,
            )
            self._thread_local.walker = walker
            with self._walker_lock:
                self._walkers.append(walker)
        return walker

    def _close_walkers(self) -> None:
        """Close all created GitWalker instances to release Git pack locks."""
        with self._walker_lock:
            for w in self._walkers:
                w.close()
            self._walkers.clear()
        if hasattr(self._thread_local, "walker"):
            delattr(self._thread_local, "walker")

    def scan(self) -> ScanResult:
        """Execute the scan and return results."""
        t0 = time.perf_counter()

        all_findings: list[Finding] = []
        total_files = 0
        revisions: list[str] = []

        try:
            main_walker = self._get_thread_walker()
            revisions = main_walker.get_revisions()

            if self.config.max_workers <= 1 or len(revisions) <= 1:
                # Sequential
                for sha in revisions:
                    findings, n_files = self._scan_revision(main_walker, sha)
                    all_findings.extend(findings)
                    total_files += n_files
            else:
                # Parallel (one isolated GitWalker instance per worker thread)
                def _worker_scan(idx_sha: tuple[int, str]) -> tuple[int, list[Finding], int]:
                    idx, sha = idx_sha
                    local_walker = self._get_thread_walker()
                    f_list, count = self._scan_revision(local_walker, sha)
                    return idx, f_list, count

                ordered_results: list[tuple[int, list[Finding], int]] = []
                with ThreadPoolExecutor(max_workers=self.config.max_workers) as pool:
                    futures = {
                        pool.submit(_worker_scan, (idx, sha)): idx
                        for idx, sha in enumerate(revisions)
                    }
                    for future in as_completed(futures):
                        ordered_results.append(future.result())

                # Sort by revision index (oldest commit first) for deterministic attribution
                ordered_results.sort(key=lambda item: item[0])
                for _, findings, n_files in ordered_results:
                    all_findings.extend(findings)
                    total_files += n_files
        finally:
            self._close_walkers()

        # Deduplicate across commits (same file+line+match)
        unique = self._deduplicate(all_findings)

        # Severity filter
        unique = [f for f in unique if f.severity >= self.config.min_severity]

        # Baseline filter (suppress existing legacy findings)
        suppressed_count = 0
        if self.baseline:
            unique, suppressed_count = self.baseline.filter_findings(unique)

        # Generate baseline file if requested
        if self.config.generate_baseline_path:
            Baseline.generate(unique, self.config.generate_baseline_path)

        elapsed = time.perf_counter() - t0

        return ScanResult(
            findings=sorted(unique, key=lambda f: f.severity, reverse=True),
            scan_duration=elapsed,
            total_commits=len(revisions),
            total_files=total_files,
            suppressed_by_baseline=suppressed_count,
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
        cached_hits: list[tuple[str, list[Finding]]] = []

        def _should_scan_file(file_path: str, blob_sha: str) -> bool:
            if not self.path_filter.should_scan(file_path):
                return False
            with self._blob_lock:
                if (file_path, blob_sha) in self._scanned_file_blobs:
                    return False
                self._scanned_file_blobs.add((file_path, blob_sha))
                if blob_sha in self._clean_blobs:
                    return False
                if blob_sha in self._dirty_blob_findings:
                    # Same blob content moved/copied to a new path: reuse cached raw findings
                    cached_hits.append((file_path, self._dirty_blob_findings[blob_sha]))
                    return False
            return True

        for file_path, content, blob_sha in walker.get_file_contents(
            commit_sha,
            max_file_size=self.config.max_file_size,
            should_scan_file=_should_scan_file,
        ):
            n_files += 1

            raw_findings = self.engine.scan_content(
                content,
                file_path=file_path,
                commit_sha=commit_sha,
                commit_author=commit_info["author"],
                commit_date=commit_info["date"],
            )

            with self._blob_lock:
                if raw_findings:
                    self._dirty_blob_findings[blob_sha] = raw_findings
                else:
                    self._clean_blobs.add(blob_sha)

            # Apply allowlist (which may be path-scoped)
            for f in raw_findings:
                if not self.allowlist.is_allowed(f):
                    findings.append(f)

        # Process any dirty blobs that were copied/renamed to a new file_path in this revision
        for new_path, raw_list in cached_hits:
            n_files += 1
            for raw_f in raw_list:
                rebound = replace(
                    raw_f,
                    file_path=new_path,
                    commit_sha=commit_sha,
                    commit_author=commit_info["author"],
                    commit_date=commit_info["date"],
                )
                if not self.allowlist.is_allowed(rebound):
                    findings.append(rebound)

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
