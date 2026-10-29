"""Git repository walker using GitPython — cross-platform and diff-aware."""

from __future__ import annotations

import contextlib
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any

from git import GitCommandNotFound, InvalidGitRepositoryError, Repo
from git.objects import Blob

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

# Default maximum file size to scan (5 MB). Files larger than this are skipped to prevent OOM.
DEFAULT_MAX_FILE_SIZE: int = 5 * 1024 * 1024


def safe_rmtree(target_dir: str | Path) -> None:
    """Recursively remove a directory, handling Windows read-only git files."""
    p = Path(target_dir)
    if not p.exists():
        return

    def _handle_readonly(func: Any, path: str, exc: Any) -> None:
        try:
            os.chmod(path, stat.S_IWRITE)
            func(path)
        except Exception:
            pass

    if sys.version_info >= (3, 12):
        shutil.rmtree(p, onexc=_handle_readonly)
    else:
        shutil.rmtree(p, onerror=_handle_readonly)


class GitWalkerError(Exception):
    """Raised when a git operation fails."""


class GitWalker:
    """Walk Git revisions and extract file contents.

    Uses GitPython for cross-platform support (Windows/macOS/Linux).
    Never calls ``os.chdir`` — all operations use explicit paths.
    """

    def __init__(
        self,
        repo_path: str | Path,
        head_only: bool = False,
        staged: bool = False,
        since_commit: str | None = None,
        diff_base: str | None = None,
    ) -> None:
        self.repo_path = Path(repo_path).resolve()
        self.head_only = head_only
        self.staged = staged
        self.since_commit = since_commit
        self.diff_base = diff_base
        try:
            self.repo = Repo(self.repo_path)
        except InvalidGitRepositoryError as exc:
            raise GitWalkerError(f"Not a git repository: {self.repo_path}") from exc
        except GitCommandNotFound as exc:
            raise GitWalkerError("Git is not installed or not on PATH.") from exc

    def close(self) -> None:
        """Close underlying GitPython Repo resources and subprocess pipes."""
        with contextlib.suppress(Exception):
            self.repo.close()

    def __enter__(self) -> GitWalker:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Revision listing
    # ------------------------------------------------------------------

    def get_revisions(self) -> list[str]:
        """Return commit SHAs to scan in chronological order (oldest first).

        If *staged* is ``True``, returns a sentinel ``["STAGED"]``.
        If *head_only* is ``True``, returns only ``HEAD``.
        If *diff_base* is set, returns commits in ``diff_base..HEAD``.
        If *since_commit* is set, returns commits in ``since_commit..HEAD``.
        Otherwise returns **all** reachable commits (oldest first).
        """
        if self.staged:
            return ["STAGED"]

        if self.head_only:
            try:
                return [self.repo.head.commit.hexsha]
            except Exception:
                return []

        # Diff-aware PR scanning: only commits in the range
        if self.diff_base:
            try:
                commits = list(self.repo.iter_commits(f"{self.diff_base}..HEAD"))
            except Exception as exc:
                raise GitWalkerError(
                    f"Invalid or unfetched diff base revision '{self.diff_base}': {exc}"
                ) from exc
            return [c.hexsha for c in reversed(commits)]

        # Incremental scanning: only new commits since a point
        if self.since_commit:
            try:
                commits = list(self.repo.iter_commits(f"{self.since_commit}..HEAD"))
            except Exception as exc:
                raise GitWalkerError(
                    f"Invalid or unfetched commit '{self.since_commit}': {exc}"
                ) from exc
            return [c.hexsha for c in reversed(commits)]

        try:
            commits = list(self.repo.iter_commits("--all"))
        except Exception:
            return []
        return [c.hexsha for c in reversed(commits)]

    # ------------------------------------------------------------------
    # File iteration
    # ------------------------------------------------------------------

    def get_file_contents(
        self,
        commit_sha: str,
        max_file_size: int = DEFAULT_MAX_FILE_SIZE,
        should_scan_file: Callable[[str, str], bool] | None = None,
    ) -> Iterator[tuple[str, str, str]]:
        """Yield ``(file_path, text_content, blob_sha)`` for non-binary files.

        Files larger than *max_file_size*, failing *should_scan_file(path, blob_sha)*,
        or containing null bytes are skipped before reading/decoding full content.
        """
        # 1. Staged files from Git index (pre-commit)
        if commit_sha == "STAGED" or self.staged:
            yield from self._iter_staged_files(max_file_size, should_scan_file)
            return

        commit = self.repo.commit(commit_sha)

        # 2. Diff-based scanning for non-root commits when not in --head-only mode
        if not self.head_only and commit.parents:
            yield from self._iter_commit_diff_files(
                commit, max_file_size, should_scan_file
            )
            return

        # 3. Full tree traversal for root commits or --head-only mode
        for item in commit.tree.traverse():
            if not isinstance(item, Blob):
                continue
            path_str = str(item.path)
            blob_sha = item.hexsha
            if should_scan_file is not None and not should_scan_file(path_str, blob_sha):
                continue
            text = self._read_blob_text(item, max_file_size)
            if text is not None:
                yield (path_str, text, blob_sha)

    def _iter_staged_files(
        self,
        max_file_size: int,
        should_scan_file: Callable[[str, str], bool] | None,
    ) -> Iterator[tuple[str, str, str]]:
        """Yield staged files in the Git index compared against HEAD."""
        staged_paths: set[str] | None = None
        try:
            # R=True reverses the diff so it compares HEAD -> index (forward direction),
            # ensuring newly added files have change_type == 'A' and renamed files use b_path.
            diffs = self.repo.index.diff("HEAD", R=True)
            staged_paths = {
                path
                for d in diffs
                if d.change_type in ("A", "M", "R", "C")
                for path in (d.b_path or d.a_path,)
                if path is not None
            }
        except Exception:
            # Initial commit (no HEAD yet): scan all stage-0 entries in index
            staged_paths = None

        for (path, stage), entry in self.repo.index.entries.items():
            if stage != 0:
                continue
            path_str = str(path)
            if staged_paths is not None and path_str not in staged_paths:
                continue
            blob_sha = entry.hexsha
            if should_scan_file is not None and not should_scan_file(path_str, blob_sha):
                continue
            try:
                stream = self.repo.odb.stream(entry.binsha)
                if hasattr(stream, "size") and stream.size > max_file_size:
                    continue
                data: bytes = stream.read()
                if len(data) > max_file_size or b"\x00" in data[:8192]:
                    continue
                text = data.decode("utf-8", errors="replace")
                yield (path_str, text, blob_sha)
            except Exception:
                continue

    def _iter_commit_diff_files(
        self,
        commit: Any,
        max_file_size: int,
        should_scan_file: Callable[[str, str], bool] | None,
    ) -> Iterator[tuple[str, str, str]]:
        """Yield only added/modified/renamed/copied files in *commit* vs its first parent."""
        parent = commit.parents[0]
        try:
            diffs = parent.diff(commit)
        except Exception:
            return

        for d in diffs:
            if d.change_type == "D" or d.b_blob is None:
                continue
            b_blob = d.b_blob
            path_str = str(d.b_path or d.a_path or "")
            if not path_str:
                continue
            blob_sha = str(b_blob.hexsha)
            if should_scan_file is not None and not should_scan_file(path_str, blob_sha):
                continue
            text = self._read_blob_text(b_blob, max_file_size)
            if text is not None:
                yield (path_str, text, blob_sha)

    @staticmethod
    def _read_blob_text(blob: Any, max_file_size: int) -> str | None:
        """Read and decode a Git blob if it is non-binary and within *max_file_size*."""
        try:
            if getattr(blob, "type", "blob") != "blob":
                return None
            if blob.size > max_file_size:
                return None
            data: bytes = blob.data_stream.read()
            if len(data) > max_file_size or b"\x00" in data[:8192]:
                return None
            return data.decode("utf-8", errors="replace")
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Commit metadata
    # ------------------------------------------------------------------

    def get_commit_info(self, sha: str) -> dict[str, str]:
        """Return author, date and message for the given commit."""
        if sha == "STAGED":
            return {
                "author": "Current User (Staged)",
                "date": "Working Tree",
                "message": "Staged changes for upcoming commit",
            }

        commit = self.repo.commit(sha)
        raw_msg = commit.message
        msg = (
            raw_msg.decode("utf-8", errors="replace")
            if isinstance(raw_msg, bytes)
            else str(raw_msg)
        )
        return {
            "author": str(commit.author),
            "date": commit.committed_datetime.isoformat(),
            "message": msg.strip(),
        }

    # ------------------------------------------------------------------
    # Clone helper
    # ------------------------------------------------------------------

    @classmethod
    def clone(
        cls,
        url: str,
        target_dir: str | Path | None = None,
    ) -> GitWalker:
        """Clone a remote repository and return a :class:`GitWalker` for it.

        Parameters
        ----------
        url:
            Any URL that ``git clone`` accepts.
        target_dir:
            Where to clone. If *None* a temporary directory is created.
        """
        target = (
            Path(tempfile.mkdtemp(prefix="lickygit_"))
            if target_dir is None
            else Path(target_dir)
        )

        try:
            subprocess.run(
                ["git", "clone", "--", url, str(target)],
                check=True,
                capture_output=True,
                text=True,
            )
        except subprocess.CalledProcessError as exc:
            raise GitWalkerError(f"Failed to clone {url}: {exc.stderr}") from exc

        return cls(target)

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def delete_repo(self) -> None:
        """Remove the repository directory from disk safely on all platforms."""
        self.close()
        safe_rmtree(self.repo_path)
