"""Git repository walker using GitPython — cross-platform."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from collections.abc import Iterator
from pathlib import Path

from git import Repo, InvalidGitRepositoryError, GitCommandNotFound


class GitWalkerError(Exception):
    """Raised when a git operation fails."""


class GitWalker:
    """Walk Git revisions and extract file contents.

    Uses GitPython for cross-platform support (Windows/macOS/Linux).
    Never calls ``os.chdir`` — all operations use explicit paths.
    """

    def __init__(self, repo_path: str | Path, head_only: bool = False) -> None:
        self.repo_path = Path(repo_path).resolve()
        self.head_only = head_only
        try:
            self.repo = Repo(self.repo_path)
        except InvalidGitRepositoryError as exc:
            raise GitWalkerError(f"Not a git repository: {self.repo_path}") from exc
        except GitCommandNotFound as exc:
            raise GitWalkerError(
                "Git is not installed or not on PATH."
            ) from exc

    # ------------------------------------------------------------------
    # Revision listing
    # ------------------------------------------------------------------

    def get_revisions(self) -> list[str]:
        """Return commit SHAs to scan.

        If *head_only* is ``True``, return only ``HEAD``.
        Otherwise return **all** reachable commits.
        """
        if self.head_only:
            return [self.repo.head.commit.hexsha]

        return [c.hexsha for c in self.repo.iter_commits("--all")]

    # ------------------------------------------------------------------
    # File iteration
    # ------------------------------------------------------------------

    def get_file_contents(self, commit_sha: str) -> Iterator[tuple[str, str]]:
        """Yield ``(file_path, text_content)`` for every non-binary file in *commit_sha*."""
        commit = self.repo.commit(commit_sha)
        for blob in commit.tree.traverse():
            if blob.type != "blob":  # type: ignore[attr-defined]
                continue
            # Skip files that look binary
            try:
                data: bytes = blob.data_stream.read()  # type: ignore[attr-defined]
                if b"\x00" in data[:8192]:
                    continue  # binary
                text = data.decode("utf-8", errors="replace")
                yield (blob.path, text)  # type: ignore[attr-defined]
            except Exception:  # noqa: BLE001
                continue  # unreadable — skip

    # ------------------------------------------------------------------
    # Commit metadata
    # ------------------------------------------------------------------

    def get_commit_info(self, sha: str) -> dict[str, str]:
        """Return author, date and message for the given commit."""
        commit = self.repo.commit(sha)
        return {
            "author": str(commit.author),
            "date": commit.committed_datetime.isoformat(),
            "message": commit.message.strip(),
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
        if target_dir is None:
            target_dir = Path(tempfile.mkdtemp(prefix="lickygit_"))
        else:
            target_dir = Path(target_dir)

        try:
            subprocess.run(
                ["git", "clone", "--", url, str(target_dir)],
                check=True,
                capture_output=True,
                text=True,
            )
        except subprocess.CalledProcessError as exc:
            raise GitWalkerError(f"Failed to clone {url}: {exc.stderr}") from exc

        return cls(target_dir)

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def delete_repo(self) -> None:
        """Remove the repository directory from disk."""
        shutil.rmtree(self.repo_path, ignore_errors=True)
