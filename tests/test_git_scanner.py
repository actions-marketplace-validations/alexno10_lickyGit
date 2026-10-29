"""Integration tests for GitWalker and Scanner on real temporary Git repositories."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from git import Actor, Repo

from lickygit.config import ScanConfig
from lickygit.core.git_walker import GitWalker, GitWalkerError
from lickygit.core.scanner import Scanner
from lickygit.filters.allowlist import AllowList, AllowListEntry

if TYPE_CHECKING:
    from pathlib import Path


def _fake_aws_key(suffix: str = "IOSFODNN7EXAMPLE") -> str:
    return "AKIA" + suffix


class TestGitWalkerAndScanner:
    """Test staged, diff, incremental, history attribution, and scoped blob caching."""

    def test_staged_scan_detects_newly_added_and_modified_files(
        self, tmp_path: Path
    ) -> None:
        repo = Repo.init(tmp_path)
        author = Actor("Alice", "alice@example.com")

        # Initial commit with clean file
        clean_file = tmp_path / "existing.py"
        clean_file.write_text("x = 1\n", encoding="utf-8")
        repo.index.add(["existing.py"])
        repo.index.commit("initial commit", author=author, committer=author)

        # Stage a brand-new file with a secret AND modify existing.py with another secret
        new_file = tmp_path / "new_secret.py"
        key1 = _fake_aws_key("1111222233334444")
        new_file.write_text(f'AWS_KEY = "{key1}"\n', encoding="utf-8")

        key2 = _fake_aws_key("5555666677778888")
        clean_file.write_text(f'AWS_KEY_2 = "{key2}"\n', encoding="utf-8")

        repo.index.add(["new_secret.py", "existing.py"])

        cfg = ScanConfig(repo_path=str(tmp_path), staged=True)
        result = Scanner(cfg).scan()

        matched_files = {f.file_path for f in result.findings}
        assert "new_secret.py" in matched_files
        assert "existing.py" in matched_files

    def test_history_attributes_secret_to_introducing_commit(
        self, tmp_path: Path
    ) -> None:
        repo = Repo.init(tmp_path)
        alice = Actor("Alice", "alice@example.com")
        bob = Actor("Bob", "bob@example.com")

        # Commit 1 by Alice introduces a secret in config.py
        cfg_file = tmp_path / "config.py"
        key = _fake_aws_key("AAAABBBBCCCCDDDD")
        cfg_file.write_text(f'SECRET = "{key}"\n', encoding="utf-8")
        repo.index.add(["config.py"])
        c1 = repo.index.commit("Add config", author=alice, committer=alice)

        # Commit 2 by Bob only updates README.md
        readme = tmp_path / "README.md"
        readme.write_text("# Project Docs\n", encoding="utf-8")
        repo.index.add(["README.md"])
        repo.index.commit("Update docs", author=bob, committer=bob)

        result = Scanner(ScanConfig(repo_path=str(tmp_path), max_workers=2)).scan()
        aws_findings = [f for f in result.findings if f.matched_text == key]
        assert len(aws_findings) == 1
        assert aws_findings[0].commit_sha == c1.hexsha
        assert "Alice" in aws_findings[0].commit_author

    def test_diff_and_since_commit_only_scan_changed_files(
        self, tmp_path: Path
    ) -> None:
        repo = Repo.init(tmp_path)
        author = Actor("Dev", "dev@example.com")

        # Commit 1 has a legacy secret in legacy.py
        legacy = tmp_path / "legacy.py"
        legacy.write_text(f'KEY = "{_fake_aws_key("LEGACYKEY1234567")}"\n', encoding="utf-8")
        repo.index.add(["legacy.py"])
        c1 = repo.index.commit("Legacy commit", author=author, committer=author)

        # Commit 2 only modifies clean.py
        clean = tmp_path / "clean.py"
        clean.write_text("print('hello world')\n", encoding="utf-8")
        repo.index.add(["clean.py"])
        repo.index.commit("Clean PR commit", author=author, committer=author)

        # Incremental scan since c1 must NOT report legacy.py
        res_since = Scanner(
            ScanConfig(repo_path=str(tmp_path), since_commit=c1.hexsha)
        ).scan()
        assert res_since.findings == []
        assert res_since.total_commits == 1

        # Diff scan against c1 must also NOT report legacy.py
        res_diff = Scanner(
            ScanConfig(repo_path=str(tmp_path), diff_base=c1.hexsha)
        ).scan()
        assert res_diff.findings == []

    def test_invalid_diff_revision_raises_error(self, tmp_path: Path) -> None:
        repo = Repo.init(tmp_path)
        author = Actor("Dev", "dev@example.com")
        f = tmp_path / "a.txt"
        f.write_text("hello\n", encoding="utf-8")
        repo.index.add(["a.txt"])
        repo.index.commit("init", author=author, committer=author)

        with GitWalker(tmp_path, diff_base="nonexistent-branch-xyz") as walker, pytest.raises(
            GitWalkerError, match="Invalid or unfetched diff base"
        ):
            walker.get_revisions()

    def test_copied_blob_with_scoped_allowlist_is_caught_in_new_path(
        self, tmp_path: Path
    ) -> None:
        repo = Repo.init(tmp_path)
        author = Actor("Dev", "dev@example.com")
        key = _fake_aws_key("SCOPEDBLOB123456")
        content = f'TOKEN = "{key}"\n'

        # Commit 1: secret in tests/fixture.py (allowed by scope:tests/*)
        test_dir = tmp_path / "tests"
        test_dir.mkdir()
        (test_dir / "fixture.py").write_text(content, encoding="utf-8")
        repo.index.add(["tests/fixture.py"])
        repo.index.commit("Add test fixture", author=author, committer=author)

        # Commit 2: exact same content (same blob_sha!) copied to src/prod.py
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        (src_dir / "prod.py").write_text(content, encoding="utf-8")
        repo.index.add(["src/prod.py"])
        repo.index.commit("Copy to prod", author=author, committer=author)

        allow = AllowList([AllowListEntry(pattern=key, scope="tests/*")])
        result = Scanner(
            ScanConfig(repo_path=str(tmp_path), max_workers=1), allowlist=allow
        ).scan()

        paths = [f.file_path for f in result.findings]
        assert "tests/fixture.py" not in paths
        assert "src/prod.py" in paths
