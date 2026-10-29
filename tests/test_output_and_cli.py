"""Unit tests for output formatters, configuration, and CLI commands."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from click.testing import CliRunner
from git import Actor, Repo

from lickygit import __version__
from lickygit.cli import main
from lickygit.config import load_config, validate_config
from lickygit.core.finding import DetectionType, Finding, Severity
from lickygit.core.scanner import ScanResult
from lickygit.output.csv_fmt import CsvFormatter
from lickygit.output.gitlab_fmt import GitlabCodeQualityFormatter
from lickygit.output.html_report import HtmlReportFormatter
from lickygit.output.json_fmt import JsonFormatter
from lickygit.output.sarif import SarifFormatter
from lickygit.output.terminal import TerminalFormatter

if TYPE_CHECKING:
    from pathlib import Path


def _sample_result() -> ScanResult:
    finding = Finding(
        rule_id="aws-access-key-id",
        rule_name="AWS Access Key ID",
        severity=Severity.CRITICAL,
        file_path="src\\config.py",
        line_number=42,
        line_content="AWS_KEY = '...'",
        matched_text="=AKIA1234567890ABCDEF",
        commit_sha="abcdef1234567890",
        commit_author="Alice",
        commit_date="2026-01-01T00:00:00",
        detection_type=DetectionType.PATTERN,
    )
    return ScanResult(
        findings=[finding],
        scan_duration=0.123,
        total_commits=5,
        total_files=12,
        suppressed_by_baseline=2,
    )


class TestOutputFormatters:
    """Verify JSON, CSV, SARIF, GitLab, HTML, and Terminal formatters."""

    def test_json_formatter_and_redaction(self, tmp_path: Path) -> None:
        res = _sample_result()
        fmt = JsonFormatter(redact=False)
        raw_json = json.loads(fmt.format(res))
        assert raw_json["findings"][0]["matched_text"] == "=AKIA1234567890ABCDEF"

        out_path = tmp_path / "out.json"
        JsonFormatter(redact=True).write(res, out_path)
        redacted_json = json.loads(out_path.read_text(encoding="utf-8"))
        assert redacted_json["findings"][0]["matched_text"] == "=AKI***"

    def test_csv_formatter_sanitizes_formula_injection_and_redacts(
        self, tmp_path: Path
    ) -> None:
        res = _sample_result()
        csv_text = CsvFormatter(redact=False).format(res)
        # Leading '=' must be prefixed with "'" to prevent spreadsheet formula execution
        assert "'=AKIA1234567890ABCDEF" in csv_text

        out_path = tmp_path / "out.csv"
        CsvFormatter(redact=True).write(res, out_path)
        assert "'=AKI***" in out_path.read_text(encoding="utf-8")

    def test_sarif_formatter_omits_empty_region_when_no_line_number(
        self, tmp_path: Path
    ) -> None:
        finding_no_line = Finding(
            rule_id="entropy-hex",
            rule_name="High-Entropy Hex String",
            severity=Severity.LOW,
            file_path="dir\\file.txt",
            line_number=None,
            line_content="",
            matched_text="0123456789abcdef",
            commit_sha="12345678",
            detection_type=DetectionType.ENTROPY,
        )
        res = ScanResult(findings=[finding_no_line])
        out_path = tmp_path / "out.sarif"
        SarifFormatter().write(res, out_path)
        sarif = json.loads(out_path.read_text(encoding="utf-8"))
        assert sarif["runs"][0]["tool"]["driver"]["version"] == __version__
        phys_loc = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        assert phys_loc["artifactLocation"]["uri"] == "dir/file.txt"
        assert "region" not in phys_loc

    def test_gitlab_html_and_terminal_formatters(self, tmp_path: Path) -> None:
        res = _sample_result()
        gl_path = tmp_path / "gl.json"
        GitlabCodeQualityFormatter().write(res, gl_path)
        gl = json.loads(gl_path.read_text(encoding="utf-8"))
        assert gl[0]["severity"] == "blocker"
        assert gl[0]["location"]["path"] == "src/config.py"
        assert gl[0]["fingerprint"] == res.findings[0].fingerprint

        html_path = tmp_path / "report.html"
        HtmlReportFormatter().write(res, html_path)
        html_out = html_path.read_text(encoding="utf-8")
        assert "AWS Access Key ID" in html_out
        assert "=AKI***" in html_out

        # Exercise TerminalFormatter in verbose mode
        TerminalFormatter(use_color=False, verbose=True, show_banner=True).format(res)


class TestConfigAndCLI:
    """Verify CLI subcommands, exit codes, hooks, and config validation."""

    def test_validate_config_detects_unknown_keys(self) -> None:
        warnings = validate_config(
            {"scan": {"unknown_opt": True}, "unknown_sec": {"x": 1}}
        )
        assert len(warnings) == 2

    def test_cli_version_and_scan_options(self, tmp_path: Path) -> None:
        runner = CliRunner()
        ver_res = runner.invoke(main, ["--version"])
        assert ver_res.exit_code == 0
        assert __version__ in ver_res.output

        # Init a git repo with a MEDIUM keyword finding
        repo = Repo.init(tmp_path)
        author = Actor("Dev", "dev@example.com")
        tok = "prod_secret_" + "987654321"
        (tmp_path / "app.py").write_text(f'password = "{tok}"\n', encoding="utf-8")
        repo.index.add(["app.py"])
        repo.index.commit("init", author=author, committer=author)
        repo.close()

        # Default scan exits 1 when findings exist
        scan_fail = runner.invoke(main, ["scan", str(tmp_path), "--no-banner"])
        assert scan_fail.exit_code == 1

        # --fail-on-severity critical exits 0 when only MEDIUM findings exist
        scan_pass = runner.invoke(
            main,
            [
                "scan",
                str(tmp_path),
                "--fail-on-severity",
                "critical",
                "-f",
                "json",
                "--redact",
            ],
        )
        assert scan_pass.exit_code == 0
        assert "prod***" in scan_pass.output

        # Generate baseline and re-scan with baseline -> exits 0
        baseline_file = tmp_path / "base.json"
        runner.invoke(
            main,
            ["scan", str(tmp_path), "--generate-baseline", str(baseline_file)],
        )
        assert baseline_file.is_file()
        scan_base = runner.invoke(
            main,
            ["scan", str(tmp_path), "--baseline", str(baseline_file), "--no-banner"],
        )
        assert scan_base.exit_code == 0

    def test_cli_config_and_hook_commands(
        self, tmp_path: Path, monkeypatch: object
    ) -> None:
        runner = CliRunner()
        cfg_file = tmp_path / ".lickygit.toml"
        cfg_file.write_text(
            '[scan]\nseverity = "high"\n[output]\nredact = true\n',
            encoding="utf-8",
        )

        loaded = load_config(cfg_file)
        assert loaded.min_severity == Severity.HIGH
        assert loaded.redact is True

        chk = runner.invoke(main, ["config", "check", "-c", str(cfg_file)])
        assert chk.exit_code == 0

        show = runner.invoke(main, ["config", "show", "-c", str(cfg_file)])
        assert show.exit_code == 0
        assert "HIGH" in show.output

        # Test hook install/uninstall inside tmp_path repo
        repo = Repo.init(tmp_path)
        repo.close()
        import pytest as _pytest

        mp = _pytest.MonkeyPatch()
        mp.chdir(tmp_path)
        try:
            inst = runner.invoke(main, ["hook", "install", "--severity", "critical"])
            assert inst.exit_code == 0
            hook_file = tmp_path / ".git" / "hooks" / "pre-commit"
            assert hook_file.is_file()

            uninst = runner.invoke(main, ["hook", "uninstall"])
            assert uninst.exit_code == 0
            assert not hook_file.exists()

            # Protect existing third-party hook unless --force is passed
            hook_file.write_text("#!/bin/sh\necho custom hook\n", encoding="utf-8")
            blocked = runner.invoke(main, ["hook", "install"])
            assert blocked.exit_code == 1
            forced = runner.invoke(main, ["hook", "install", "--force"])
            assert forced.exit_code == 0
        finally:
            mp.undo()
