"""Configuration management — load from ``.lickygit.toml`` and merge with CLI args."""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from lickygit.core.finding import Severity
from lickygit.core.git_walker import DEFAULT_MAX_FILE_SIZE


@dataclass
class ScanConfig:
    """All options that control a scan run.

    Defaults are sensible for interactive terminal usage.
    """

    # ── repo ───────────────────────────────────────────────────────────
    repo_path: str = "."
    head_only: bool = False
    staged: bool = False
    max_workers: int = 4
    max_file_size: int = DEFAULT_MAX_FILE_SIZE

    # ── detection ──────────────────────────────────────────────────────
    use_entropy: bool = True
    use_keywords: bool = True
    use_builtin_rules: bool = True
    entropy_threshold: float = 4.5
    custom_rules_path: str | None = None

    # ── filtering ──────────────────────────────────────────────────────
    exclude_paths: list[str] = field(default_factory=list)
    include_paths: list[str] = field(default_factory=list)
    allowlist_path: str | None = None
    baseline_path: str | None = None
    generate_baseline_path: str | None = None
    min_severity: Severity = Severity.LOW

    # ── output ─────────────────────────────────────────────────────────
    output_format: str = "terminal"  # terminal | json | csv | sarif | html
    output_file: str | None = None
    verbose: bool = False
    use_color: bool = True
    show_banner: bool = True

    # ── clone helpers ──────────────────────────────────────────────────
    clone_url: str | None = None
    delete_after_scan: bool = False


# ---------------------------------------------------------------------- #
# TOML loader
# ---------------------------------------------------------------------- #

def _load_toml(path: Path) -> dict[str, Any]:
    """Read a TOML file and return its data as a dict."""
    if sys.version_info >= (3, 11):
        import tomllib  # noqa: F811
    else:
        try:
            import tomli as tomllib  # type: ignore[no-redef]
        except ImportError as exc:
            raise ImportError(
                "Install 'tomli' for Python <3.11: pip install tomli"
            ) from exc

    with open(path, "rb") as fh:
        return tomllib.load(fh)


def _find_config_file(start: Path | None = None) -> Path | None:
    """Walk from *start* up to the filesystem root looking for ``.lickygit.toml``."""
    current = (start or Path.cwd()).resolve()
    for directory in [current, *current.parents]:
        candidate = directory / ".lickygit.toml"
        if candidate.is_file():
            return candidate
    return None


_SEVERITY_MAP: dict[str, Severity] = {s.value.lower(): s for s in Severity}


def _parse_severity(value: str) -> Severity:
    try:
        return _SEVERITY_MAP[value.lower()]
    except KeyError:
        return Severity.LOW


def load_config(path: str | Path | None = None) -> ScanConfig:
    """Load configuration from a ``.lickygit.toml`` file.

    If *path* is ``None``, searches the current directory and its parents.
    Returns a default :class:`ScanConfig` if no file is found.
    """
    config_path: Path | None
    if path is not None:
        config_path = Path(path)
        if not config_path.is_file():
            raise FileNotFoundError(f"Config file not found: {config_path}")
    else:
        config_path = _find_config_file()

    if config_path is None:
        return ScanConfig()

    data = _load_toml(config_path)

    scan = data.get("scan", {})
    detection = data.get("detection", {})
    filters = data.get("filters", {})
    output = data.get("output", {})

    return ScanConfig(
        head_only=scan.get("head_only", False),
        staged=scan.get("staged", False),
        max_workers=scan.get("max_workers", 4),
        max_file_size=scan.get("max_file_size", DEFAULT_MAX_FILE_SIZE),
        min_severity=_parse_severity(scan.get("severity", "low")),
        use_entropy=detection.get("use_entropy", True),
        use_keywords=detection.get("use_keywords", True),
        use_builtin_rules=detection.get("use_builtin_rules", True),
        entropy_threshold=detection.get("entropy_threshold", 4.5),
        custom_rules_path=detection.get("custom_rules", None),
        exclude_paths=filters.get("exclude", []),
        include_paths=filters.get("include", []),
        allowlist_path=filters.get("allowlist", None),
        baseline_path=filters.get("baseline", None),
        output_format=output.get("format", "terminal"),
        verbose=output.get("verbose", False),
        use_color=output.get("color", True),
        show_banner=output.get("banner", True),
    )


# ---------------------------------------------------------------------- #
# Merge
# ---------------------------------------------------------------------- #

def merge_configs(file_config: ScanConfig, cli_overrides: dict[str, Any]) -> ScanConfig:
    """Create a new :class:`ScanConfig` by overlaying *cli_overrides* on *file_config*.

    Only keys present **and not-None** in *cli_overrides* take effect.
    """
    merged = ScanConfig(**{
        f.name: getattr(file_config, f.name)
        for f in file_config.__dataclass_fields__.values()  # type: ignore[attr-defined]
    })
    for key, value in cli_overrides.items():
        if value is not None and hasattr(merged, key):
            object.__setattr__(merged, key, value)
    return merged
