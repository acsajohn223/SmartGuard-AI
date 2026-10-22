"""
SmartGuard AI - Application configuration.

Central place for every tunable value used by Modules 1 and 2.
Values can be overridden through environment variables so the same
code runs locally, in Docker and in CI without edits.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    """Runtime settings for the SmartGuard AI backend."""

    # --- Module 1: Contract Upload -------------------------------------
    # Maximum accepted upload size in megabytes (SRS 4.1: 2 MB).
    max_file_size_mb: int = field(
        default_factory=lambda: _env_int("SMARTGUARD_MAX_FILE_SIZE_MB", 2)
    )
    # Only Solidity source files are accepted.
    allowed_extension: str = ".sol"
    # Hard ceiling on pasted source, in characters. Sized so that a
    # 2 MB source file fits comfortably with room for decoding overhead.
    max_source_chars: int = field(
        default_factory=lambda: _env_int("SMARTGUARD_MAX_SOURCE_CHARS", 2 * 1024 * 1024)
    )
    # Directory used for the short-lived working files handed to Slither.
    work_dir: str = field(
        default_factory=lambda: os.getenv("SMARTGUARD_WORK_DIR", "/tmp/smartguard")
    )
    # Directory where finished analysis reports are archived.
    results_dir: str = field(
        default_factory=lambda: os.getenv(
            "SMARTGUARD_RESULTS_DIR",
            os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "results"),
        )
    )

    # --- Module 2: Slither Scanning ------------------------------------
    # Slither impact levels that map onto security-relevant findings.
    # SRS 4.2: run the 57 High and Medium severity detectors and exclude
    # the Informational and Optimization detectors.
    included_impacts: tuple[str, ...] = ("High", "Medium")
    # Timeout for a single Slither subprocess, in seconds.
    scan_timeout_seconds: int = field(
        default_factory=lambda: _env_int("SMARTGUARD_SCAN_TIMEOUT", 300)
    )
    # Pinned solc version used to compile contracts before scanning.
    solc_version: str = field(
        default_factory=lambda: os.getenv("SMARTGUARD_SOLC_VERSION", "0.8.20")
    )

    # --- API ------------------------------------------------------------
    api_title: str = "SmartGuard AI"
    api_version: str = "0.2.0"
    # Origins allowed to call the API from a browser.
    cors_origins: tuple[str, ...] = (
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    )

    @property
    def max_file_size_bytes(self) -> int:
        return self.max_file_size_mb * 1024 * 1024


settings = Settings()
