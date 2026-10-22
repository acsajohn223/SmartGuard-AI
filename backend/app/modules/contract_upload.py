"""
Module 1 - Contract Upload.

The entry point of SmartGuard AI. Accepts Solidity source either as a
`.sol` file upload or as raw pasted text, validates it against the rules
in SRS 4.1, and hands the validated source to the scanning module.

Validation rules implemented here:
  * the file extension must be `.sol`                -> rejected otherwise
  * the payload must not be empty                    -> rejected otherwise
  * the payload must not exceed the configured limit (2 MB) -> rejected otherwise
  * filenames are sanitised before they touch the filesystem
  * an `analysis_id` is returned immediately so the caller can poll
"""
from __future__ import annotations

import os
import re
import shutil
import uuid
from dataclasses import dataclass
from pathlib import Path

from app.core.config import Settings
from app.core.models import UploadReceipt


class UploadValidationError(Exception):
    """Raised when a payload violates a Module 1 validation rule.

    The ``code`` attribute lets the API layer map the failure onto a
    stable, machine-readable error code for the frontend.
    """

    def __init__(self, message: str, code: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
        self.status_code = status_code


@dataclass
class ValidatedContract:
    """A contract that passed every Module 1 check."""

    analysis_id: str
    contract_name: str
    source: str
    source_size_bytes: int
    source_type: str  # "upload" or "paste"
    path: Path

    def cleanup(self) -> None:
        """Remove the temporary working file. Safe to call more than once."""
        try:
            if self.path.exists():
                self.path.unlink()
        except OSError:
            pass


class ContractUploadModule:
    """Module 1 implementation."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        # Any character that is not alphanumeric, a dot, a dash or an
        # underscore is collapsed so the name can never escape the
        # working directory.
        self._unsafe_chars = re.compile(r"[^A-Za-z0-9._-]")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def accept_upload(self, filename: str | None, content: bytes) -> ValidatedContract:
        """Validate an uploaded `.sol` file and stage it on disk."""
        # The extension is checked against the original client filename so
        # that sanitisation can never mask an invalid file type.
        self._check_extension(filename)
        safe_name = self.sanitize_filename(filename)

        if not content:
            raise UploadValidationError(
                "The uploaded file is empty. Provide a Solidity contract with source code.",
                "EMPTY_FILE",
            )

        max_bytes = self.settings.max_file_size_bytes
        if len(content) > max_bytes:
            raise UploadValidationError(
                f"The uploaded file is {len(content) / 1024 / 1024:.2f} MB. "
                f"The maximum allowed size is {self.settings.max_file_size_mb} MB.",
                "FILE_TOO_LARGE",
                status_code=413,
            )

        try:
            source = content.decode("utf-8")
        except UnicodeDecodeError:
            raise UploadValidationError(
                "The uploaded file is not valid UTF-8 text. "
                "SmartGuard AI only accepts plain Solidity source files.",
                "INVALID_ENCODING",
            )

        self._check_not_blank(source)
        return self._stage(safe_name, source, source_type="upload")

    def accept_source(self, source: str, filename: str = "contract.sol") -> ValidatedContract:
        """Validate pasted Solidity source and stage it on disk."""
        self._check_extension(filename)
        safe_name = self.sanitize_filename(filename or "contract.sol")
        self._check_extension(safe_name)

        if source is None or not source.strip():
            raise UploadValidationError(
                "The pasted source code is empty. Provide a Solidity contract with source code.",
                "EMPTY_SOURCE",
            )

        if len(source) > self.settings.max_source_chars:
            raise UploadValidationError(
                f"The pasted source is {len(source)} characters. "
                f"The maximum allowed size is {self.settings.max_source_chars} characters.",
                "SOURCE_TOO_LARGE",
                status_code=413,
            )

        self._check_not_blank(source)
        return self._stage(safe_name, source, source_type="paste")

    def receipt(self, contract: ValidatedContract) -> UploadReceipt:
        """Build the immediate receipt returned to the caller."""
        return UploadReceipt(
            analysis_id=contract.analysis_id,
            contract_name=contract.contract_name,
            source_type=contract.source_type,
            source_size_bytes=contract.source_size_bytes,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def sanitize_filename(self, filename: str | None) -> str:
        """Reduce an arbitrary client filename to a safe basename.

        The extension is preserved as sent by the client so that a file
        named ``Contract.sol`` stays ``Contract.sol`` and a file named
        ``Contract.py`` is never silently turned into a Solidity file.
        """
        if not filename:
            return "contract.sol"

        # Strip any directory components a client may have sent.
        base = os.path.basename(filename.replace("\\", "/"))
        # Remove control characters before the general whitelist.
        base = re.sub(r"[\x00-\x1f\x7f]", "_", base)

        if not base:
            return "contract.sol"

        # Split off the extension *before* stripping characters, so that a
        # name such as "Contract.sol; rm -rf /.sol" still keeps its suffix.
        stem, dot, extension = base.rpartition(".")
        if not dot:
            stem, extension = base, ""

        stem = re.sub(r"[^\w-]", "_", stem).strip("._") or "contract"
        extension = re.sub(r"[^\w-]", "_", extension).strip("._")

        return f"{stem}.{extension}" if extension else stem

    def _check_extension(self, filename: str | None) -> None:
        """Reject anything that is not a `.sol` file."""
        if not filename:
            raise UploadValidationError(
                "No file name was supplied. "
                f"SmartGuard AI only accepts '{self.settings.allowed_extension}' Solidity files.",
                "INVALID_EXTENSION",
            )

        if not filename.lower().endswith(self.settings.allowed_extension):
            raise UploadValidationError(
                f"Invalid file type '{os.path.basename(filename)}'. "
                f"SmartGuard AI only accepts '{self.settings.allowed_extension}' Solidity files.",
                "INVALID_EXTENSION",
            )

    def _check_not_blank(self, source: str) -> None:
        """Reject content that is whitespace only."""
        if not source.strip():
            raise UploadValidationError(
                "The submitted source code is empty. Provide a Solidity contract with source code.",
                "EMPTY_SOURCE",
            )

    def _stage(self, safe_name: str, source: str, source_type: str) -> ValidatedContract:
        """Write the validated source into the working directory."""
        work_dir = Path(self.settings.work_dir)
        work_dir.mkdir(parents=True, exist_ok=True)

        analysis_id = uuid.uuid4().hex
        # Prefix with the analysis id so concurrent jobs never collide.
        target = work_dir / f"{analysis_id}_{safe_name}"

        target.write_text(source, encoding="utf-8")

        return ValidatedContract(
            analysis_id=analysis_id,
            contract_name=safe_name,
            source=source,
            source_size_bytes=len(source.encode("utf-8")),
            source_type=source_type,
            path=target,
        )

    def cleanup_work_dir(self) -> None:
        """Remove the whole working directory. Used by tests and shutdown."""
        shutil.rmtree(self.settings.work_dir, ignore_errors=True)
