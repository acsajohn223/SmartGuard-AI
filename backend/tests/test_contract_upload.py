"""
Module 1 - Contract Upload tests.

Covers every validation rule in SRS 4.1.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.config import Settings
from app.modules.contract_upload import ContractUploadModule, UploadValidationError


@pytest.fixture()
def uploader(tmp_path):
    settings = Settings(work_dir=str(tmp_path / "work"))
    return ContractUploadModule(settings)


# ----------------------------------------------------------------------
# Extension validation
# ----------------------------------------------------------------------
@pytest.mark.parametrize(
    "filename",
    ["contract.py", "contract.txt", "contract.solx", "contract", "contract.sol.json"],
)
def test_rejects_non_sol_extension(uploader, filename):
    with pytest.raises(UploadValidationError) as exc:
        uploader.accept_upload(filename, b"contract C {}")
    assert exc.value.code == "INVALID_EXTENSION"


def test_accepts_sol_extension(uploader):
    contract = uploader.accept_upload("MyContract.sol", b"contract C {}")
    assert contract.contract_name == "MyContract.sol"
    assert contract.source_type == "upload"
    contract.cleanup()


def test_extension_check_is_case_insensitive(uploader):
    contract = uploader.accept_upload("Contract.SOL", b"contract C {}")
    assert contract.contract_name == "Contract.SOL"
    contract.cleanup()


# ----------------------------------------------------------------------
# Empty content validation
# ----------------------------------------------------------------------
def test_rejects_empty_file(uploader):
    with pytest.raises(UploadValidationError) as exc:
        uploader.accept_upload("C.sol", b"")
    assert exc.value.code == "EMPTY_FILE"


def test_rejects_whitespace_only_file(uploader):
    with pytest.raises(UploadValidationError) as exc:
        uploader.accept_upload("C.sol", b"   \n\t  \n  ")
    assert exc.value.code == "EMPTY_SOURCE"


def test_rejects_empty_paste(uploader):
    with pytest.raises(UploadValidationError) as exc:
        uploader.accept_source("   ")
    assert exc.value.code == "EMPTY_SOURCE"


def test_rejects_empty_paste_none(uploader):
    with pytest.raises(UploadValidationError) as exc:
        uploader.accept_source(None)  # type: ignore[arg-type]
    assert exc.value.code == "EMPTY_SOURCE"


# ----------------------------------------------------------------------
# Size validation
# ----------------------------------------------------------------------
def test_rejects_file_over_size_limit(tmp_path):
    settings = Settings(max_file_size_mb=1, work_dir=str(tmp_path / "work"))
    uploader = ContractUploadModule(settings)
    oversized = b"a" * (1024 * 1024 + 10)

    with pytest.raises(UploadValidationError) as exc:
        uploader.accept_upload("Big.sol", oversized)
    assert exc.value.code == "FILE_TOO_LARGE"
    assert exc.value.status_code == 413


def test_accepts_file_at_size_limit(tmp_path):
    settings = Settings(max_file_size_mb=1, work_dir=str(tmp_path / "work"))
    uploader = ContractUploadModule(settings)
    payload = b"a" * (1024 * 1024)

    contract = uploader.accept_upload("Exact.sol", payload)
    assert contract.source_size_bytes == payload.__len__()
    contract.cleanup()


def test_rejects_paste_over_char_limit(tmp_path):
    settings = Settings(max_source_chars=100, work_dir=str(tmp_path / "work"))
    uploader = ContractUploadModule(settings)

    with pytest.raises(UploadValidationError) as exc:
        uploader.accept_source("x" * 200)
    assert exc.value.code == "SOURCE_TOO_LARGE"


# ----------------------------------------------------------------------
# Filename sanitisation
# ----------------------------------------------------------------------
@pytest.mark.parametrize(
    "raw,expected",
    [
        ("../../etc/passwd.sol", "passwd.sol"),
        ("/absolute/path/Contract.sol", "Contract.sol"),
        ("..\\..\\windows\\Contract.sol", "Contract.sol"),
        # Only the part after the last slash is used, and the extension
        # is rebuilt safely from whatever survives.
        ("Contract.sol; rm -rf /.sol", "contract.sol"),
        ("my contract.sol", "my_contract.sol"),
        ("", "contract.sol"),
        (None, "contract.sol"),
    ],
)
def test_sanitizes_filenames(uploader, raw, expected):
    assert uploader.sanitize_filename(raw) == expected


def test_sanitisation_preserves_non_sol_extension(uploader):
    """Sanitisation must never turn a non-Solidity file into a `.sol` file."""
    assert uploader.sanitize_filename("contract.py") == "contract.py"
    assert uploader.sanitize_filename("notes.txt") == "notes.txt"


def test_staged_file_stays_inside_work_dir(uploader):
    contract = uploader.accept_upload("../../../evil.sol", b"contract C {}")
    work_dir = Path(uploader.settings.work_dir).resolve()
    assert contract.path.resolve().parent == work_dir
    contract.cleanup()


def test_analysis_ids_are_unique(uploader):
    first = uploader.accept_upload("A.sol", b"contract A {}")
    second = uploader.accept_upload("A.sol", b"contract A {}")
    assert first.analysis_id != second.analysis_id
    first.cleanup()
    second.cleanup()


# ----------------------------------------------------------------------
# Misc
# ----------------------------------------------------------------------
def test_rejects_non_utf8_payload(uploader):
    with pytest.raises(UploadValidationError) as exc:
        uploader.accept_upload("C.sol", b"\xff\xfe\x00\x01binary")
    assert exc.value.code == "INVALID_ENCODING"


def test_receipt_reports_metadata(uploader):
    contract = uploader.accept_upload("C.sol", b"contract C {}")
    receipt = uploader.receipt(contract)
    assert receipt.analysis_id == contract.analysis_id
    assert receipt.contract_name == "C.sol"
    assert receipt.source_type == "upload"
    assert receipt.source_size_bytes == len(b"contract C {}")
    contract.cleanup()


def test_cleanup_removes_staged_file(uploader):
    contract = uploader.accept_upload("C.sol", b"contract C {}")
    assert contract.path.exists()
    contract.cleanup()
    assert not contract.path.exists()
    # Calling cleanup twice must not raise.
    contract.cleanup()
