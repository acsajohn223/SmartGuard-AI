"""
Module 2 - Slither Scanner tests.

These tests actually invoke Slither, so they need solc to be installed.
They are skipped automatically when Slither or solc is unavailable.
"""
from __future__ import annotations

import shutil
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.config import Settings
from app.modules.contract_upload import ContractUploadModule
from app.modules.slither_scanner import ScanError, SlitherScannerModule

SAMPLES = Path(__file__).resolve().parents[2] / "samples" / "contracts"

def _has_slither_module() -> bool:
    try:
        import slither  # noqa: F401
    except ImportError:
        return False
    return True


pytestmark = pytest.mark.skipif(
    not _has_slither_module(),
    reason="Slither is not installed in this environment.",
)


@pytest.fixture()
def scanner(tmp_path):
    settings = Settings(work_dir=str(tmp_path / "work"))
    return SlitherScannerModule(settings)


@pytest.fixture()
def uploader(tmp_path):
    settings = Settings(work_dir=str(tmp_path / "work"))
    return ContractUploadModule(settings)


def test_scan_finds_vulnerabilities(scanner, uploader):
    source = (SAMPLES / "VulnerableVault.sol").read_text(encoding="utf-8")
    contract = uploader.accept_source(source, "VulnerableVault.sol")

    result = scanner.scan(
        analysis_id=contract.analysis_id,
        contract_path=contract.path,
        contract_name=contract.contract_name,
        source_type=contract.source_type,
        source_size_bytes=contract.source_size_bytes,
    )

    assert result.status.value == "completed"
    assert len(result.findings) > 0
    assert result.summary.total == len(result.findings)
    # Every finding must be normalised and carry a severity.
    for finding in result.findings:
        assert finding.detector
        assert finding.severity.value in {"critical", "high", "medium", "low", "informational"}
        assert finding.finding_id
    contract.cleanup()


def test_scan_detects_reentrancy(scanner, uploader):
    source = (SAMPLES / "VulnerableVault.sol").read_text(encoding="utf-8")
    contract = uploader.accept_source(source, "VulnerableVault.sol")
    result = scanner.scan(
        analysis_id=contract.analysis_id,
        contract_path=contract.path,
        contract_name=contract.contract_name,
    )
    detectors = {f.detector for f in result.findings}
    assert "reentrancy-eth" in detectors
    contract.cleanup()


def test_scan_detects_controlled_delegatecall(scanner, uploader):
    source = (SAMPLES / "VulnerableVault.sol").read_text(encoding="utf-8")
    contract = uploader.accept_source(source, "VulnerableVault.sol")
    result = scanner.scan(
        analysis_id=contract.analysis_id,
        contract_path=contract.path,
        contract_name=contract.contract_name,
    )
    detectors = {f.detector for f in result.findings}
    assert "controlled-delegatecall" in detectors
    contract.cleanup()


def test_only_high_and_medium_detectors_are_eligible(scanner):
    _, detectors = scanner._load_slither()
    eligible = [d for d in detectors if scanner._impact_of(d) in ("High", "Medium")]
    excluded = [d for d in detectors if scanner._impact_of(d) not in ("High", "Medium")]

    assert len(eligible) > 0
    assert len(excluded) > 0
    # SRS 4.2 expects 57 eligible detectors for the pinned Slither version.
    assert len(eligible) == 57


def test_secure_contract_has_no_high_findings(scanner, uploader):
    source = (SAMPLES / "SecureVault.sol").read_text(encoding="utf-8")
    contract = uploader.accept_source(source, "SecureVault.sol")
    result = scanner.scan(
        analysis_id=contract.analysis_id,
        contract_path=contract.path,
        contract_name=contract.contract_name,
    )
    assert result.summary.critical == 0
    assert result.summary.high == 0
    contract.cleanup()


def test_scan_reports_compilation_failure(scanner, uploader):
    contract = uploader.accept_source("contract Broken { this is not solidity }", "Broken.sol")
    with pytest.raises(ScanError) as exc:
        scanner.scan(
            analysis_id=contract.analysis_id,
            contract_path=contract.path,
            contract_name=contract.contract_name,
        )
    assert exc.value.code == "COMPILATION_FAILED"
    contract.cleanup()


def test_findings_are_sorted_by_severity(scanner, uploader):
    source = (SAMPLES / "VulnerableVault.sol").read_text(encoding="utf-8")
    contract = uploader.accept_source(source, "VulnerableVault.sol")
    result = scanner.scan(
        analysis_id=contract.analysis_id,
        contract_path=contract.path,
        contract_name=contract.contract_name,
    )
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    ranks = [order[f.severity.value] for f in result.findings]
    assert ranks == sorted(ranks)
    contract.cleanup()
