"""
Module 2 - Slither Vulnerability Scanning.

Wraps the Slither static analysis framework as the first detection pass
of the SmartGuard AI pipeline. Slither compiles the contract with solc,
converts it to SlithIR and then runs its detector suite over it.

Per SRS 4.2 the scanner runs the 57 High and Medium severity detectors
and excludes the Informational and Optimization detectors, because those
are not security relevant. The count of eligible detectors is reported
back with every result so the report always states what was executed.
"""
from __future__ import annotations

import inspect
import re
import shutil
import time
import traceback
from pathlib import Path
from typing import Any, Optional

from app.core.config import Settings
from app.core.models import (
    SLITHER_IMPACT_TO_SEVERITY,
    AnalysisResult,
    AnalysisStatus,
    SeverityCount,
    SeverityLevel,
    SlitherFinding,
)


class ScanError(Exception):
    """Raised when Slither cannot produce a result for the contract."""

    def __init__(self, message: str, code: str = "SCAN_FAILED") -> None:
        super().__init__(message)
        self.message = message
        self.code = code


class SlitherScannerModule:
    """Module 2 implementation."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def scan(self, analysis_id: str, contract_path: Path, contract_name: str,
             source_type: str = "upload", source_size_bytes: int = 0) -> AnalysisResult:
        """Run the Slither detector suite over a contract file."""
        try:
            slither_cls, detector_classes = self._load_slither()
        except ImportError as exc:  # pragma: no cover - environment issue
            raise ScanError(
                f"Slither is not installed in the current environment: {exc}",
                "SLITHER_UNAVAILABLE",
            ) from exc

        started = time.perf_counter()
        try:
            slither = slither_cls(
                str(contract_path),
                solc=self._resolve_solc(contract_path),
            )
        except Exception as exc:  # compilation / parsing failure
            raise ScanError(self._describe_compile_error(exc), "COMPILATION_FAILED") from exc

        # Register exactly the eligible detectors and run them.
        eligible = [
            detector
            for detector in detector_classes
            if self._impact_of(detector) in self.settings.included_impacts
        ]

        try:
            for detector in eligible:
                slither.register_detector(detector)
            raw_results = slither.run_detectors()
        except Exception as exc:  # pragma: no cover - defensive
            raise ScanError(f"Slither failed while running detectors: {exc}", "SCAN_FAILED") from exc

        findings = self._normalise(raw_results)
        findings.sort(key=self._severity_rank)

        summary = SeverityCount()
        for finding in findings:
            setattr(summary, finding.severity.value, getattr(summary, finding.severity.value) + 1)

        duration = time.perf_counter() - started

        return AnalysisResult(
            analysis_id=analysis_id,
            contract_name=contract_name,
            status=AnalysisStatus.COMPLETED,
            source_type=source_type,
            source_size_bytes=source_size_bytes,
            findings=findings,
            summary=summary,
            detectors_available=len(eligible),
            detectors_ran=len(eligible),
            scan_duration_seconds=round(duration, 3),
        )

    # ------------------------------------------------------------------
    # Compiler resolution
    # ------------------------------------------------------------------
    def _resolve_solc(self, contract_path: Path) -> str:
        """Return the solc binary to compile the contract with.

        The contract's ``pragma solidity`` statement is matched against the
        compilers installed through solc-select. When the pragma cannot be
        satisfied the configured default version is used, and finally a
        plain ``solc`` on the PATH.
        """
        required = self._pragma_version(contract_path)
        candidates = self._installed_solc_versions()

        chosen = self._pick_version(required, candidates)
        if chosen:
            path = self._solc_artifact_path(chosen)
            if path:
                return path

        # Fall back to a solc that is directly on the PATH.
        system_solc = shutil.which("solc")
        if system_solc:
            return system_solc

        return "solc"

    def _pragma_version(self, contract_path: Path) -> Optional[str]:
        """Read the ``pragma solidity`` version out of the contract."""
        try:
            source = contract_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return None

        match = re.search(
            r"pragma\s+solidity\s*[^;]*?(\d+\.\d+\.\d+)",
            source,
        )
        return match.group(1) if match else None

    def _installed_solc_versions(self) -> list[str]:
        """List the solc versions installed through solc-select."""
        try:
            from solc_select.solc_select import installed_versions
        except ImportError:
            return []

        try:
            return sorted(installed_versions())
        except Exception:
            return []

    def _solc_artifact_path(self, version: str) -> Optional[str]:
        """Return the absolute path of an installed solc binary."""
        try:
            from solc_select.solc_select import artifact_path
        except ImportError:
            return None

        try:
            # crytic-compile expects a plain string, not a Path object.
            return str(artifact_path(version))
        except Exception:
            return None

    def _pick_version(self, required: Optional[str], candidates: list[str]) -> Optional[str]:
        """Choose the installed compiler that best satisfies the pragma."""
        if not candidates:
            return None

        if not required:
            # Prefer the configured default when it is installed.
            if self.settings.solc_version in candidates:
                return self.settings.solc_version
            return candidates[-1]

        wanted = tuple(int(part) for part in required.split("."))

        # Exact match first.
        if required in candidates:
            return required

        # Same major and minor version, different patch.
        same_minor = [
            version
            for version in candidates
            if version.split(".")[:2] == required.split(".")[:2]
        ]
        if same_minor:
            return same_minor[-1]

        # Same major version, closest minor.
        same_major = [
            version
            for version in candidates
            if version.split(".")[0] == required.split(".")[0]
        ]
        if same_major:
            return same_major[-1]

        # Nothing compatible is installed; let the default try.
        if self.settings.solc_version in candidates:
            return self.settings.solc_version
        return None

    # ------------------------------------------------------------------
    # Detector helpers
    # ------------------------------------------------------------------
    def _load_slither(self):
        """Import Slither and collect every detector class it ships with.

        The ``backdoor`` example detector is excluded, mirroring Slither's
        own ``--list-detectors`` output, which skips it because it is a
        tutorial example rather than a real vulnerability class.
        """
        from slither.detectors import all_detectors
        from slither.detectors.abstract_detector import AbstractDetector
        from slither.slither import Slither

        candidates = [
            getattr(all_detectors, name)
            for name in dir(all_detectors)
            if not name.startswith("_")
        ]
        detectors = [
            candidate
            for candidate in candidates
            if inspect.isclass(candidate)
            and issubclass(candidate, AbstractDetector)
            and not self._is_abstract(candidate)
            and getattr(candidate, "ARGUMENT", "") != "backdoor"
        ]
        # De-duplicate while keeping a stable order.
        seen: set[int] = set()
        unique: list[Any] = []
        for detector in detectors:
            if id(detector) not in seen:
                seen.add(id(detector))
                unique.append(detector)

        return Slither, unique

    def _impact_of(self, detector) -> str:
        """Return the impact string of a detector class or instance.

        ``AbstractDetector.IMPACT`` is a ``DetectorClassification`` enum whose
        ``.value`` is an integer index, so the enum *name* is what carries the
        meaning (``HIGH``, ``MEDIUM``, ...). The name is title-cased so it
        matches the impact strings Slither reports on individual results.
        """
        impact = getattr(detector, "IMPACT", None)
        if impact is None:
            return ""
        name = getattr(impact, "name", None)
        if name:
            return name.title()
        return str(getattr(impact, "value", impact)).title()

    def _is_abstract(self, detector) -> bool:
        """Abstract detector bases are never executed on their own."""
        if getattr(detector, "ABSTRACT", False):
            return True
        # Only detector bases whose class name ends with AbstractDetection
        # (e.g. ShadowingAbstractDetection) are skipped by Slither's own runner.
        return detector.__name__.endswith("AbstractDetection") and getattr(detector, "ARGUMENT", "") != "shadowing-abstract"

    def _severity_rank(self, finding: SlitherFinding) -> tuple[int, str]:
        """Order findings from most to least severe."""
        order = {
            SeverityLevel.CRITICAL: 0,
            SeverityLevel.HIGH: 1,
            SeverityLevel.MEDIUM: 2,
            SeverityLevel.LOW: 3,
            SeverityLevel.INFORMATIONAL: 4,
        }
        return (order.get(finding.severity, 5), finding.detector)

    # ------------------------------------------------------------------
    # Result normalisation
    # ------------------------------------------------------------------
    def _normalise(self, raw_results: list) -> list[SlitherFinding]:
        """Convert Slither's raw output into :class:`SlitherFinding` objects."""
        findings: list[SlitherFinding] = []

        for detector_output in raw_results or []:
            for result in detector_output or []:
                finding = self._parse_result(result)
                if finding is not None:
                    findings.append(finding)

        return findings

    def _parse_result(self, result: Any) -> Optional[SlitherFinding]:
        """Parse one Slither result object/dict, tolerating API differences."""
        try:
            # Slither 0.11+ returns dicts (OrderedDict) from run_detectors().
            if isinstance(result, dict):
                return self._parse_result_dict(result)

            impact = str(getattr(result, "impact", "") or "")
            if not impact:
                return None

            severity = SLITHER_IMPACT_TO_SEVERITY.get(impact, SeverityLevel.MEDIUM)

            detector = getattr(result, "check", None)
            if detector is None:
                return None

            contract_name = "Unknown"
            contract = getattr(result, "contract", None)
            if contract is not None:
                contract_name = getattr(contract, "name", str(contract))

            function_name = None
            function = getattr(result, "function", None)
            if function is not None:
                function_name = getattr(function, "name", str(function))

            line_number = self._first_line(result)
            source_mapping = self._source_mapping(result)

            return SlitherFinding(
                finding_id=self._finding_id(detector, contract_name, function_name, line_number),
                detector=str(detector),
                impact=impact,
                severity=severity,
                confidence=str(getattr(result, "confidence", "") or ""),
                description=self._clean_description(getattr(result, "description", "") or ""),
                contract=contract_name,
                function=function_name,
                line=line_number,
                source_mapping=source_mapping,
            )
        except Exception:
            # A single malformed result must never abort the whole scan.
            traceback.print_exc()
            return None

    def _parse_result_dict(self, result: dict) -> Optional[SlitherFinding]:
        """Parse a dict-form result produced by Slither 0.11+."""
        impact = str(result.get("impact", "") or "")
        if not impact:
            return None

        severity = SLITHER_IMPACT_TO_SEVERITY.get(impact, SeverityLevel.MEDIUM)
        detector = result.get("check")
        if not detector:
            return None

        contract_name = "Unknown"
        function_name = None
        line_number = None

        for element in result.get("elements") or []:
            if not isinstance(element, dict):
                continue
            etype = element.get("type")
            if etype == "contract" and contract_name == "Unknown":
                contract_name = element.get("name") or contract_name
            elif etype == "function" and function_name is None:
                function_name = element.get("name")
                parent = element.get("type_specific_fields", {}).get("parent") or {}
                if isinstance(parent, dict) and parent.get("name"):
                    contract_name = parent.get("name")

            source_mapping = element.get("source_mapping") or {}
            if isinstance(source_mapping, dict) and line_number is None:
                lines = source_mapping.get("lines") or []
                if lines:
                    try:
                        line_number = int(lines[0])
                    except (TypeError, ValueError, IndexError):
                        pass

        return SlitherFinding(
            finding_id=self._finding_id(detector, contract_name, function_name, line_number),
            detector=str(detector),
            impact=impact,
            severity=severity,
            confidence=str(result.get("confidence", "") or ""),
            description=self._clean_description(result.get("description", "") or ""),
            contract=contract_name,
            function=function_name,
            line=line_number,
            source_mapping=str(result.get("first_markdown_element") or "") or None,
        )

    def _finding_id(self, detector: str, contract: str, function: Optional[str],
                    line: Optional[int]) -> str:
        """Build a stable identifier for a finding."""
        import hashlib

        raw = f"{detector}|{contract}|{function}|{line}"
        return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:12]

    def _first_line(self, result: Any) -> Optional[int]:
        """Best-effort extraction of the first source line of a finding."""
        node = getattr(result, "node", None)
        if node is not None:
            mapping = getattr(node, "source_mapping", None)
            lines = getattr(mapping, "lines", None) if mapping else None
            if lines:
                try:
                    return int(list(lines)[0])
                except (TypeError, ValueError, IndexError):
                    pass

        mapping = getattr(result, "source_mapping", None)
        lines = getattr(mapping, "lines", None) if mapping else None
        if lines:
            try:
                return int(list(lines)[0])
            except (TypeError, ValueError, IndexError):
                pass

        return None

    def _source_mapping(self, result: Any) -> Optional[str]:
        """Return the source mapping string for a finding, if available."""
        mapping = getattr(result, "source_mapping", None)
        if mapping is None:
            return None
        try:
            return str(mapping)
        except Exception:
            return None

    def _clean_description(self, description: str) -> str:
        """Normalise whitespace and strip Slither's markdown padding."""
        cleaned = " ".join(description.split())
        return cleaned.strip()

    # ------------------------------------------------------------------
    # Error reporting
    # ------------------------------------------------------------------
    def _describe_compile_error(self, exc: Exception) -> str:
        """Turn a Slither compilation exception into a readable message."""
        message = str(exc).strip()
        if not message:
            message = "The contract could not be compiled."

        lowered = message.lower()
        if "solc" in lowered or "compil" in lowered:
            prefix = (
                "The contract could not be compiled with solc "
                f"{self.settings.solc_version}. "
            )
        else:
            prefix = "The contract could not be parsed. "

        return f"{prefix}{message}"
