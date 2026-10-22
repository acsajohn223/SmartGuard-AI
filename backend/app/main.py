"""
SmartGuard AI - FastAPI application.

Module 1 (Contract Upload) and Module 2 (Slither Scanning) endpoints.
"""
from __future__ import annotations

import uuid
from pathlib import Path
from typing import Optional

from fastapi import BackgroundTasks, FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from app.core.config import settings
from app.core.models import AnalysisResult, AnalysisStatus, UploadReceipt
from app.modules.contract_upload import ContractUploadModule, UploadValidationError
from app.modules.slither_scanner import ScanError, SlitherScannerModule

app = FastAPI(
    title=settings.api_title,
    description="AI-Powered Smart Contract Vulnerability Detection & Risk Assessment",
    version=settings.api_version,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=list(settings.cors_origins),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

upload_module = ContractUploadModule(settings)
scanner_module = SlitherScannerModule(settings)

# In-memory store of the most recent analyses, keyed by analysis_id.
ANALYSIS_STORE: dict[str, AnalysisResult] = {}


class SourceRequest(BaseModel):
    """Body of the paste-source endpoint."""

    content: str = Field(..., description="Raw Solidity source code")
    filename: str = Field(
        default="contract.sol",
        description="Optional file name used in the report",
    )


def _run_analysis(analysis_id: str, contract_path: Path, contract_name: str,
                  source_type: str, source_size_bytes: int) -> None:
    """Background job that executes Module 2 and stores the result."""
    try:
        result = scanner_module.scan(
            analysis_id=analysis_id,
            contract_path=contract_path,
            contract_name=contract_name,
            source_type=source_type,
            source_size_bytes=source_size_bytes,
        )
    except ScanError as exc:
        result = AnalysisResult(
            analysis_id=analysis_id,
            contract_name=contract_name,
            status=AnalysisStatus.FAILED,
            source_type=source_type,
            source_size_bytes=source_size_bytes,
            error=exc.message,
            error_code=exc.code,
        )
    finally:
        # The working file is only needed while Slither reads it.
        try:
            if contract_path.exists():
                contract_path.unlink()
        except OSError:
            pass

    ANALYSIS_STORE[analysis_id] = result


@app.get("/", tags=["meta"])
async def root() -> dict:
    """Service banner."""
    return {
        "name": settings.api_title,
        "version": settings.api_version,
        "modules": ["Module 1 - Contract Upload", "Module 2 - Slither Scanning"],
        "status": "running",
    }


@app.get("/api/health", tags=["meta"])
async def health_check() -> dict:
    """Liveness probe."""
    return {"status": "healthy"}


@app.post("/api/analyze/upload", response_model=UploadReceipt, tags=["Module 1"])
async def analyze_upload(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
) -> UploadReceipt:
    """Module 1 - accept a `.sol` file, then scan it with Slither.

    Rejects payloads that are not Solidity source: wrong extension,
    empty content, or a file above the 2 MB limit.
    """
    content = await file.read()
    try:
        contract = upload_module.accept_upload(file.filename, content)
    except UploadValidationError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail={"code": exc.code, "message": exc.message},
        ) from exc

    background_tasks.add_task(
        _run_analysis,
        contract.analysis_id,
        contract.path,
        contract.contract_name,
        contract.source_type,
        contract.source_size_bytes,
    )
    return upload_module.receipt(contract)


@app.post("/api/analyze/source", response_model=UploadReceipt, tags=["Module 1"])
async def analyze_source(
    background_tasks: BackgroundTasks,
    request: SourceRequest,
) -> UploadReceipt:
    """Module 1 - accept pasted Solidity source, then scan it with Slither."""
    try:
        contract = upload_module.accept_source(request.content, request.filename)
    except UploadValidationError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail={"code": exc.code, "message": exc.message},
        ) from exc

    background_tasks.add_task(
        _run_analysis,
        contract.analysis_id,
        contract.path,
        contract.contract_name,
        contract.source_type,
        contract.source_size_bytes,
    )
    return upload_module.receipt(contract)


@app.post("/api/scan/sync", response_model=AnalysisResult, tags=["Module 2"])
async def scan_sync(request: SourceRequest) -> AnalysisResult:
    """Scan pasted source synchronously and return the full result.

    Convenience endpoint for the frontend and for scripted use.
    """
    try:
        contract = upload_module.accept_source(request.content, request.filename)
    except UploadValidationError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail={"code": exc.code, "message": exc.message},
        ) from exc

    try:
        result = scanner_module.scan(
            analysis_id=contract.analysis_id,
            contract_path=contract.path,
            contract_name=contract.contract_name,
            source_type=contract.source_type,
            source_size_bytes=contract.source_size_bytes,
        )
    except ScanError as exc:
        result = AnalysisResult(
            analysis_id=contract.analysis_id,
            contract_name=contract.contract_name,
            status=AnalysisStatus.FAILED,
            source_type=contract.source_type,
            source_size_bytes=contract.source_size_bytes,
            error=exc.message,
            error_code=exc.code,
        )
    finally:
        try:
            if contract.path.exists():
                contract.path.unlink()
        except OSError:
            pass

    ANALYSIS_STORE[result.analysis_id] = result
    return result


@app.get("/api/analysis/{analysis_id}", response_model=AnalysisResult, tags=["Module 2"])
async def get_analysis(analysis_id: str) -> AnalysisResult:
    """Poll the status and result of a previously started analysis."""
    result = ANALYSIS_STORE.get(analysis_id)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "NOT_FOUND", "message": f"No analysis with id {analysis_id}."},
        )
    return result


@app.get("/api/detectors", tags=["Module 2"])
async def list_detectors() -> dict:
    """Report which Slither detectors are registered and which are eligible."""
    try:
        _, detector_classes = scanner_module._load_slither()
    except ImportError as exc:
        raise HTTPException(
            status_code=503,
            detail={"code": "SLITHER_UNAVAILABLE", "message": str(exc)},
        ) from exc

    eligible = [
        detector.__name__
        for detector in detector_classes
        if scanner_module._impact_of(detector) in settings.included_impacts
    ]

    return {
        "total_registered": len(detector_classes),
        "eligible_count": len(eligible),
        "included_impacts": list(settings.included_impacts),
        "eligible_detectors": sorted(eligible),
    }


@app.exception_handler(UploadValidationError)
async def upload_validation_handler(_, exc: UploadValidationError) -> JSONResponse:
    """Fallback handler so the error shape is consistent everywhere."""
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": {"code": exc.code, "message": exc.message}},
    )
