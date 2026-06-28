"""Masrek API — FastAPI application."""

from __future__ import annotations

import json
import logging
import os
from contextlib import asynccontextmanager
from collections.abc import AsyncIterator

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from urllib.parse import urlparse

from .auth import require_auth
from .database import get_db, init_db
from .models import (
    FindingResponse,
    RunDetailResponse,
    RunResponse,
    RunSummary,
    ScanRequest,
    ScopeCheckResponse,
    ScopeResponse,
)
from .models import TargetType
from .scanner import ScanRefusedError, reconcile_orphaned_runs, start_scan, start_source_scan, start_combined_scan
from .scope import SourcePathError, parse_scope, is_in_scope
from .target_validation import TargetValidationError

_logger = logging.getLogger("masrek")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    init_db()
    count = reconcile_orphaned_runs()
    if count:
        _logger.warning(
            "Reconciled %d orphaned run(s) from previous server instance", count
        )
    yield


app = FastAPI(title="Masrek API", version="0.1.0", lifespan=lifespan)

_frontend_origin = os.environ.get("FRONTEND_ORIGIN", "http://localhost:5173")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[_frontend_origin],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)


# ── Health (no auth) ─────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {"status": "ok"}


# ── Scope (read-only, no auth — no finding data exposed) ────────────────────

@app.get("/scope", response_model=ScopeResponse)
async def get_scope():
    scope = parse_scope()
    return ScopeResponse(
        allowlist=list(scope.allowlist),
        safety={
            "rate_limit_rps": scope.safety.rate_limit_rps,
            "max_scan_minutes": scope.safety.max_scan_minutes,
            "destructive_tests": scope.safety.destructive_tests,
            "auth_brute_force": scope.safety.auth_brute_force,
            "fail_gate_on": scope.safety.fail_gate_on,
        },
    )


@app.get("/scope/check", response_model=ScopeCheckResponse)
async def check_scope(url: str = Query(..., description="Target URL to check")):
    scope = parse_scope()
    in_scope = is_in_scope(url, scope)
    parsed = urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port
    host_display = f"{host}:{port}" if port else host
    return ScopeCheckResponse(
        host=host_display,
        in_scope=in_scope,
        allowed_mode="active" if in_scope else "passive",
    )


# ── Scan (auth required) ────────────────────────────────────────────────────

@app.post("/scan", status_code=202, dependencies=[Depends(require_auth)])
async def create_scan(req: ScanRequest):
    if req.target_type == TargetType.combined:
        if not req.target_url:
            raise HTTPException(
                status_code=400,
                detail="target_url is required for combined scan.",
            )
        if not req.source_path:
            raise HTTPException(
                status_code=400,
                detail="source_path is required for combined scan.",
            )
        try:
            run_id, resolved_mode = start_combined_scan(
                req.target_url, req.source_path,
                mode=req.mode, checks=req.checks,
                scan_type=req.scan_type,
            )
        except TargetValidationError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        except ScanRefusedError as exc:
            raise HTTPException(status_code=403, detail=str(exc))
        except SourcePathError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        return {
            "run_id": run_id,
            "target_type": "combined",
            "target_url": req.target_url,
            "source_path": req.source_path,
            "mode": resolved_mode,
            "status": "queued",
        }

    if req.target_type == TargetType.source:
        if not req.source_path:
            raise HTTPException(
                status_code=400,
                detail="source_path is required when target_type is 'source'.",
            )
        try:
            run_id = start_source_scan(
                req.source_path, checks=req.checks,
            )
        except SourcePathError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        return {
            "run_id": run_id,
            "target_type": "source",
            "source_path": req.source_path,
            "mode": "sast",
            "status": "queued",
        }

    if not req.target_url:
        raise HTTPException(
            status_code=400,
            detail="target_url is required when target_type is 'url'.",
        )
    try:
        run_id, resolved_mode = start_scan(
            req.target_url, req.mode, checks=req.checks,
            scan_type=req.scan_type,
        )
    except TargetValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except ScanRefusedError as exc:
        raise HTTPException(status_code=403, detail=str(exc))

    return {
        "run_id": run_id,
        "target_url": req.target_url,
        "mode": resolved_mode,
        "status": "queued",
    }


# ── Runs (auth required — findings are sensitive) ───────────────────────────

@app.get("/runs", response_model=list[RunResponse], dependencies=[Depends(require_auth)])
async def list_runs():
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM runs ORDER BY created_at DESC"
        ).fetchall()
    return [_row_to_run(r) for r in rows]


@app.get("/runs/{run_id}", response_model=RunDetailResponse, dependencies=[Depends(require_auth)])
async def get_run(run_id: str):
    with get_db() as conn:
        row = conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Run not found.")

        finding_rows = conn.execute(
            "SELECT * FROM findings WHERE run_id = ? ORDER BY "
            "CASE severity "
            "  WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
            "  WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END",
            (run_id,),
        ).fetchall()

    run = _row_to_run(row)
    findings = [
        FindingResponse(
            id=f["id"],
            severity=f["severity"],
            title=f["title"],
            category=f["category"],
            category_name=f["category_name"],
            location=f["location"],
            evidence=f["evidence"],
            verified=f["verified"],
            fix=f["fix"],
            source_tool=f["source_tool"],
            run_id=f["run_id"],
            mapping=f["mapping"] if "mapping" in f.keys() else "exact",
        )
        for f in finding_rows
    ]

    return RunDetailResponse(**run.model_dump(), findings=findings)


@app.get("/runs/{run_id}/diff", dependencies=[Depends(require_auth)])
async def get_run_diff(run_id: str):
    with get_db() as conn:
        row = conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Run not found.")

        prev = conn.execute(
            "SELECT * FROM runs WHERE target_host = ? AND created_at < ? "
            "ORDER BY created_at DESC LIMIT 1",
            (row["target_host"], row["created_at"]),
        ).fetchone()

        if not prev:
            return {
                "current_run_id": run_id,
                "previous_run_id": None,
                "message": "No previous run for this target.",
            }

        current_hashes = {
            r["dedupe_hash"]: dict(r)
            for r in conn.execute(
                "SELECT * FROM findings WHERE run_id = ?", (run_id,)
            ).fetchall()
        }
        previous_hashes = {
            r["dedupe_hash"]: dict(r)
            for r in conn.execute(
                "SELECT * FROM findings WHERE run_id = ?", (prev["id"],)
            ).fetchall()
        }

    new_keys = set(current_hashes) - set(previous_hashes)
    resolved_keys = set(previous_hashes) - set(current_hashes)
    unchanged_keys = set(current_hashes) & set(previous_hashes)

    return {
        "current_run_id": run_id,
        "previous_run_id": prev["id"],
        "new_findings": [_finding_summary(current_hashes[k]) for k in new_keys],
        "resolved_findings": [_finding_summary(previous_hashes[k]) for k in resolved_keys],
        "unchanged_count": len(unchanged_keys),
    }


# ── Helpers ───────────────────────────────────────────────────────────────────

def _row_to_run(row) -> RunResponse:
    summary = None
    if row["summary_json"]:
        summary = RunSummary(**json.loads(row["summary_json"]))
    keys = row.keys()
    selected_checks = None
    if "selected_checks" in keys and row["selected_checks"]:
        selected_checks = [c for c in row["selected_checks"].split(",") if c]
    scan_type = row["scan_type"] if "scan_type" in keys else None
    target_type = row["target_type"] if "target_type" in keys else "url"
    source_path = row["source_path"] if "source_path" in keys else None
    return RunResponse(
        run_id=row["id"],
        target_url=row["target_url"],
        target_host=row["target_host"],
        mode=row["mode"],
        status=row["status"],
        created_at=row["created_at"],
        completed_at=row["completed_at"],
        summary=summary,
        error_message=row["error_message"],
        selected_checks=selected_checks,
        scan_type=scan_type,
        target_type=target_type or "url",
        source_path=source_path,
    )


def _finding_summary(f: dict) -> dict:
    return {
        "severity": f["severity"],
        "title": f["title"],
        "category": f["category"],
        "location": f["location"],
    }
