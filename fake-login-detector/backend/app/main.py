"""
main.py — FastAPI application factory, lifespan, routes, and static mounts.

All routes are registered here. Heavy logic lives in orchestrator.py,
registry.py, and the individual analyzer modules.

Startup order:
  1. Load brand registry
  2. Start Playwright browser (PageFetcher.startup)
  3. Mount /artifacts and /frontend as static directories

Shutdown:
  1. Close Playwright browser (PageFetcher.shutdown)
"""
from __future__ import annotations

import asyncio
import logging
import sys
import time
import uuid

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app.cache import TTLCache
from app.config import settings
from app.fetcher import fetcher
from app.models import (
    ErrorResponse,
    QuickCheckRequest,
    QuickCheckResult,
    ScanRequest,
    ScanResult,
    Verdict,
)
from app.orchestrator import orchestrator
from app.registry import get_brands, load_brands

logger = logging.getLogger(__name__)

# In-memory stores for scan results and progress
_scan_results: TTLCache = TTLCache(ttl_seconds=3600)  # 1 hour
_scan_progress: dict[str, dict[str, Any]] = {}

# Paths
_ARTIFACTS_DIR = settings.artifacts_dir
_FRONTEND_DIR = Path(__file__).parent.parent.parent / "frontend"


# ── Lifespan ──────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown for shared resources."""
    # Startup
    logger.info("Loading brand registry…")
    load_brands()

    logger.info("Starting Playwright browser…")
    await fetcher.startup()

    logger.info("Fake Login Detector ready on %s:%d", settings.host, settings.port)
    yield

    # Shutdown
    logger.info("Shutting down Playwright browser…")
    await fetcher.shutdown()
    logger.info("Shutdown complete.")


# ── App factory ───────────────────────────────────────────────────────────────

def create_app() -> FastAPI:
    app = FastAPI(
        title="Fake Login Page Detector",
        version="0.1.0",
        description="Detects phishing clone pages by comparing them to genuine originals.",
        lifespan=lifespan,
    )

    # CORS — allow extension origins and localhost dev
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],          # Tightened in production; fine for hackathon
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    _register_routes(app)
    _mount_static(app)
    return app


def _register_routes(app: FastAPI) -> None:
    """Attach all API routes to the app."""

    # ── Health ───────────────────────────────────────────────────────────────

    @app.get("/api/health", tags=["meta"])
    async def health() -> dict:
        """
        Liveness check.

        Returns: {"status": "ok", "version": "0.1.0"}
        """
        return {"status": "ok", "version": "0.1.0"}

    # ── Brands ───────────────────────────────────────────────────────────────

    @app.get("/api/brands", tags=["meta"])
    async def brands() -> list[dict]:
        """
        Return the full brand registry.

        Used by the extension for data sync and by the UI brand selector.
        """
        return [b.model_dump() for b in get_brands()]

    # ── Scan ─────────────────────────────────────────────────────────────────

    @app.post("/api/scan", tags=["scan"], response_model=ScanResult, status_code=200)
    async def start_scan(request: ScanRequest) -> Any:
        """
        Start a full scan.

        For scans that finish within 12 s the result is returned directly (200).
        Longer scans return 202 with a scan_id for polling.

        Inputs:  ScanRequest body
        Outputs: ScanResult (200) or {"scan_id": "..."} (202)
        """
        from app.utils.urls import normalize_url

        normalized = normalize_url(request.url)
        if not normalized:
            raise HTTPException(
                status_code=422,
                detail=ErrorResponse(
                    code="INVALID_URL",
                    message=f"The URL {request.url!r} is not a valid http/https URL.",
                ).model_dump(),
            )

        request = ScanRequest(
            url=normalized,
            genuine_url=request.genuine_url,
            mode=request.mode,
        )

        start = time.monotonic()
        result = await orchestrator.scan(request)
        elapsed_ms = int((time.monotonic() - start) * 1000)
        result.duration_ms = elapsed_ms

        # Cache the result
        _scan_results.set(result.scan_id, result)
        return result

    @app.get("/api/scan/{scan_id}", tags=["scan"], response_model=ScanResult)
    async def get_scan(scan_id: str) -> Any:
        """
        Retrieve a previously completed scan by ID.

        Inputs:  scan_id path parameter
        Outputs: ScanResult or 404
        """
        result = _scan_results.get(scan_id)
        if result is None:
            raise HTTPException(
                status_code=404,
                detail=ErrorResponse(
                    code="SCAN_NOT_FOUND",
                    message=f"No scan found with id {scan_id!r}.",
                ).model_dump(),
            )
        return result

    @app.get("/api/scan/{scan_id}/progress", tags=["scan"])
    async def get_progress(scan_id: str) -> dict:
        """
        Return the current pipeline stage for a running scan.

        Inputs:  scan_id path parameter
        Outputs: {"scan_id": str, "stage": str, "done": bool}
        """
        progress = await orchestrator.get_progress(scan_id)
        return progress

    # ── Quick check (extension fast path) ────────────────────────────────────

    @app.post("/api/quick-check", tags=["scan"], response_model=QuickCheckResult)
    async def quick_check(request: QuickCheckRequest) -> Any:
        """
        Fast verdict from domain and form logic only — no browser.

        Used by the extension Tier 3 for a rapid second opinion.
        Inputs:  QuickCheckRequest body
        Outputs: QuickCheckResult
        """
        from app.utils.urls import normalize_url, origin_key, resolve_action
        from app.registry import find_brand_by_origin, match_brand
        from app.analyzers.domain import DomainAnalyzer
        from app.analyzers.form import FormAnalyzer
        from app.scoring import compute_score
        from app.models import PageSnapshot, FormInfo, ScanContext, ScanSettings

        normalized = normalize_url(request.url)
        if not normalized:
            return QuickCheckResult(verdict=Verdict.unrelated, score=0)

        origin = origin_key(normalized)
        brand = find_brand_by_origin(origin)

        # Same-origin short circuit
        if brand and (origin in brand.origins or origin in brand.trusted_related_origins):
            return QuickCheckResult(
                verdict=Verdict.genuine,
                score=0,
                brand=brand.name,
            )

        # If origin not directly in brand registry, try matching by URL / lookalike
        if not brand:
            brand = match_brand(normalized)

        # Build FormInfo objects from form_actions
        forms: list[FormInfo] = []
        for action in request.form_actions:
            resolved = resolve_action(action, normalized)
            action_orig = origin_key(resolved) if resolved else ""
            is_cross = bool(action_orig and action_orig != origin)
            is_http = resolved.lower().startswith("http://") if resolved else False
            forms.append(
                FormInfo(
                    action_raw=action,
                    action_resolved=resolved,
                    action_origin=action_orig,
                    method="post",
                    has_password=request.has_password,
                    is_cross_origin=is_cross,
                    is_http=is_http,
                )
            )

        suspect_snapshot = PageSnapshot(
            requested_url=normalized,
            final_url=normalized,
            forms=forms,
        )

        ctx = ScanContext(
            suspect=suspect_snapshot,
            genuine=None,
            brand=brand,
            settings=ScanSettings(),
        )

        domain_signal = await DomainAnalyzer().analyze(ctx)
        form_signal = await FormAnalyzer().analyze(ctx)

        scored = compute_score(
            {"domain": domain_signal, "form": form_signal},
            settings=ScanSettings(),
        )

        return QuickCheckResult(
            verdict=scored.verdict,
            score=scored.score,
            reasons=scored.reasons,
            brand=brand.name if brand else None,
        )

    # ── Reports ──────────────────────────────────────────────────────────────

    @app.get("/api/report/{scan_id}.json", tags=["report"])
    async def report_json(scan_id: str) -> Any:
        """Download the full scan result as JSON."""
        result = _scan_results.get(scan_id)
        if result is None:
            raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "message": "Scan not found."})
        return JSONResponse(
            content=result.model_dump(mode="json"),
            headers={"Content-Disposition": f'attachment; filename="scan_{scan_id}.json"'},
        )

    @app.get("/api/report/{scan_id}.pdf", tags=["report"])
    async def report_pdf(scan_id: str) -> Any:
        """Download the scan result as a PDF report (Phase 3+)."""
        result = _scan_results.get(scan_id)
        if result is None:
            raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "message": "Scan not found."})

        pdf_path = _ARTIFACTS_DIR / scan_id / "report.pdf"
        if not pdf_path.exists():
            from app.report import generate_pdf
            success = await generate_pdf(result, str(pdf_path))
            if not success or not pdf_path.exists():
                raise HTTPException(
                    status_code=500,
                    detail={"code": "PDF_FAILED", "message": "Could not generate PDF report."},
                )
        return FileResponse(
            path=str(pdf_path),
            media_type="application/pdf",
            filename=f"scan_{scan_id}.pdf",
        )


def _mount_static(app: FastAPI) -> None:
    """Mount artifact and frontend directories as static file servers."""
    _ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    app.mount(
        "/artifacts",
        StaticFiles(directory=str(_ARTIFACTS_DIR)),
        name="artifacts",
    )

    if _FRONTEND_DIR.exists():
        app.mount(
            "/",
            StaticFiles(directory=str(_FRONTEND_DIR), html=True),
            name="frontend",
        )
    else:
        logger.warning("Frontend directory not found at %s — skipping static mount.", _FRONTEND_DIR)


# ── Entry point ───────────────────────────────────────────────────────────────

app = create_app()

if __name__ == "__main__":
    import uvicorn

    logging.basicConfig(level=logging.INFO)
    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        reload=True,
        log_level=settings.log_level,
    )
