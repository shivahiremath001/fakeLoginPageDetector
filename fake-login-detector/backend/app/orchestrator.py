"""
orchestrator.py — Scan pipeline orchestration stub.

Full implementation in Phase 3.
"""
from __future__ import annotations

from app.models import ScanRequest, ScanResult, Verdict


class Orchestrator:
    async def scan(self, request: ScanRequest) -> ScanResult:
        """Stub — implemented in Phase 3."""
        return ScanResult(
            suspect_url=request.url,
            verdict=Verdict.unrelated,
            score=0,
            summary="Orchestrator not yet implemented (Phase 3).",
        )

    async def get_progress(self, scan_id: str) -> dict:
        """Stub — returns empty progress."""
        return {"scan_id": scan_id, "stage": "pending", "done": False}


orchestrator = Orchestrator()
