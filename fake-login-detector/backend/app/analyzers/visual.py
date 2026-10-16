"""
analyzers/visual.py — Screenshot visual similarity analyzer stub.

Full implementation in Phase 3.
"""
from __future__ import annotations

from app.models import ScanContext, SignalResult


class VisualAnalyzer:
    name = "visual"

    async def analyze(self, ctx: ScanContext) -> SignalResult:
        """Stub — implemented in Phase 3."""
        return SignalResult(
            name=self.name,
            score=0.0,
            available=False,
            unavailable_reason="Not yet implemented (Phase 3)",
        )
