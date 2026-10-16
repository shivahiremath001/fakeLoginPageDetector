"""
analyzers/dom.py — DOM structure and text similarity analyzer stub.

Full implementation in Phase 2.
"""
from __future__ import annotations

from app.models import ScanContext, SignalResult


class DomAnalyzer:
    name = "dom"

    async def analyze(self, ctx: ScanContext) -> SignalResult:
        """Stub — implemented in Phase 2."""
        return SignalResult(
            name=self.name,
            score=0.0,
            available=False,
            unavailable_reason="Not yet implemented (Phase 2)",
        )
