"""
analyzers/assets.py — Logo match and hotlinking analyzer stub.

Full implementation in Phase 3.
"""
from __future__ import annotations

from app.models import ScanContext, SignalResult


class AssetsAnalyzer:
    name = "assets"

    async def analyze(self, ctx: ScanContext) -> SignalResult:
        """Stub — implemented in Phase 3."""
        return SignalResult(
            name=self.name,
            score=0.0,
            available=False,
            unavailable_reason="Not yet implemented (Phase 3)",
        )
