"""
analyzers/form.py — Form action and credential-exfiltration analyzer stub.

Full implementation in Phase 1.
"""
from __future__ import annotations

from app.models import ScanContext, SignalResult


class FormAnalyzer:
    name = "form"

    async def analyze(self, ctx: ScanContext) -> SignalResult:
        """Stub — implemented in Phase 1."""
        return SignalResult(
            name=self.name,
            score=0.0,
            available=False,
            unavailable_reason="Not yet implemented (Phase 1)",
        )
