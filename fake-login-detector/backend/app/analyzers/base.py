"""
analyzers/base.py — Analyzer protocol definition and failure-wrapping helper.

Inputs:  a ScanContext
Outputs: a SignalResult
Failure: the wrap_analyzer helper catches any exception from analyze() and
         returns available=False so one broken analyzer never fails the scan.
"""
from __future__ import annotations

import logging
import traceback
from typing import Protocol, runtime_checkable

from app.models import ScanContext, SignalResult

logger = logging.getLogger(__name__)


@runtime_checkable
class Analyzer(Protocol):
    """
    Contract every analyzer must satisfy.

    name:    Stable string identifier, e.g. "domain". Used as the dict key in
             ScanResult.signals and as the signal field in Reason objects.
    analyze: Pure async function. Receives a ScanContext, returns a SignalResult.
             Must NEVER raise — use the wrap_analyzer helper to enforce this.
    """

    name: str

    async def analyze(self, ctx: ScanContext) -> SignalResult:
        """Run the analysis and return a SignalResult."""
        ...


async def run_analyzer(analyzer: Analyzer, ctx: ScanContext) -> SignalResult:
    """
    Run one analyzer with a failure envelope.

    Inputs:  analyzer instance (must satisfy the Analyzer protocol), ScanContext
    Outputs: SignalResult — always. On exception: available=False, score=0.
    Failure: never raises; logs the full traceback at ERROR level.
    """
    try:
        result = await analyzer.analyze(ctx)
        return result
    except Exception as exc:  # noqa: BLE001
        reason_text = f"{type(exc).__name__}: {exc}"
        logger.error(
            "Analyzer %r raised an unexpected exception — marking unavailable.\n%s",
            analyzer.name,
            traceback.format_exc(),
        )
        return SignalResult(
            name=analyzer.name,
            score=0.0,
            available=False,
            unavailable_reason=reason_text,
        )
