"""
scoring.py — Weighted score computation, override rules, and verdict assignment.

Full implementation in Phase 3. Phase 0 provides the interface.
"""
from __future__ import annotations

from app.models import ScanResult, SignalResult, Verdict
from app.config import settings


def compute_score(signals: dict[str, SignalResult]) -> ScanResult:
    """
    Stub — implemented in Phase 3.

    Inputs:  signals — dict of analyzer name → SignalResult
    Outputs: partially populated ScanResult with score and verdict
    Failure: never raises; returns a 0-score unrelated result on error
    """
    return ScanResult(verdict=Verdict.unrelated, score=0)
