"""
tests/unit/test_analyzer_base.py — Tests for the Analyzer protocol and
the run_analyzer failure wrapper.
"""
from __future__ import annotations

import pytest
from app.analyzers.base import Analyzer, run_analyzer
from app.models import ScanContext, PageSnapshot, SignalResult


class GoodAnalyzer:
    """A well-behaved analyzer that always succeeds."""
    name = "good"

    async def analyze(self, ctx: ScanContext) -> SignalResult:
        return SignalResult(name=self.name, score=0.75)


class BrokenAnalyzer:
    """An analyzer that always raises an exception."""
    name = "broken"

    async def analyze(self, ctx: ScanContext) -> SignalResult:
        raise RuntimeError("Something went wrong inside the analyzer")


class PartialAnalyzer:
    """An analyzer that returns available=False without raising."""
    name = "partial"

    async def analyze(self, ctx: ScanContext) -> SignalResult:
        return SignalResult(
            name=self.name,
            score=0.0,
            available=False,
            unavailable_reason="No dependency",
        )


def _make_ctx() -> ScanContext:
    ps = PageSnapshot(requested_url="http://example.com")
    return ScanContext(suspect=ps)


class TestAnalyzerProtocol:
    def test_good_analyzer_satisfies_protocol(self):
        assert isinstance(GoodAnalyzer(), Analyzer)

    def test_broken_analyzer_satisfies_protocol(self):
        assert isinstance(BrokenAnalyzer(), Analyzer)


class TestRunAnalyzer:
    @pytest.mark.asyncio
    async def test_good_analyzer_returns_result(self):
        ctx = _make_ctx()
        result = await run_analyzer(GoodAnalyzer(), ctx)
        assert result.available
        assert result.score == 0.75
        assert result.name == "good"

    @pytest.mark.asyncio
    async def test_broken_analyzer_never_raises(self):
        ctx = _make_ctx()
        result = await run_analyzer(BrokenAnalyzer(), ctx)
        # Must not raise; must return available=False
        assert not result.available
        assert result.score == 0.0
        assert "RuntimeError" in (result.unavailable_reason or "")

    @pytest.mark.asyncio
    async def test_partial_analyzer_passes_through(self):
        ctx = _make_ctx()
        result = await run_analyzer(PartialAnalyzer(), ctx)
        assert not result.available
        assert result.unavailable_reason == "No dependency"
