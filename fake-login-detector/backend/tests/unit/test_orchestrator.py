
import pytest

import app.orchestrator as orchestrator_module
from app.models import PageSnapshot, ScanRequest, SignalResult
from app.orchestrator import Orchestrator


@pytest.mark.asyncio
async def test_scan_runs_analyzers_and_returns_weighted_result(monkeypatch):
    """A successful scan should combine all five analyzer results."""
    async def fake_fetch(url, scan_id):
        return PageSnapshot(
            requested_url=url,
            final_url=url,
            title="Test login page",
            visible_text="Sign in to your account",
            html="<html><body>Sign in</body></html>",
        )

    async def fake_run_analyzer(analyzer, context):
        return SignalResult(
            name=analyzer.name,
            score=0.5,
            available=True,
        )

    monkeypatch.setattr(
        orchestrator_module.fetcher, "fetch", fake_fetch
    )
    monkeypatch.setattr(
        orchestrator_module, "match_brand", lambda *args, **kwargs: None
    )
    monkeypatch.setattr(
        orchestrator_module, "run_analyzer", fake_run_analyzer
    )

    service = Orchestrator()
    request = ScanRequest(
        url="https://suspect.example/login",
        genuine_url="https://genuine.example/login",
    )

    result = await service.scan(request)

    assert result.scan_id
    assert result.score == 50
    assert set(result.signals) == {
        "domain", "form", "dom", "visual", "assets"
    }
    assert all(signal.available for signal in result.signals.values())
    assert result.partial is False
    assert result.timings["suspect_capture"] >= 0
    assert result.timings["genuine_capture"] >= 0


@pytest.mark.asyncio
async def test_scan_returns_unreliable_result_when_capture_fails(monkeypatch):
    """A capture failure must not be presented as a safe result."""
    async def fake_fetch(url, scan_id):
        return PageSnapshot(
            requested_url=url,
            load_error="Test capture failure",
        )

    monkeypatch.setattr(
        orchestrator_module.fetcher, "fetch", fake_fetch
    )

    service = Orchestrator()
    request = ScanRequest(url="https://unavailable.example/login")

    result = await service.scan(request)

    assert result.partial is True
    assert result.score == 0
    assert "could not be captured" in result.summary.lower()
    assert result.verdict.value == "unrelated"
