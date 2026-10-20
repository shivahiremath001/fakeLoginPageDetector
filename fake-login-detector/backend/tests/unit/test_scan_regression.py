from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from app.fetcher import fetcher
from app.main import app
from app.models import Verdict


BASE_URL = "http://localhost:5001/login"

CASES = [
    pytest.param(
        "http://localhost:5002/login",
        "http://localhost:5001/login",
        70,
        "likely_clone",
        "FORM_PASSWORD_FOREIGN_ACTION",
        id="suspicious-foreign-form-action",
    ),
    pytest.param(
        "http://localhost:5003/login",
        "http://localhost:5001/login",
        None,
        "not-likely-clone",
        None,
        id="unrelated-login-page",
    ),
    pytest.param(
        "http://localhost:5001/login",
        "http://localhost:5001/login",
        0,
        "low_risk",
        None,
        id="genuine-page-compared-with-itself",
    ),
]
@pytest.fixture(autouse=True)
async def browser_lifecycle():
    """Start and stop Playwright within each test's event loop."""
    await fetcher.startup()
    try:
        yield
    finally:
        await fetcher.shutdown()

@pytest.mark.asyncio
@pytest.mark.parametrize(
    "suspect_url,genuine_url,min_score,expected_verdict,expected_reason",
    CASES,
)
async def test_scan_regression_cases(
    suspect_url,
    genuine_url,
    min_score,
    expected_verdict,
    expected_reason,
):
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        response = await client.post(
            "/api/scan",
            json={
                "url": suspect_url,
                "genuine_url": genuine_url,
                "mode": "full",
            },
        )

    assert response.status_code == 200, response.text
    data = response.json()

    assert isinstance(data["score"], int)
    assert data["partial"] is False
    assert set(data["signals"]) == {
        "domain",
        "form",
        "dom",
        "visual",
        "assets",
    }

    if min_score is not None:
        assert data["score"] >= min_score

    if expected_verdict == "not-likely-clone":
        assert data["verdict"] != Verdict.likely_clone.value
    else:
        assert data["verdict"] == expected_verdict

    if expected_reason is not None:
        reason_codes = {reason["code"] for reason in data["reasons"]}
        assert expected_reason in reason_codes
