"""
tests/unit/test_quick_check.py — Verify the /api/quick-check endpoint behavior.
"""
import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app


@pytest.mark.asyncio
async def test_quick_check_genuine_origin():
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post(
            "/api/quick-check",
            json={
                "url": "http://localhost:5001/login",
                "form_actions": ["/login"],
                "has_password": True,
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["verdict"] == "genuine"
        assert data["score"] == 0


@pytest.mark.asyncio
async def test_quick_check_foreign_form_action():
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post(
            "/api/quick-check",
            json={
                "url": "http://localhost:5002/login",
                "form_actions": ["http://localhost:5006/submit"],
                "has_password": True,
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["score"] >= 50
        assert data["verdict"] in ("likely_clone", "suspicious")
        assert any(
            "foreign" in r["code"].lower() or "form" in r["code"].lower()
            for r in data["reasons"]
        )


@pytest.mark.asyncio
async def test_quick_check_unrelated_safe_page():
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post(
            "/api/quick-check",
            json={
                "url": "https://random-unrelated-domain.com/login",
                "form_actions": ["/login"],
                "has_password": True,
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["verdict"] in ("unrelated", "low_risk")
        assert data["score"] < 40
