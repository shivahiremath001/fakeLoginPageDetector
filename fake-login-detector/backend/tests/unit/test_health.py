"""
tests/unit/test_health.py — End-to-end test of the FastAPI app: import,
startup, and /api/health endpoint response.
"""
from __future__ import annotations

import pytest
from httpx import AsyncClient, ASGITransport

from app.main import app


@pytest.mark.asyncio
async def test_health_endpoint():
    """GET /api/health must return 200 with status=ok."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/api/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert "version" in data


@pytest.mark.asyncio
async def test_brands_endpoint():
    """GET /api/brands must return a JSON array (may be empty)."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/api/brands")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)


@pytest.mark.asyncio
async def test_scan_rejects_bad_url():
    """POST /api/scan with an invalid scheme must return 422."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/api/scan", json={"url": "file:///etc/passwd"})
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_scan_missing_result():
    """GET /api/scan/{id} for an unknown id must return 404."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/api/scan/nonexistent-scan-id")
    assert resp.status_code == 404
