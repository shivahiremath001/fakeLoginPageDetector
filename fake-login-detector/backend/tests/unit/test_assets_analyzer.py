
import pytest

from app.analyzers.assets import AssetsAnalyzer
from app.models import PageSnapshot, RequestRecord, ScanContext


def request(url: str, resource_type: str = "image") -> RequestRecord:
    from app.utils.urls import origin_key

    return RequestRecord(
        url=url,
        method="GET",
        resource_type=resource_type,
        origin=origin_key(url),
    )


@pytest.mark.asyncio
async def test_shared_image_asset_is_detected():
    genuine = PageSnapshot(
        requested_url="https://portal.example.test/login",
        final_url="https://portal.example.test/login",
        requests=[
            request("https://cdn.example.test/images/logo.png"),
            request("https://cdn.example.test/styles/site.css", "stylesheet"),
        ],
    )
    suspect = PageSnapshot(
        requested_url="https://copy.example.test/login",
        final_url="https://copy.example.test/login",
        requests=[
            request("https://cdn.example.test/images/logo.png"),
            request("https://other.example.test/styles/copy.css", "stylesheet"),
        ],
    )

    result = await AssetsAnalyzer().analyze(
        ScanContext(suspect=suspect, genuine=genuine)
    )

    assert result.available
    assert result.metrics["shared_asset_count"] == 1
    assert any(r.code == "ASSET_SHARED_RESOURCE" for r in result.reasons)


@pytest.mark.asyncio
async def test_unrelated_assets_have_no_shared_asset_evidence():
    genuine = PageSnapshot(
        requested_url="https://portal.example.test/login",
        requests=[request("https://portal.example.test/images/logo.png")],
    )
    suspect = PageSnapshot(
        requested_url="https://copy.example.test/login",
        requests=[request("https://copy.example.test/images/banner.png")],
    )

    result = await AssetsAnalyzer().analyze(
        ScanContext(suspect=suspect, genuine=genuine)
    )

    assert result.available
    assert result.metrics["shared_asset_count"] == 0
    assert result.score == 0.0


@pytest.mark.asyncio
async def test_missing_genuine_page_is_unavailable():
    suspect = PageSnapshot(
        requested_url="https://copy.example.test/login",
        requests=[request("https://copy.example.test/logo.png")],
    )

    result = await AssetsAnalyzer().analyze(ScanContext(suspect=suspect))

    assert not result.available
    assert result.unavailable_reason


@pytest.mark.asyncio
async def test_common_third_party_assets_are_not_strong_evidence():
    genuine = PageSnapshot(
        requested_url="https://portal.example.test/login",
        requests=[
            request("https://fonts.googleapis.com/css?family=Roboto", "stylesheet"),
        ],
    )
    suspect = PageSnapshot(
        requested_url="https://copy.example.test/login",
        requests=[
            request("https://fonts.googleapis.com/css?family=Roboto", "stylesheet"),
        ],
    )

    result = await AssetsAnalyzer().analyze(
        ScanContext(suspect=suspect, genuine=genuine)
    )

    assert result.available
    assert result.score == 0.0
    assert result.metrics["shared_asset_count"] == 0
