
from __future__ import annotations

import pytest

from app.analyzers.domain import DomainAnalyzer
from app.models import Brand, PageSnapshot, ScanContext, ScanSettings


def make_context(
    url: str,
    *,
    brand: Brand | None = None,
    settings: ScanSettings | None = None,
) -> ScanContext:
    return ScanContext(
        suspect=PageSnapshot(
            requested_url=url,
            final_url=url,
        ),
        brand=brand,
        settings=settings or ScanSettings(),
    )


@pytest.fixture
def paypal_brand() -> Brand:
    return Brand(
        id="paypal",
        name="PayPal",
        genuine_urls=["https://paypal.com/"],
        origins=["https://paypal.com"],
    )


@pytest.mark.asyncio
async def test_genuine_brand_domain_has_no_domain_warning(paypal_brand):
    result = await DomainAnalyzer().analyze(
        make_context("https://paypal.com/login", brand=paypal_brand)
    )

    assert result.available
    assert result.score == 0.0
    assert result.reasons == []


@pytest.mark.asyncio
async def test_lookalike_brand_domain_is_detected(paypal_brand):
    result = await DomainAnalyzer().analyze(
        make_context("https://paypa1.com/login", brand=paypal_brand)
    )

    assert result.available
    assert result.score >= 0.80
    assert any(
        reason.code == "DOMAIN_CONFUSABLE_BRAND"
        for reason in result.reasons
    )


@pytest.mark.asyncio
async def test_brand_inside_another_domain_is_flagged(paypal_brand):
    result = await DomainAnalyzer().analyze(
        make_context(
            "https://paypal.com.attacker.example/login",
            brand=paypal_brand,
        )
    )

    assert result.available
    assert result.score > 0.0
    assert result.reasons


@pytest.mark.asyncio
async def test_url_userinfo_trick_is_detected():
    result = await DomainAnalyzer().analyze(
        make_context("https://trusted.example@attacker.example/login")
    )

    assert result.available
    assert any(
        reason.code == "DOMAIN_USERINFO_TRICK"
        for reason in result.reasons
    )


@pytest.mark.asyncio
async def test_risky_tld_uses_configured_settings():
    settings = ScanSettings(risky_tlds=["zip"])

    result = await DomainAnalyzer().analyze(
        make_context("https://account-login.zip", settings=settings)
    )

    assert result.available
    assert any(
        reason.code == "DOMAIN_RISKY_TLD"
        for reason in result.reasons
    )


@pytest.mark.asyncio
async def test_invalid_url_returns_unavailable_result():
    result = await DomainAnalyzer().analyze(
        make_context("not a valid URL")
    )

    assert not result.available
    assert result.score == 0.0
    assert result.unavailable_reason
