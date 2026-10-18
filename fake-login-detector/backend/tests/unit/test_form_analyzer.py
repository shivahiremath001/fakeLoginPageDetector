
import pytest

from app.analyzers.form import FormAnalyzer
from app.models import (
    Brand,
    FormInfo,
    PageSnapshot,
    ScanContext,
)


def make_form(
    *,
    action: str,
    password: bool = True,
    method: str = "post",
    cross_origin: bool = False,
    http: bool = False,
) -> FormInfo:
    return FormInfo(
        action_raw=action,
        action_resolved=action,
        action_origin=action,
        method=method,
        has_password=password,
        is_cross_origin=cross_origin,
        is_http=http,
    )


def make_context(
    suspect_url: str,
    forms: list[FormInfo],
    *,
    genuine_url: str | None = None,
    genuine_forms: list[FormInfo] | None = None,
    brand: Brand | None = None,
) -> ScanContext:
    genuine = None
    if genuine_url:
        genuine = PageSnapshot(
            requested_url=genuine_url,
            final_url=genuine_url,
            forms=genuine_forms or [],
        )

    return ScanContext(
        suspect=PageSnapshot(
            requested_url=suspect_url,
            final_url=suspect_url,
            forms=forms,
        ),
        genuine=genuine,
        brand=brand,
    )


@pytest.mark.asyncio
async def test_same_origin_password_form_is_not_flagged():
    url = "https://portal.example.com/login"
    form = make_form(
        action="https://portal.example.com/session",
    )

    result = await FormAnalyzer().analyze(
        make_context(url, [form])
    )

    assert result.available
    assert result.score == 0.0
    assert result.reasons == []


@pytest.mark.asyncio
async def test_untrusted_password_action_is_flagged_against_genuine_page():
    genuine_url = "https://portal.example.com/login"
    genuine_form = make_form(
        action="https://portal.example.com/session",
    )
    suspect_form = make_form(
        action="https://attacker.example/collect",
        cross_origin=True,
    )
    brand = Brand(
        id="portal",
        name="Example Portal",
        genuine_urls=[genuine_url],
        origins=["https://portal.example.com"],
    )

    result = await FormAnalyzer().analyze(
        make_context(
            genuine_url,
            [suspect_form],
            genuine_url=genuine_url,
            genuine_forms=[genuine_form],
            brand=brand,
        )
    )

    assert result.available
    assert result.score >= 0.90
    assert any(
        reason.code == "FORM_PASSWORD_FOREIGN_ACTION"
        for reason in result.reasons
    )


@pytest.mark.asyncio
async def test_trusted_related_origin_is_not_flagged():
    page_url = "https://portal.example.com/login"
    trusted_action = "https://auth.example.net/session"
    form = make_form(
        action=trusted_action,
        cross_origin=True,
    )
    brand = Brand(
        id="portal",
        name="Example Portal",
        genuine_urls=[page_url],
        origins=["https://portal.example.com"],
        trusted_related_origins=["https://auth.example.net"],
    )

    result = await FormAnalyzer().analyze(
        make_context(page_url, [form], brand=brand)
    )

    assert result.available
    assert result.score == 0.0
    assert result.reasons == []


@pytest.mark.asyncio
async def test_password_form_using_get_is_flagged():
    form = make_form(
        action="https://portal.example.com/login",
        method="get",
    )

    result = await FormAnalyzer().analyze(
        make_context(
            "https://portal.example.com/login",
            [form],
        )
    )

    assert result.available
    assert result.score >= 0.75
    assert any(
        reason.code == "FORM_PASSWORD_GET"
        for reason in result.reasons
    )


@pytest.mark.asyncio
async def test_password_form_using_http_is_flagged():
    form = make_form(
        action="http://portal.example.com/session",
        http=True,
    )

    result = await FormAnalyzer().analyze(
        make_context(
            "https://portal.example.com/login",
            [form],
        )
    )

    assert result.available
    assert result.score >= 0.85
    assert any(
        reason.code == "FORM_PASSWORD_HTTP"
        for reason in result.reasons
    )


@pytest.mark.asyncio
async def test_invalid_page_url_returns_unavailable():
    result = await FormAnalyzer().analyze(
        make_context("not a valid URL", [])
    )

    assert not result.available
    assert result.score == 0.0
