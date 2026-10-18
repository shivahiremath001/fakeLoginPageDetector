
import pytest

from app.analyzers.dom import DomAnalyzer
from app.models import PageSnapshot, ScanContext


def make_page(url: str, html: str, title: str = "") -> PageSnapshot:
    from bs4 import BeautifulSoup

    soup = BeautifulSoup(html, "lxml")
    return PageSnapshot(
        requested_url=url,
        final_url=url,
        html=html,
        title=title or (soup.title.get_text(strip=True) if soup.title else ""),
        visible_text=soup.get_text(" ", strip=True),
    )


@pytest.mark.asyncio
async def test_similar_page_on_different_origin_is_flagged():
    genuine_html = """
    <html><head><title>Greenfield Login</title></head>
    <body><h1>Welcome back</h1>
    <form><input name="email" type="email">
    <input name="password" type="password">
    <button>Sign in</button></form></body></html>
    """
    suspect_html = """
    <html><head><title>Greenfield Login</title></head>
    <body><h1>Welcome back</h1>
    <form><input name="email" type="email">
    <input name="password" type="password">
    <button>Sign in</button></form></body></html>
    """

    ctx = ScanContext(
        suspect=make_page("https://greenfieId-example.test/login", suspect_html),
        genuine=make_page("https://portal.greenfield.test/login", genuine_html),
    )

    result = await DomAnalyzer().analyze(ctx)

    assert result.available
    assert result.score >= 0.75
    assert any(reason.code == "DOM_HIGH_PAGE_SIMILARITY" for reason in result.reasons)


@pytest.mark.asyncio
async def test_same_origin_does_not_receive_clone_score():
    html = """
    <html><head><title>Account</title></head>
    <body><h1>Account login</h1><form><input type="password"></form></body></html>
    """
    ctx = ScanContext(
        suspect=make_page("https://portal.example.test/login", html),
        genuine=make_page("https://portal.example.test/home", html),
    )

    result = await DomAnalyzer().analyze(ctx)

    assert result.available
    assert result.score == 0.0
    assert result.metrics["different_origin"] is False


@pytest.mark.asyncio
async def test_unrelated_page_has_lower_similarity():
    genuine = """
    <html><head><title>Greenfield Login</title></head>
    <body><h1>Welcome back</h1><form><input type="password"></form></body></html>
    """
    suspect = """
    <html><head><title>Weather Forecast</title></head>
    <body><h1>Today's weather</h1><p>Sunny with light winds.</p></body></html>
    """
    ctx = ScanContext(
        suspect=make_page("https://other.example.test/weather", suspect),
        genuine=make_page("https://portal.greenfield.test/login", genuine),
    )

    result = await DomAnalyzer().analyze(ctx)

    assert result.available
    assert result.score < 0.75


@pytest.mark.asyncio
async def test_missing_genuine_reference_is_unavailable():
    ctx = ScanContext(
        suspect=make_page(
            "https://example.test/login",
            "<html><body><h1>Login</h1></body></html>",
        ),
        genuine=None,
    )

    result = await DomAnalyzer().analyze(ctx)

    assert not result.available
    assert result.unavailable_reason


@pytest.mark.asyncio
async def test_missing_html_is_unavailable():
    ctx = ScanContext(
        suspect=PageSnapshot(requested_url="https://suspect.test"),
        genuine=PageSnapshot(requested_url="https://genuine.test", html="<html>Reference</html>"),
    )

    result = await DomAnalyzer().analyze(ctx)

    assert not result.available
    assert result.unavailable_reason
