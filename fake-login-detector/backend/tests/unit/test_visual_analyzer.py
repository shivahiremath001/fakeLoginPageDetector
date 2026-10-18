
import pytest
from PIL import Image, ImageDraw

from app.analyzers.visual import VisualAnalyzer
from app.models import PageSnapshot, ScanContext


def make_screenshot(path, background, title):
    image = Image.new("RGB", (640, 400), background)
    draw = ImageDraw.Draw(image)
    draw.rectangle((80, 50, 560, 350), outline="black", width=3)
    draw.text((110, 80), title, fill="black")
    draw.rectangle((110, 150, 500, 190), outline="black", width=2)
    draw.rectangle((110, 220, 500, 260), outline="black", width=2)
    image.save(path)
    return str(path)


@pytest.mark.asyncio
async def test_similar_screenshots_on_different_origins_are_flagged(tmp_path):
    genuine_path = make_screenshot(tmp_path / "genuine.png", "white", "Sign in")
    suspect_path = make_screenshot(tmp_path / "suspect.png", "white", "Sign in")

    ctx = ScanContext(
        suspect=PageSnapshot(
            requested_url="https://copy.example.test",
            screenshot_path=suspect_path,
        ),
        genuine=PageSnapshot(
            requested_url="https://genuine.example.test",
            screenshot_path=genuine_path,
        ),
    )

    result = await VisualAnalyzer().analyze(ctx)

    assert result.available
    assert result.score >= 0.85
    assert result.metrics["phash_distance"] == 0
    assert any(reason.code == "VISUAL_HIGH_SIMILARITY" for reason in result.reasons)


@pytest.mark.asyncio
async def test_missing_reference_screenshot_is_unavailable(tmp_path):
    suspect_path = make_screenshot(tmp_path / "suspect.png", "white", "Sign in")

    ctx = ScanContext(
        suspect=PageSnapshot(
            requested_url="https://copy.example.test",
            screenshot_path=suspect_path,
        ),
        genuine=PageSnapshot(
            requested_url="https://genuine.example.test",
            screenshot_path=str(tmp_path / "missing.png"),
        ),
    )

    result = await VisualAnalyzer().analyze(ctx)

    assert not result.available
    assert result.unavailable_reason


@pytest.mark.asyncio
async def test_same_origin_has_zero_clone_score(tmp_path):
    genuine_path = make_screenshot(tmp_path / "genuine.png", "white", "Sign in")
    suspect_path = make_screenshot(tmp_path / "suspect.png", "white", "Sign in")

    ctx = ScanContext(
        suspect=PageSnapshot(
            requested_url="https://portal.example.test/login",
            screenshot_path=suspect_path,
        ),
        genuine=PageSnapshot(
            requested_url="https://portal.example.test/home",
            screenshot_path=genuine_path,
        ),
    )

    result = await VisualAnalyzer().analyze(ctx)

    assert result.available
    assert result.score == 0.0
