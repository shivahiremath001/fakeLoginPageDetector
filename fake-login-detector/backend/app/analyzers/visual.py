
"""Compare saved screenshots for visual similarity."""
from __future__ import annotations

from pathlib import Path

import imagehash
import numpy as np
from PIL import Image, ImageOps
from skimage.metrics import structural_similarity

from app.models import Reason, ScanContext, Severity, SignalResult
from app.utils.urls import origin_key


def _load_image(path: str | None) -> Image.Image | None:
    """Load a screenshot safely; return None when unavailable or invalid."""
    if not path:
        return None

    try:
        image_path = Path(path)
        if not image_path.is_file():
            return None

        with Image.open(image_path) as image:
            return ImageOps.exif_transpose(image).convert("RGB")
    except (OSError, ValueError):
        return None


def _prepare_images(
    suspect: Image.Image,
    genuine: Image.Image,
    size: tuple[int, int] = (320, 240),
) -> tuple[np.ndarray, np.ndarray]:
    """Resize screenshots to a common size and convert them to grayscale."""
    suspect_resized = suspect.resize(size, Image.Resampling.LANCZOS)
    genuine_resized = genuine.resize(size, Image.Resampling.LANCZOS)

    return (
        np.asarray(suspect_resized.convert("L")),
        np.asarray(genuine_resized.convert("L")),
    )


def _color_similarity(
    suspect: Image.Image,
    genuine: Image.Image,
    size: tuple[int, int] = (320, 240),
) -> float:
    """Compare prominent color distributions, returning a value from 0 to 1."""
    suspect_hsv = np.asarray(
        suspect.resize(size, Image.Resampling.LANCZOS).convert("HSV")
    )
    genuine_hsv = np.asarray(
        genuine.resize(size, Image.Resampling.LANCZOS).convert("HSV")
    )

    # Exclude nearly gray pixels so white backgrounds do not dominate.
    suspect_mask = suspect_hsv[:, :, 1] >= 48
    genuine_mask = genuine_hsv[:, :, 1] >= 48

    if not suspect_mask.any() and not genuine_mask.any():
        return 1.0

    if not suspect_mask.any() or not genuine_mask.any():
        return 0.0

    suspect_hist, _, _ = np.histogram2d(
        suspect_hsv[:, :, 0][suspect_mask],
        suspect_hsv[:, :, 1][suspect_mask],
        bins=(36, 8),
        range=((0, 256), (0, 256)),
    )
    genuine_hist, _, _ = np.histogram2d(
        genuine_hsv[:, :, 0][genuine_mask],
        genuine_hsv[:, :, 1][genuine_mask],
        bins=(36, 8),
        range=((0, 256), (0, 256)),
    )

    suspect_total = suspect_hist.sum()
    genuine_total = genuine_hist.sum()

    if suspect_total == 0 or genuine_total == 0:
        return 0.0

    suspect_hist /= suspect_total
    genuine_hist /= genuine_total

    similarity = np.minimum(suspect_hist, genuine_hist).sum()
    return float(np.clip(similarity, 0.0, 1.0))


class VisualAnalyzer:
    """Measure screenshot similarity and report supporting evidence."""

    name = "visual"

    async def analyze(self, ctx: ScanContext) -> SignalResult:
        if ctx.genuine is None:
            return SignalResult(
                name=self.name,
                score=0.0,
                available=False,
                unavailable_reason=(
                    "No genuine reference screenshot is available."
                ),
            )

        suspect_image = _load_image(ctx.suspect.screenshot_path)
        genuine_image = _load_image(ctx.genuine.screenshot_path)

        if suspect_image is None or genuine_image is None:
            return SignalResult(
                name=self.name,
                score=0.0,
                available=False,
                unavailable_reason=(
                    "The suspect or genuine screenshot is missing or unreadable."
                ),
            )

        suspect_url = ctx.suspect.final_url or ctx.suspect.requested_url
        genuine_url = ctx.genuine.final_url or ctx.genuine.requested_url

        suspect_origin = origin_key(suspect_url)
        genuine_origin = origin_key(genuine_url)

        if not suspect_origin or not genuine_origin:
            return SignalResult(
                name=self.name,
                score=0.0,
                available=False,
                unavailable_reason=(
                    "A page URL has no valid HTTP(S) origin."
                ),
            )

        different_origin = suspect_origin != genuine_origin

        try:
            # 1. Perceptual hash similarity.
            suspect_hash = imagehash.phash(suspect_image)
            genuine_hash = imagehash.phash(genuine_image)

            hash_distance = suspect_hash - genuine_hash
            hash_bits = len(suspect_hash.hash) ** 2

            hash_similarity = max(
                0.0,
                1.0 - hash_distance / max(hash_bits, 1),
            )

            # 2. Structural similarity.
            suspect_gray, genuine_gray = _prepare_images(
                suspect_image, genuine_image
            )

            ssim_value = float(
                structural_similarity(
                    suspect_gray,
                    genuine_gray,
                    data_range=255,
                )
            )

            ssim_normalized = float(
                np.clip((ssim_value + 1.0) / 2.0, 0.0, 1.0)
            )

            # 3. Prominent color-distribution similarity.
            color_similarity = _color_similarity(
                suspect_image, genuine_image
            )

            # First measure grayscale/structural resemblance.
            structural_similarity_score = (
                0.55 * hash_similarity
                + 0.45 * ssim_normalized
            )

            # Color mismatch reduces the structural score, but does not
            # erase all evidence. A genuine clone can change its colors.
            color_reliability = 0.35 + 0.65 * color_similarity

            adjusted_similarity = (
                structural_similarity_score * color_reliability
            )

        except (ValueError, OSError, TypeError) as exc:
            return SignalResult(
                name=self.name,
                score=0.0,
                available=False,
                unavailable_reason=(
                    f"Could not compare screenshots: {type(exc).__name__}."
                ),
            )

        # Same-origin visual resemblance is not clone evidence by itself.
        score = adjusted_similarity if different_origin else 0.0

        evidence = {
            "suspect_origin": suspect_origin,
            "genuine_origin": genuine_origin,
            "phash_distance": int(hash_distance),
            "phash_similarity": round(float(hash_similarity), 3),
            "ssim": round(ssim_value, 3),
            "ssim_normalized": round(ssim_normalized, 3),
            "structural_similarity_score": round(
                structural_similarity_score, 3
            ),
            "color_similarity": round(float(color_similarity), 3),
            "color_reliability": round(color_reliability, 3),
            "combined_similarity": round(float(adjusted_similarity), 3),
        }

        reasons: list[Reason] = []

        if different_origin and adjusted_similarity >= 0.85:
            reasons.append(
                Reason(
                    code="VISUAL_HIGH_SIMILARITY",
                    title="Screenshots look highly similar",
                    detail=(
                        "The screenshots closely resemble one another in "
                        "structure and prominent colors. Consider this "
                        "evidence alongside DOM, form, and domain signals."
                    ),
                    severity=Severity.high,
                    signal=self.name,
                    evidence=evidence,
                )
            )
        elif different_origin and adjusted_similarity >= 0.70:
            reasons.append(
                Reason(
                    code="VISUAL_MODERATE_SIMILARITY",
                    title="Screenshots share visual similarities",
                    detail=(
                        "The screenshots share visual structure or colors. "
                        "This is supporting evidence, not proof of a clone."
                    ),
                    severity=Severity.medium,
                    signal=self.name,
                    evidence=evidence,
                )
            )

        return SignalResult(
            name=self.name,
            score=max(0.0, min(1.0, float(score))),
            available=True,
            reasons=reasons,
            metrics={
                "phash_distance": int(hash_distance),
                "phash_similarity": round(float(hash_similarity), 3),
                "ssim": round(ssim_value, 3),
                "ssim_normalized": round(ssim_normalized, 3),
                "structural_similarity_score": round(
                    structural_similarity_score, 3
                ),
                "color_similarity": round(float(color_similarity), 3),
                "color_reliability": round(color_reliability, 3),
                "combined_similarity": round(float(adjusted_similarity), 3),
                "different_origin": different_origin,
                "suspect_dimensions": list(suspect_image.size),
                "genuine_dimensions": list(genuine_image.size),
                "reason_count": len(reasons),
            },
        )
