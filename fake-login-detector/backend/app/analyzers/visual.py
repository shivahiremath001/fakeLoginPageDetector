
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

    suspect_gray = np.asarray(suspect_resized.convert("L"))
    genuine_gray = np.asarray(genuine_resized.convert("L"))

    return suspect_gray, genuine_gray


class VisualAnalyzer:
    """Measure screenshot similarity and report supporting evidence."""

    name = "visual"

    async def analyze(self, ctx: ScanContext) -> SignalResult:
        if ctx.genuine is None:
            return SignalResult(
                name=self.name,
                score=0.0,
                available=False,
                unavailable_reason="No genuine reference screenshot is available.",
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

        # Compare normalized origins, not full URLs or their paths.
        suspect_origin = origin_key(suspect_url)
        genuine_origin = origin_key(genuine_url)

        if not suspect_origin or not genuine_origin:
            return SignalResult(
                name=self.name,
                score=0.0,
                available=False,
                unavailable_reason="A page URL has no valid HTTP(S) origin.",
            )

        different_origin = suspect_origin != genuine_origin

        try:
            suspect_hash = imagehash.phash(suspect_image)
            genuine_hash = imagehash.phash(genuine_image)

            hash_distance = suspect_hash - genuine_hash
            hash_bits = len(suspect_hash.hash) ** 2
            hash_similarity = max(
                0.0, 1.0 - (hash_distance / max(hash_bits, 1))
            )

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

            # Normalize SSIM from [-1, 1] to [0, 1].
            ssim_normalized = max(
                0.0,
                min(1.0, (ssim_value + 1.0) / 2.0),
            )

            combined_similarity = (
                0.55 * hash_similarity
                + 0.45 * ssim_normalized
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

        # Similar screenshots on the same origin are not clone evidence.
        score = combined_similarity if different_origin else 0.0
        reasons: list[Reason] = []

        evidence = {
            "suspect_origin": suspect_origin,
            "genuine_origin": genuine_origin,
            "phash_distance": int(hash_distance),
            "phash_similarity": round(float(hash_similarity), 3),
            "ssim": round(ssim_value, 3),
            "ssim_normalized": round(ssim_normalized, 3),
            "combined_similarity": round(float(combined_similarity), 3),
        }

        if different_origin and combined_similarity >= 0.85:
            reasons.append(
                Reason(
                    code="VISUAL_HIGH_SIMILARITY",
                    title="Screenshots look highly similar",
                    detail=(
                        "The suspect screenshot closely resembles the genuine "
                        "reference. Shared templates can also look similar, so "
                        "consider this finding alongside other evidence."
                    ),
                    severity=Severity.high,
                    signal=self.name,
                    evidence=evidence,
                )
            )

        elif different_origin and combined_similarity >= 0.70:
            reasons.append(
                Reason(
                    code="VISUAL_MODERATE_SIMILARITY",
                    title="Screenshots share visual similarities",
                    detail=(
                        "The screenshots have similar visual structure or "
                        "perceptual hashes. This alone does not establish that "
                        "the suspect page is malicious."
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
                "combined_similarity": round(float(combined_similarity), 3),
                "different_origin": different_origin,
                "suspect_dimensions": list(suspect_image.size),
                "genuine_dimensions": list(genuine_image.size),
                "reason_count": len(reasons),
            },
        )
