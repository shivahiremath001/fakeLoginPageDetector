"""
evidence.py — Diff heatmap generation and annotated screenshot production.

Generates:
  1. diff.png: Absolute pixel difference thresholded and alpha-blended as a red heatmap overlay.
  2. annotated_suspect.png: Suspect screenshot with red bounding boxes and threat callouts.
  3. annotated_genuine.png: Genuine screenshot with green bounding boxes around verified login elements.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Optional

import numpy as np
from PIL import Image, ImageDraw, ImageFont

from app.config import settings
from app.models import PageSnapshot

logger = logging.getLogger(__name__)

_ARTIFACTS_DIR = settings.artifacts_dir


def _safe_open_image(path: str | Path | None) -> Optional[Image.Image]:
    """Open an image safely, returning None on failure."""
    if not path:
        return None
    try:
        p = Path(path)
        if not p.is_file():
            return None
        with Image.open(p) as img:
            return img.convert("RGBA")
    except Exception as exc:
        logger.debug("Failed to open image %s: %s", path, exc)
        return None


async def build_evidence(
    scan_id: str,
    suspect: PageSnapshot,
    genuine: Optional[PageSnapshot] = None,
    action_target: Optional[str] = None,
) -> dict[str, str]:
    """
    Produce visual diffs and annotated screenshots with threat bounding boxes.

    Inputs:  scan_id, suspect snapshot, genuine snapshot, optional form action target
    Outputs: Dict mapping evidence keys to artifact URL paths:
             {"diff": "/artifacts/...", "annotated_suspect": "/artifacts/...", "annotated_genuine": "/artifacts/..."}
    """
    out_dir = _ARTIFACTS_DIR / scan_id
    out_dir.mkdir(parents=True, exist_ok=True)
    results: dict[str, str] = {}

    suspect_img = _safe_open_image(suspect.screenshot_path)

    # 1. Annotated Suspect Screenshot
    if suspect_img is not None:
        try:
            annotated = suspect_img.copy()
            draw = ImageDraw.Draw(annotated, "RGBA")

            # Draw boxes for forms and inputs
            for form in suspect.forms:
                if form.bounding_box:
                    box = form.bounding_box
                    x0, y0 = box.x, box.y
                    x1, y1 = box.x + box.width, box.y + box.height
                    # Red border for suspect login form
                    draw.rectangle([x0, y0, x1, y1], outline=(239, 68, 68, 255), width=3)

                    # Text banner
                    label = f"FORM -> {action_target or form.action_origin or 'External'}"
                    draw.rectangle([x0, max(0, y0 - 24), x0 + min(320, box.width), y0], fill=(239, 68, 68, 220))
                    draw.text((x0 + 6, max(2, y0 - 20)), label, fill=(255, 255, 255, 255))

            for item in getattr(suspect, "element_boxes", []):
                b = getattr(item, "box", None) or item
                if hasattr(b, "x") and hasattr(b, "y"):
                    draw.rectangle([b.x, b.y, b.x + b.width, b.y + b.height], outline=(239, 68, 68, 220), width=2)

            suspect_ann_path = out_dir / "annotated_suspect.png"
            annotated.save(suspect_ann_path, "PNG")
            results["annotated_suspect"] = f"/artifacts/{scan_id}/annotated_suspect.png"
        except Exception as exc:
            logger.warning("Failed to annotate suspect screenshot: %s", exc)

    # 2. Annotated Genuine Screenshot
    genuine_img = _safe_open_image(genuine.screenshot_path) if genuine else None
    if genuine_img is not None and genuine is not None:
        try:
            annotated = genuine_img.copy()
            draw = ImageDraw.Draw(annotated, "RGBA")

            for form in genuine.forms:
                if form.bounding_box:
                    box = form.bounding_box
                    x0, y0 = box.x, box.y
                    x1, y1 = box.x + box.width, box.y + box.height
                    # Green border for verified genuine login form
                    draw.rectangle([x0, y0, x1, y1], outline=(34, 197, 94, 255), width=3)
                    label = "VERIFIED GENUINE LOGIN"
                    draw.rectangle([x0, max(0, y0 - 24), x0 + 200, y0], fill=(34, 197, 94, 220))
                    draw.text((x0 + 6, max(2, y0 - 20)), label, fill=(255, 255, 255, 255))

            genuine_ann_path = out_dir / "annotated_genuine.png"
            annotated.save(genuine_ann_path, "PNG")
            results["annotated_genuine"] = f"/artifacts/{scan_id}/annotated_genuine.png"
        except Exception as exc:
            logger.warning("Failed to annotate genuine screenshot: %s", exc)

    # 3. Absolute Difference Heatmap
    if suspect_img is not None and genuine_img is not None:
        try:
            w, h = 1024, 576
            s_resized = np.array(suspect_img.convert("RGB").resize((w, h), Image.Resampling.BILINEAR), dtype=float)
            g_resized = np.array(genuine_img.convert("RGB").resize((w, h), Image.Resampling.BILINEAR), dtype=float)

            # Compute pixel difference across RGB
            diff = np.abs(s_resized - g_resized)
            gray_diff = diff.mean(axis=2)  # shape (h, w)

            # Threshold and build red heatmap mask
            mask = np.clip((gray_diff - 25.0) / 100.0, 0.0, 1.0)
            mask = mask[:, :, np.newaxis]

            # Red tint color: (239, 68, 68)
            red_tint = np.array([239.0, 68.0, 68.0])
            blended = (1.0 - 0.7 * mask) * s_resized + (0.7 * mask) * red_tint
            blended = np.clip(blended, 0, 255).astype(np.uint8)

            diff_img = Image.fromarray(blended)
            diff_path = out_dir / "diff.png"
            diff_img.save(diff_path, "PNG")
            results["diff"] = f"/artifacts/{scan_id}/diff.png"
        except Exception as exc:
            logger.warning("Failed to generate visual diff heatmap: %s", exc)

    return results
