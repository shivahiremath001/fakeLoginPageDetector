
"""Generate visual comparison evidence for phishing scans."""
from __future__ import annotations

from pathlib import Path

import cv2
import numpy as np

from app.config import settings

async def build_evidence(
    scan_id: str,
    suspect_path: str,
    genuine_path: str,
) -> dict[str, str]:
    """Create a red-highlighted difference image and return its artifact path."""
    suspect_file = Path(suspect_path)
    genuine_file = Path(genuine_path)

    if not suspect_file.is_file() or not genuine_file.is_file():
        return {}

    output_dir = settings.artifacts_dir / scan_id
    output_dir.mkdir(parents=True, exist_ok=True)
    diff_file = output_dir / "diff.png"

    suspect = cv2.imread(str(suspect_file))
    genuine = cv2.imread(str(genuine_file))

    if suspect is None or genuine is None:
        return {}

    # Align dimensions before comparing screenshots.
    height = min(suspect.shape[0], genuine.shape[0])
    width = min(suspect.shape[1], genuine.shape[1])

    if height == 0 or width == 0:
        return {}

    suspect = cv2.resize(suspect, (width, height))
    genuine = cv2.resize(genuine, (width, height))

    # Calculate pixel-level visual differences.
    difference = cv2.absdiff(genuine, suspect)
    gray = cv2.cvtColor(difference, cv2.COLOR_BGR2GRAY)
    gray = cv2.GaussianBlur(gray, (5, 5), 0)

    _, mask = cv2.threshold(gray, 25, 255, cv2.THRESH_BINARY)
    mask = cv2.dilate(
        mask,
        np.ones((3, 3), dtype=np.uint8),
        iterations=1,
    )

    # Overlay red on areas that differ.
    result = genuine.copy()
    red_overlay = np.zeros_like(genuine)
    red_overlay[:, :] = (0, 0, 255)

    highlighted = cv2.addWeighted(result, 0.65, red_overlay, 0.35, 0)
    result[mask > 0] = highlighted[mask > 0]

    if not cv2.imwrite(str(diff_file), result):
        return {}

    return {
        "diff": f"/artifacts/{scan_id}/diff.png"
    }
