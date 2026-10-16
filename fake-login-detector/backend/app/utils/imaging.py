"""
utils/imaging.py — Image loading, resizing, grayscale, and perceptual hash helpers.

All functions are synchronous (they are called inside asyncio.to_thread in the
visual analyzer). They never raise; they return None on failure so callers can
check availability cleanly.

Inputs:  file paths or numpy arrays
Outputs: numpy arrays, imagehash objects, or None
Failure: all functions return None on missing file, bad format, or library error.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Lazy imports — numpy and cv2 are heavy; only loaded when actually used.


def load_image_bgr(path: str | Path) -> "Optional[object]":
    """
    Load an image from disk as a NumPy BGR array (OpenCV native format).

    Inputs:  path — absolute path to a PNG or JPEG image
    Outputs: np.ndarray (H×W×3, uint8) or None on failure
    Failure: logs a warning and returns None
    """
    try:
        import cv2
        img = cv2.imread(str(path))
        if img is None:
            logger.warning("cv2.imread returned None for %s", path)
        return img
    except Exception as exc:
        logger.warning("load_image_bgr failed for %s: %s", path, exc)
        return None


def resize_to(img: "object", width: int, height: int) -> "Optional[object]":
    """
    Resize a BGR image to exactly (width, height).

    Inputs:  img — np.ndarray; width, height — target pixel dimensions
    Outputs: resized np.ndarray or None on failure
    Failure: returns None
    """
    try:
        import cv2
        return cv2.resize(img, (width, height), interpolation=cv2.INTER_LANCZOS4)
    except Exception as exc:
        logger.warning("resize_to failed: %s", exc)
        return None


def to_grayscale(img: "object") -> "Optional[object]":
    """
    Convert a BGR image to grayscale.

    Inputs:  img — np.ndarray (BGR)
    Outputs: np.ndarray (H×W, uint8) or None on failure
    Failure: returns None
    """
    try:
        import cv2
        return cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    except Exception as exc:
        logger.warning("to_grayscale failed: %s", exc)
        return None


def compute_phash(path: str | Path) -> "Optional[object]":
    """
    Compute the perceptual hash (pHash) of an image using imagehash.

    Inputs:  path — absolute path to the image file
    Outputs: imagehash.ImageHash object or None on failure
    Failure: returns None
    """
    try:
        import imagehash
        from PIL import Image
        with Image.open(str(path)) as img:
            return imagehash.phash(img)
    except Exception as exc:
        logger.warning("compute_phash failed for %s: %s", path, exc)
        return None


def phash_similarity(hash_a: "object", hash_b: "object") -> float:
    """
    Convert a Hamming distance between two pHashes to a 0–1 similarity.

    Distance 0  → similarity 1.0 (identical)
    Distance 64 → similarity 0.0 (completely different; pHash is 64 bits)

    Inputs:  two imagehash.ImageHash objects (or None)
    Outputs: float in [0.0, 1.0]; returns 0.0 if either hash is None
    Failure: returns 0.0; never raises
    """
    if hash_a is None or hash_b is None:
        return 0.0
    try:
        distance: int = hash_a - hash_b  # type: ignore[operator]
        return max(0.0, 1.0 - distance / 64.0)
    except Exception:
        return 0.0


def crop_region(img: "object", x: int, y: int, w: int, h: int) -> "Optional[object]":
    """
    Crop a rectangular region from a BGR image.

    Inputs:  img — np.ndarray; x, y, w, h — pixel coordinates and size
    Outputs: np.ndarray crop or None on failure
    Failure: returns None
    """
    try:
        return img[y : y + h, x : x + w]
    except Exception as exc:
        logger.warning("crop_region failed: %s", exc)
        return None
