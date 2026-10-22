"""
registry.py — Brand registry loader and brand matcher.

Loads brands.json and provides functions to look up a brand by origin key
or to score-match an unknown page against all known brands.

This module is implemented in Phase 1.
"""
from __future__ import annotations

import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Optional

from app.models import Brand

logger = logging.getLogger(__name__)

_BRANDS_FILE = Path(__file__).parent.parent / "config" / "brands.json"

# Module-level cache: loaded once at startup
_brands: list[Brand] = []


def load_brands(path: Path = _BRANDS_FILE) -> list[Brand]:
    """
    Load and parse brands.json.

    Inputs:  path — optional override for the brands file location
    Outputs: list of Brand objects
    Failure: returns [] and logs an error on file/parse errors; never raises
    """
    global _brands
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        _brands = [Brand(**entry) for entry in data.get("brands", [])]
        logger.info("Loaded %d brands from %s", len(_brands), path)
        return _brands
    except Exception as exc:
        logger.error("Failed to load brands from %s: %s", path, exc)
        _brands = []
        return []


def get_brands() -> list[Brand]:
    """Return the cached brand list, loading it if necessary."""
    if not _brands:
        load_brands()
    return _brands

def find_brand_by_origin(origin: str) -> Optional[Brand]:
    """Return a verified brand matching the given origin."""
    for brand in get_brands():
        if brand.verification_status != "verified":
            continue

        if origin in brand.origins or origin in brand.trusted_related_origins:
            return brand

    return None

# Full brand matching (score-based) will be implemented in Phase 1.
def match_brand(
    suspect_url: str,
    title: str = "",
    visible_text: str = "",
    favicon_path: Optional[str] = None,
) -> Optional[Brand]:
    """
    Score each brand and return the best match if its score >= 0.5.

    Full implementation in Phase 1.
    """
    from app.utils.urls import origin_key as _origin_key

    origin = _origin_key(suspect_url)
    direct = find_brand_by_origin(origin)
    if direct:
        return direct
    # Phase 1: add domain similarity + title + favicon + text scoring here.
    return None

def save_brands(brands: list[Brand], path: Path = _BRANDS_FILE) -> None:
    """Atomically save the brand registry and refresh the in-memory cache."""
    path.parent.mkdir(parents=True, exist_ok=True)

    data = {
        "brands": [brand.model_dump(mode="json") for brand in brands]
    }

    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=str(path.parent),
            suffix=".tmp",
            delete=False,
        ) as temp_file:
            temp_path = Path(temp_file.name)
            json.dump(data, temp_file, indent=2, ensure_ascii=False)
            temp_file.write("\n")

        os.replace(temp_path, path)

    except Exception:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)
        raise

    global _brands
    _brands = list(brands)
    logger.info("Saved %d brands to %s", len(_brands), path)
