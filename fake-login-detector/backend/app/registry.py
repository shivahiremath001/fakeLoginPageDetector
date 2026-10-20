"""
registry.py — Brand registry loader and brand matcher.

Loads brands.json and provides functions to look up a brand by origin key
or to score-match an unknown page against all known brands.

This module is implemented in Phase 1.
"""
from __future__ import annotations

import json
import logging
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
    """
    Return the Brand whose origins list contains the given origin key.

    Inputs:  origin — "host:port" string (from origin_key())
    Outputs: Brand or None
    Failure: returns None; never raises
    """
    for brand in get_brands():
        if origin in brand.origins or origin in brand.trusted_related_origins:
            return brand
    return None


def match_brand(
    suspect_url: str,
    title: str = "",
    visible_text: str = "",
    favicon_path: Optional[str] = None,
) -> Optional[Brand]:
    """
    Score each brand and return the best match if its score >= 0.5.
    """
    from urllib.parse import urlparse
    from app.utils.urls import origin_key as _origin_key
    from app.utils.confusables import skeleton

    origin = _origin_key(suspect_url)
    direct = find_brand_by_origin(origin)
    if direct:
        return direct

    # Check hostname & port
    parsed = urlparse(suspect_url if "://" in suspect_url else f"http://{suspect_url}")
    host = (parsed.hostname or "").lower()
    labels = host.split(".")

    best_brand: Optional[Brand] = None
    best_score = 0.0

    for brand in get_brands():
        score = 0.0

        # Check local test aliases
        if host in [a.lower() for a in brand.aliases_for_local_testing]:
            return brand

        # Domain lookalike / skeleton matching
        label_skeletons = [skeleton(lbl) for lbl in labels if lbl]
        for protected in brand.lookalike_labels:
            p_skel = skeleton(protected)
            if not p_skel:
                continue
            for l_skel in label_skeletons:
                if l_skel == p_skel:
                    score += 0.5
                    break
                elif p_skel in l_skel or l_skel in p_skel:
                    score += 0.3
                    break

        # Title keywords matching
        if title:
            title_lower = title.lower()
            keyword_hits = sum(1 for kw in brand.title_keywords if kw.lower() in title_lower)
            if brand.title_keywords:
                score += 0.3 * (keyword_hits / len(brand.title_keywords))
        else:
            # Check keywords in URL path if no title
            path_lower = (parsed.path or "").lower()
            keyword_hits = sum(1 for kw in brand.title_keywords if kw.lower() in path_lower)
            if keyword_hits > 0:
                score += 0.2

        if score > best_score:
            best_score = score
            best_brand = brand

    if best_score >= 0.4:
        return best_brand

    return None

