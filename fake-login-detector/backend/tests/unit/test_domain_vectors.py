"""
tests/unit/test_domain_vectors.py — Pytest parity test runner for shared/domain_test_vectors.json

Ensures Python domain logic stays in 100% parity with extension/lib/localCheck.js.
"""
from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

import pytest

from app.utils.confusables import skeleton
from app.utils.urls import origin_key

_VECTORS_PATH = Path(__file__).parent.parent.parent.parent / "shared" / "domain_test_vectors.json"


def load_vectors():
    with open(_VECTORS_PATH, "r", encoding="utf-8") as f:
        return json.load(f)["vectors"]


@pytest.mark.parametrize("vec", load_vectors(), ids=lambda v: v["id"])
def test_domain_vector(vec):
    if "expect_skeleton_match" in vec:
        s1 = skeleton(vec["label"])
        s2 = skeleton(vec["brand"])
        matches = bool(s1 and s2 and s1 == s2)
        assert matches == vec["expect_skeleton_match"], (
            f"skeleton({vec['label']!r})={s1!r} vs skeleton({vec['brand']!r})={s2!r}"
        )

    if "expect_different_origin" in vec:
        o = origin_key(vec["url"])
        is_diff = o != vec["genuine_origin"]
        assert is_diff == vec["expect_different_origin"]
