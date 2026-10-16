"""
tests/unit/test_utils_confusables.py — Unit tests for skeleton() and char_diff().
"""
from __future__ import annotations

import pytest
from app.utils.confusables import char_diff, skeleton


class TestSkeleton:
    """Test that skeleton() correctly normalizes visually similar strings."""

    # Digit substitutions
    def test_zero_to_o(self):
        assert skeleton("c0llege") == skeleton("college")

    def test_one_to_l(self):
        assert skeleton("port1l") == skeleton("portll")

    def test_three_to_e(self):
        assert skeleton("3vil") == skeleton("evil")

    def test_five_to_s(self):
        assert skeleton("5ecure") == skeleton("secure")

    # Multi-character substitutions
    def test_rn_to_m(self):
        assert skeleton("rnicrosoft") == skeleton("microsoft")

    def test_rn_to_m_with_space_is_still_normalized(self):
        # skeleton() strips non-alpha characters including spaces
        # so "rnicrosof t" → "microsoft" as well (expected behavior)
        assert skeleton("rnicrosof t") == skeleton("microsoft")

    def test_vv_to_w(self):
        assert skeleton("vvebmail") == skeleton("webmail")

    def test_cl_to_d(self):
        assert skeleton("clownloaclcl") == skeleton("clownloadd")  # partial

    # Cyrillic lookalikes
    def test_cyrillic_a(self):
        # Cyrillic а (U+0430) should map same as Latin a
        assert skeleton("\u0430ccount") == skeleton("account")

    def test_cyrillic_e(self):
        assert skeleton("coll\u0435ge") == skeleton("college")

    def test_cyrillic_o(self):
        assert skeleton("c\u043fllege") != skeleton("college")  # п ≠ o — different char

    def test_cyrillic_o_correct(self):
        assert skeleton("c\u043ellege") == skeleton("college")  # о (U+043E) → o

    # Greek lookalikes
    def test_greek_alpha(self):
        assert skeleton("\u03b1ccount") == skeleton("account")

    def test_greek_omicron(self):
        assert skeleton("p\u03bfrtal") == skeleton("portal")

    # Hyphens and non-alpha stripped
    def test_hyphens_stripped(self):
        s = skeleton("college-portal")
        assert "-" not in s

    def test_digits_stripped_after_sub(self):
        # digit 9 has no leet sub → stripped
        s = skeleton("college9")
        assert "9" not in s

    # Same-origin short circuit
    def test_identical_returns_same(self):
        assert skeleton("college") == skeleton("college")

    # Edge cases
    def test_empty_string(self):
        assert skeleton("") == ""

    def test_already_clean(self):
        assert skeleton("portal") == "portal"

    # Punycode — idna decoding
    def test_punycode_label(self):
        # xn--nxasmq6b is the punycode for a Greek word; skeleton should handle it
        result = skeleton("xn--nxasmq6b")
        assert isinstance(result, str)  # must not raise

    # Brand protection: ensure lookalike skeletons match genuine skeletons
    def test_lookalike_matches_brand(self):
        """c0llege, с0llege, and college should all produce the same skeleton."""
        brand = skeleton("college")
        variants = ["c0llege", "c\u043ellege", "col1ege"]
        for v in variants:
            assert skeleton(v) == brand, f"skeleton({v!r}) != {brand!r}"


class TestCharDiff:
    def test_identical(self):
        diff = char_diff("college", "college")
        assert all(d["status"] == "match" for d in diff)

    def test_substitution(self):
        diff = char_diff("c0llege", "college")
        statuses = [d["status"] for d in diff]
        assert "substituted" in statuses or "extra" in statuses

    def test_empty_inputs(self):
        assert char_diff("", "") == []
        assert char_diff("", "college") == []
        assert char_diff("college", "") == []

    def test_returns_list_of_dicts(self):
        diff = char_diff("college", "college")
        assert isinstance(diff, list)
        for item in diff:
            assert "char" in item
            assert "status" in item
