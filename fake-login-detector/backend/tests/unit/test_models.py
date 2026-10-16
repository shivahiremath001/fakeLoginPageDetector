"""
tests/unit/test_models.py — Verify that all Pydantic models import and
instantiate cleanly. This is the Phase 0 acceptance gate.
"""
from __future__ import annotations

import pytest
from app.models import (
    BoundingBox,
    Brand,
    ErrorResponse,
    FormComparison,
    FormInfo,
    PageSnapshot,
    ProgressUpdate,
    QuickCheckRequest,
    QuickCheckResult,
    Reason,
    RequestRecord,
    ScanContext,
    ScanRequest,
    ScanResult,
    ScanSettings,
    Severity,
    SignalResult,
    Verdict,
)


class TestEnums:
    def test_severity_values(self):
        assert list(Severity) == [
            Severity.info, Severity.low, Severity.medium,
            Severity.high, Severity.critical,
        ]

    def test_verdict_values(self):
        values = {v.value for v in Verdict}
        assert values == {"genuine", "low_risk", "suspicious", "likely_clone", "unrelated"}


class TestReason:
    def test_minimal_construction(self):
        r = Reason(
            code="TEST_CODE",
            title="Test Title",
            detail="One plain sentence.",
            severity=Severity.medium,
            signal="domain",
        )
        assert r.code == "TEST_CODE"
        assert r.evidence == {}

    def test_with_evidence(self):
        r = Reason(
            code="FORM_FOREIGN_ACTION",
            title="Foreign form action",
            detail="Form posts to evil.com.",
            severity=Severity.critical,
            signal="form",
            evidence={"action_url": "http://evil.com/steal"},
        )
        assert r.evidence["action_url"] == "http://evil.com/steal"


class TestSignalResult:
    def test_score_bounds(self):
        sr = SignalResult(name="domain", score=0.5)
        assert 0.0 <= sr.score <= 1.0

    def test_score_lower_bound(self):
        with pytest.raises(Exception):
            SignalResult(name="domain", score=-0.1)

    def test_score_upper_bound(self):
        with pytest.raises(Exception):
            SignalResult(name="domain", score=1.1)

    def test_unavailable(self):
        sr = SignalResult(name="domain", score=0.0, available=False, unavailable_reason="no dep")
        assert not sr.available
        assert sr.unavailable_reason == "no dep"


class TestFormInfo:
    def test_defaults(self):
        f = FormInfo()
        assert f.method == "post"
        assert not f.has_password
        assert not f.is_cross_origin

    def test_full_construction(self):
        f = FormInfo(
            action_raw="/login",
            action_resolved="http://evil.com/login",
            action_origin="http://evil.com",
            method="post",
            has_password=True,
            is_cross_origin=True,
        )
        assert f.is_cross_origin


class TestPageSnapshot:
    def test_minimal(self):
        ps = PageSnapshot(requested_url="http://example.com")
        assert ps.final_url == ""
        assert ps.forms == []
        assert not ps.is_image_only

    def test_with_load_error(self):
        ps = PageSnapshot(requested_url="http://bad.url", load_error="Connection refused")
        assert ps.load_error == "Connection refused"


class TestScanContext:
    def test_minimal(self):
        ps = PageSnapshot(requested_url="http://suspect.com")
        ctx = ScanContext(suspect=ps)
        assert ctx.genuine is None
        assert ctx.brand is None

    def test_with_brand(self):
        ps = PageSnapshot(requested_url="http://suspect.com")
        brand = Brand(id="test", name="Test Brand")
        ctx = ScanContext(suspect=ps, brand=brand)
        assert ctx.brand.name == "Test Brand"


class TestScanRequest:
    def test_whitespace_stripped(self):
        req = ScanRequest(url="  http://evil.com  ")
        assert req.url == "http://evil.com"

    def test_default_mode(self):
        from app.models import ScanMode
        req = ScanRequest(url="http://evil.com")
        assert req.mode == ScanMode.full


class TestScanResult:
    def test_defaults(self):
        r = ScanResult()
        assert 0 <= r.score <= 100
        assert r.verdict == Verdict.unrelated
        assert r.scan_id  # non-empty uuid
        assert r.created_at  # non-empty timestamp

    def test_score_bounds(self):
        with pytest.raises(Exception):
            ScanResult(score=101)
        with pytest.raises(Exception):
            ScanResult(score=-1)
