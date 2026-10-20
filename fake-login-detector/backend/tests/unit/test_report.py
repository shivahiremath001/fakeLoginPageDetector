"""
tests/unit/test_report.py — Test PDF report generation.
"""
import os
import tempfile
import pytest

from app.models import (
    FormComparison,
    Reason,
    ScanResult,
    Severity,
    Verdict,
)
from app.report import generate_pdf


@pytest.mark.asyncio
async def test_pdf_report_generation():
    result = ScanResult(
        scan_id="test-scan-123",
        suspect_url="http://localhost:5002/login",
        genuine_url="http://localhost:5001/login",
        brand="Greenfield College",
        score=92,
        verdict=Verdict.likely_clone,
        summary="High confidence clone imitating Greenfield College and sending credentials to an external host.",
        reasons=[
            Reason(
                code="FORM_FOREIGN_ACTION",
                title="Foreign Form Destination",
                detail="Form submits passwords to http://localhost:5006/submit.",
                severity=Severity.critical,
                signal="form",
            ),
            Reason(
                code="VISUALLY_IDENTICAL",
                title="Pixel Identical Design",
                detail="Page appearance matches the genuine Greenfield portal.",
                severity=Severity.high,
                signal="visual",
            ),
        ],
        form_comparison=FormComparison(
            genuine_action="http://localhost:5001/login",
            suspect_action="http://localhost:5006/submit",
            action_host="localhost:5006",
            is_cross_origin=True,
        ),
        duration_ms=450,
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        pdf_path = os.path.join(tmpdir, "report.pdf")
        success = await generate_pdf(result, pdf_path)
        assert success is True
        assert os.path.exists(pdf_path)
        assert os.path.getsize(pdf_path) > 1000
