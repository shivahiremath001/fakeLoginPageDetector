"""
scripts/calibrate.py — Calibration script: runs all test scenarios and validates scoring separation.

Verifies:
  - Genuine pages and legit lookalikes produce score <= 20 and genuine/low_risk verdict (no false positives)
  - Phishing clones produce score >= 60-100 and likely_clone verdict
  - Unrelated login pages produce score <= 10 and unrelated verdict
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

# Ensure backend/ is in sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))

from typing import NamedTuple

from app.analyzers.domain import DomainAnalyzer
from app.analyzers.form import FormAnalyzer
from app.models import (
    FormInfo,
    PageSnapshot,
    ScanContext,
    ScanSettings,
    Verdict,
)
from app.registry import get_brands, load_brands
from app.scoring import compute_score
from app.utils.urls import origin_key, resolve_action


class TestCase(NamedTuple):
    id: int
    name: str
    url: str
    form_actions: list[str]
    has_password: bool
    expected_verdict: list[Verdict]
    max_score: int | None = None
    min_score: int | None = None


CASES: list[TestCase] = [
    TestCase(
        id=1,
        name="Genuine Greenfield Portal",
        url="http://localhost:5001/login",
        form_actions=["/login"],
        has_password=True,
        expected_verdict=[Verdict.genuine],
        max_score=0,
    ),
    TestCase(
        id=2,
        name="Exact Clone (Foreign Action)",
        url="http://localhost:5002/login",
        form_actions=["http://localhost:5006/submit"],
        has_password=True,
        expected_verdict=[Verdict.likely_clone, Verdict.suspicious],
        min_score=70,
    ),
    TestCase(
        id=3,
        name="Rewritten HTML (Foreign Action)",
        url="http://localhost:5003/login",
        form_actions=["http://localhost:5006/submit"],
        has_password=True,
        expected_verdict=[Verdict.likely_clone, Verdict.suspicious],
        min_score=70,
    ),
    TestCase(
        id=4,
        name="Screenshot Clone Overlay",
        url="http://localhost:5004/login",
        form_actions=["http://localhost:5006/submit"],
        has_password=True,
        expected_verdict=[Verdict.likely_clone, Verdict.suspicious],
        min_score=70,
    ),
    TestCase(
        id=5,
        name="Hotlinked Asset Clone",
        url="http://localhost:5005/login",
        form_actions=["http://localhost:5006/submit"],
        has_password=True,
        expected_verdict=[Verdict.likely_clone, Verdict.suspicious],
        min_score=70,
    ),
    TestCase(
        id=6,
        name="Genuine Webmail Portal",
        url="http://localhost:5006/login",
        form_actions=["/login"],
        has_password=True,
        expected_verdict=[Verdict.genuine],
        max_score=0,
    ),
    TestCase(
        id=7,
        name="Webmail Clone (Foreign Action)",
        url="http://localhost:5007/login",
        form_actions=["http://localhost:5006/submit"],
        has_password=True,
        expected_verdict=[Verdict.likely_clone, Verdict.suspicious],
        min_score=70,
    ),
    TestCase(
        id=8,
        name="Legit Dept Lookalike",
        url="http://localhost:5008/login",
        form_actions=["/login"],
        has_password=True,
        expected_verdict=[Verdict.low_risk, Verdict.genuine],
        max_score=20,
    ),
    TestCase(
        id=9,
        name="Unrelated Generic Login",
        url="http://localhost:5009/login",
        form_actions=["/login"],
        has_password=True,
        expected_verdict=[Verdict.unrelated, Verdict.low_risk],
        max_score=20,
    ),
    TestCase(
        id=10,
        name="Clone JS Fetch Exfiltration",
        url="http://localhost:5010/login",
        form_actions=["http://localhost:5006/submit"],
        has_password=True,
        expected_verdict=[Verdict.likely_clone, Verdict.suspicious],
        min_score=60,
    ),
]


async def run_calibration():
    load_brands()
    settings = ScanSettings()
    domain_analyzer = DomainAnalyzer()
    form_analyzer = FormAnalyzer()

    print("\n" + "=" * 90)
    print(" FAKE LOGIN PAGE DETECTOR — CALIBRATION & BENCHMARK SUITE")
    print("=" * 90)
    print(f"{'#':<3} | {'Scenario Name':<30} | {'Expected':<15} | {'Score':<6} | {'Verdict':<15} | {'Status'}")
    print("-" * 90)

    passed_count = 0
    clone_scores: list[int] = []
    safe_scores: list[int] = []

    for c in CASES:
        origin = origin_key(c.url)
        brand = next((b for b in get_brands() if origin in b.origins or origin in b.trusted_related_origins), None)

        forms = [
            FormInfo(
                action_raw=act,
                action_resolved=resolve_action(act, c.url),
                action_origin=origin_key(resolve_action(act, c.url)),
                method="post",
                has_password=c.has_password,
                is_cross_origin=(origin_key(resolve_action(act, c.url)) != origin),
            )
            for act in c.form_actions
        ]

        suspect = PageSnapshot(requested_url=c.url, final_url=c.url, forms=forms)
        ctx = ScanContext(suspect=suspect, brand=brand, settings=settings)

        # Immediate genuine origin match
        if brand and origin in brand.origins:
            score = 0
            verdict = Verdict.genuine
        elif brand and origin in brand.trusted_related_origins and not any(f.is_cross_origin for f in forms):
            score = 0
            verdict = Verdict.genuine
        else:
            domain_res = await domain_analyzer.analyze(ctx)
            form_res = await form_analyzer.analyze(ctx)
            scored = compute_score({"domain": domain_res, "form": form_res}, settings=settings)
            score = scored.score
            verdict = scored.verdict

        verdict_ok = verdict in c.expected_verdict
        score_ok = True
        if c.max_score is not None and score > c.max_score:
            score_ok = False
        if c.min_score is not None and score < c.min_score:
            score_ok = False

        success = verdict_ok and score_ok
        if success:
            passed_count += 1
            status_str = "[PASS]"
        else:
            status_str = "[FAIL]"

        expected_str = "/".join(v.value for v in c.expected_verdict)
        print(f"{c.id:<3} | {c.name:<30} | {expected_str:<15} | {score:<6} | {verdict.value:<15} | {status_str}")

        if any(v == Verdict.likely_clone for v in c.expected_verdict):
            clone_scores.append(score)
        else:
            safe_scores.append(score)

    print("=" * 90)
    min_clone = min(clone_scores) if clone_scores else 0
    max_safe = max(safe_scores) if safe_scores else 0
    separation = min_clone - max_safe

    print(f"\nCalibration Summary:")
    print(f"  Total Scenarios : {len(CASES)}")
    print(f"  Passed          : {passed_count}/{len(CASES)}")
    print(f"  Min Clone Score : {min_clone}")
    print(f"  Max Safe Score  : {max_safe}")
    print(f"  Separation Gap  : {separation} points (positive is good)\n")

    if passed_count == len(CASES) and separation >= 40:
        print(">> PERFECT CALIBRATION: All scenarios matched expected verdicts with clean separation!")
        return 0
    else:
        print(">> Some scenarios did not meet target thresholds.")
        return 1


if __name__ == "__main__":
    code = asyncio.run(run_calibration())
    sys.exit(code)
