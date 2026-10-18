
from app.models import Reason, ScanSettings, Severity, SignalResult, Verdict
from app.scoring import compute_score


def make_signal(
    name: str,
    score: float,
    available: bool = True,
) -> SignalResult:
    return SignalResult(
        name=name,
        score=score,
        available=available,
    )


def test_all_zero_scores_produce_low_risk():
    signals = {
        "visual": make_signal("visual", 0.0),
        "dom": make_signal("dom", 0.0),
        "form": make_signal("form", 0.0),
        "domain": make_signal("domain", 0.0),
        "assets": make_signal("assets", 0.0),
    }

    result = compute_score(signals)

    assert result.score == 0
    assert result.verdict == Verdict.low_risk
    assert len(result.signals) == 5


def test_high_scores_produce_likely_clone():
    signals = {
        name: make_signal(name, 1.0)
        for name in ("visual", "dom", "form", "domain", "assets")
    }

    result = compute_score(signals)

    assert result.score == 100
    assert result.verdict == Verdict.likely_clone


def test_unavailable_signal_weight_is_renormalized():
    signals = {
        "visual": make_signal("visual", 1.0),
        "dom": make_signal("dom", 0.0, available=False),
        "form": make_signal("form", 0.0),
        "domain": make_signal("domain", 0.0),
        "assets": make_signal("assets", 0.0),
    }

    result = compute_score(signals)

    assert result.signals["dom"].weight_used == 0.0
    assert result.signals["dom"].contribution == 0.0
    assert abs(
        sum(s.weight_used for s in result.signals.values()) - 1.0
    ) < 1e-9
    assert "partial evidence" in result.summary


def test_reasons_are_combined_and_sorted_by_severity():
    low = Reason(
        code="LOW_FINDING",
        title="Low finding",
        detail="A low-severity finding.",
        severity=Severity.low,
        signal="domain",
    )
    high = Reason(
        code="HIGH_FINDING",
        title="High finding",
        detail="A high-severity finding.",
        severity=Severity.high,
        signal="form",
    )

    signals = {
        "domain": SignalResult(
            name="domain", score=0.2, reasons=[low]
        ),
        "form": SignalResult(
            name="form", score=0.8, reasons=[high]
        ),
    }

    result = compute_score(signals)

    assert [reason.code for reason in result.reasons] == [
        "HIGH_FINDING",
        "LOW_FINDING",
    ]


def test_duplicate_reasons_are_removed():
    reason = Reason(
        code="SAME_FINDING",
        title="Finding",
        detail="Same evidence.",
        severity=Severity.medium,
        signal="domain",
    )

    signals = {
        "domain": SignalResult(
            name="domain", score=0.3, reasons=[reason, reason]
        )
    }

    result = compute_score(signals)

    assert len(result.reasons) == 1


def test_custom_thresholds_are_respected():
    settings = ScanSettings(
        threshold_low_risk=10,
        threshold_suspicious=50,
    )
    signals = {
        name: make_signal(name, 0.4)
        for name in ("visual", "dom", "form", "domain", "assets")
    }

    result = compute_score(signals, settings)

    assert result.score == 40
    assert result.verdict == Verdict.suspicious


def test_no_available_signals_does_not_claim_page_is_safe():
    signals = {
        "visual": make_signal("visual", 0.0, available=False),
        "dom": make_signal("dom", 0.0, available=False),
    }

    result = compute_score(signals)

    assert result.score == 0
    assert result.verdict == Verdict.unrelated
    assert "could not be assessed reliably" in result.summary


def test_genuine_page_baseline_has_zero_risk():
    """A genuine page compared with itself should not score as a clone."""
    signals = {
        "visual": make_signal("visual", 0.0),
        "dom": make_signal("dom", 0.0),
        "form": make_signal("form", 0.0),
        "domain": make_signal("domain", 0.0),
        "assets": make_signal("assets", 0.0),
    }

    result = compute_score(signals)

    assert result.score == 0
    assert result.verdict == Verdict.low_risk


def test_strong_clone_evidence_produces_high_risk():
    """Strong evidence across visual, DOM and form checks should score highly."""
    signals = {
        "visual": make_signal("visual", 1.0),
        "dom": make_signal("dom", 1.0),
        "form": make_signal("form", 0.95),
        "domain": make_signal("domain", 0.0),
        "assets": make_signal("assets", 0.0),
    }

    result = compute_score(signals)

    assert result.score >= 70
    assert result.verdict == Verdict.likely_clone


def test_unrelated_page_similarity_does_not_automatically_mean_clone():
    """Moderate similarity alone should not trigger a likely-clone verdict."""
    signals = {
        "visual": make_signal("visual", 0.3535),
        "dom": make_signal("dom", 0.2714),
        "form": make_signal("form", 0.0),
        "domain": make_signal("domain", 0.0),
        "assets": make_signal("assets", 0.0),
    }

    result = compute_score(signals)

    assert result.score < 70
    assert result.verdict != Verdict.likely_clone
