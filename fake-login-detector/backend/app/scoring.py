
from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from app.models import (
    Reason,
    ScanResult,
    ScanSettings,
    SignalResult,
    Verdict,
)


def _reason_key(reason: Reason) -> Tuple[str, str, str]:
    """Build a stable key for deduplicating reasons."""
    return (
        str(getattr(reason, "code", "")),
        str(getattr(reason, "title", "")),
        str(getattr(reason, "description", "")),
    )


def _severity_value(reason: Reason) -> int:
    """Convert a reason's severity into a sortable numeric value."""
    severity = getattr(reason, "severity", 0)

    if isinstance(severity, (int, float)):
        return int(severity)

    severity_map = {
        "critical": 5,
        "high": 4,
        "medium": 3,
        "low": 2,
        "info": 1,
        "informational": 1,
    }

    return severity_map.get(str(severity).lower(), 0)


def _combine_reasons(
    signals: Dict[str, SignalResult],
) -> List[Reason]:
    """Combine reasons from all signals, remove duplicates, and sort."""
    unique_reasons: Dict[Tuple[str, str, str], Reason] = {}

    for signal in signals.values():
        for reason in signal.reasons:
            key = _reason_key(reason)

            existing = unique_reasons.get(key)
            if existing is None or _severity_value(reason) > _severity_value(existing):
                unique_reasons[key] = reason

    return sorted(
        unique_reasons.values(),
        key=lambda reason: (
            -_severity_value(reason),
            str(getattr(reason, "code", "")),
            str(getattr(reason, "title", "")),
        ),
    )


def compute_score(
    signals: Dict[str, SignalResult],
    settings: Optional[ScanSettings] = None,
) -> ScanResult:
    """
    Calculate an overall clone-risk score from available analyzer signals.

    Signal scores are expected to be normalized between 0.0 and 1.0.
    Unavailable signals do not contribute to the score. The remaining
    signal weights are normalized so their total contribution remains
    comparable when one or more analyzers are unavailable.
    """
    config = settings or ScanSettings()

    configured_weights = getattr(config, "weights", {}) or {}

    # Default weights are used only when settings do not provide a weight
    # for a signal. Adjust these defaults to match your ScanSettings model.
    default_weights = {
        "visual": 0.30,
        "dom": 0.25,
        "form": 0.25,
        "domain": 0.10,
        "assets": 0.10,
    }

    available_signals: Dict[str, SignalResult] = {}
    weights: Dict[str, float] = {}

    for name, signal in signals.items():
        if not signal.available:
            continue

        available_signals[name] = signal

        configured_weight = configured_weights.get(
            name,
            default_weights.get(name, 0.0),
        )

        try:
            weight = max(0.0, float(configured_weight))
        except (TypeError, ValueError):
            weight = 0.0

        weights[name] = weight

    total_weight = sum(weights.values())

    # Prepare independent copies of the signal results with their
    # effective weights and score contributions.
    scored_signals: Dict[str, SignalResult] = {}

    if total_weight > 0:
        for name, signal in signals.items():
            if name not in available_signals:
                scored_signals[name] = signal.model_copy(
                    update={
                        "weight_used": 0.0,
                        "contribution": 0.0,
                    }
                )
                continue

            normalized_weight = weights[name] / total_weight
            normalized_score = max(0.0, min(1.0, float(signal.score)))
            contribution = normalized_score * normalized_weight * 100.0

            scored_signals[name] = signal.model_copy(
                update={
                    "weight_used": normalized_weight,
                    "contribution": contribution,
                }
            )
    else:
        for name, signal in signals.items():
            scored_signals[name] = signal.model_copy(
                update={
                    "weight_used": 0.0,
                    "contribution": 0.0,
                }
            )

    score = 0

    if total_weight > 0:
        score = round(
            sum(
                max(0.0, min(1.0, float(signal.score)))
                * weights[name]
                / total_weight
                * 100.0
                for name, signal in available_signals.items()
            )
        )

    score = max(0, min(100, score))
    reasons = _combine_reasons(scored_signals)

    # No usable analyzer results means there is not enough information
    # to assess whether the page is a clone.
    if not available_signals or total_weight <= 0:
        verdict = Verdict.unrelated
        summary = (
            "Insufficient evidence to assess whether this page "
            "is a phishing clone. The page could not be assessed "
            "reliably. This does not mean the page is safe."
        )

    elif score >= config.threshold_suspicious:
        verdict = Verdict.likely_clone
        summary = (
            "Strong similarity or other risk indicators suggest "
            "this page may be a phishing clone. Review the evidence "
            "before interacting with it."
        )

    elif score >= config.threshold_low_risk:
        verdict = Verdict.suspicious

        if len(available_signals) < len(signals):
            summary = (
                "Suspicious indicators were found, but the assessment "
                "has partial evidence because some analyzers were unavailable. "
                "Review the evidence before trusting this page."
            )
        else:
            summary = (
                "The page has some indicators that may warrant caution. "
                "Review the evidence before trusting it."
            )

    else:
        # A low score without specific findings is inconclusive,
        # not proof that the website is safe.
        has_evidence = bool(reasons)

        if not has_evidence:
            verdict = Verdict.unrelated
            summary = (
                "Insufficient evidence to establish whether this page "
                "is a phishing clone. No specific findings were returned. "
                "This does not mean the page is safe."
            )
        else:
            verdict = Verdict.low_risk
            summary = (
                "The available checks found limited evidence of cloning. "
                "This does not guarantee that the page is safe."
            )

    return ScanResult(
        score=score,
        verdict=verdict,
        summary=summary,
        signals=scored_signals,
        reasons=reasons,
    )
