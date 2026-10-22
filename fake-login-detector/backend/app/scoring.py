
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

    # ── Section 6.5: Rule-based Overrides R1 through R4 ───────────────────────
    overrides_applied: list[str] = []

    has_foreign_form = any(
        r.code in ("FORM_PASSWORD_FOREIGN_ACTION", "FORM_FOREIGN_ACTION", "FORM_EXFILTRATION_JS")
        for r in reasons
    )
    has_domain_skeleton = any(
        r.code in ("DOMAIN_CONFUSABLE_BRAND", "DOMAIN_ALIAS_MATCH")
        for r in reasons
    )

    # Compute similarity index among available similarity signals
    sim_weights = {"visual": 0.50, "dom": 0.35, "assets": 0.15}
    available_sim = [name for name in sim_weights if name in available_signals]
    if available_sim:
        sim_total = sum(sim_weights[name] for name in available_sim)
        similarity_index = sum(
            available_signals[name].score * sim_weights[name] / sim_total
            for name in available_sim
        )
    else:
        # When visual/dom are not run (fast mode), use 1.0 if foreign form present
        similarity_index = 1.0 if has_foreign_form else 0.0

    # R1: Same origin or trusted origin
    if any(r.code in ("SAME_ORIGIN", "GENUINE_ORIGIN") for r in reasons):
        score = 0
        verdict = Verdict.genuine
        overrides_applied.append("R1: Same origin or trusted related origin")

    # R2: Foreign form action AND similarity index >= 0.60 (or fast mode)
    elif has_foreign_form and (similarity_index >= 0.60 or not available_sim):
        score = max(score, 88)
        verdict = Verdict.likely_clone
        overrides_applied.append("R2: Foreign form action stealing credentials")

    # R3: Domain skeleton match AND similarity index >= 0.50
    elif has_domain_skeleton and similarity_index >= 0.50:
        score = max(score, 65)
        verdict = Verdict.likely_clone
        overrides_applied.append("R3: Domain skeleton match with high similarity")

    # R4: Low similarity and no risk indicators
    elif similarity_index < 0.20 and not has_domain_skeleton and not has_foreign_form and score <= 20:
        score = min(score, 10)
        verdict = Verdict.unrelated
        overrides_applied.append("R4: Low similarity and no risk indicators")

    # Threshold-based verdict fallback if no override applied
    elif score >= config.threshold_suspicious:
        verdict = Verdict.likely_clone
    elif score >= config.threshold_low_risk:
        verdict = Verdict.suspicious
    elif score > 0:
        verdict = Verdict.low_risk
    else:
        verdict = Verdict.unrelated

    # Summary text
    if not available_signals or total_weight <= 0:
        summary = (
            "Insufficient evidence to assess whether this page "
            "is a phishing clone. The page could not be assessed "
            "reliably. This does not mean the page is safe."
        )
    elif verdict == Verdict.genuine:
        summary = "Verified genuine portal. Origin matches registered authentic organization."
    elif verdict == Verdict.likely_clone:
        summary = "Strong similarity or other risk indicators suggest this page may be a phishing clone. Review the evidence before interacting with it."
    elif verdict == Verdict.suspicious:
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
    elif score == 0 and not reasons:
        summary = (
            "Insufficient evidence to assess whether this page "
            "is a phishing clone. No specific findings were returned. "
            "This does not mean the page is safe."
        )
    elif verdict == Verdict.low_risk:
        summary = (
            "The available checks found limited evidence of cloning. "
            "This does not guarantee that the page is safe."
        )
    else:
        summary = (
            "Insufficient evidence to assess whether this page "
            "is a phishing clone. The page could not be assessed "
            "reliably. This does not mean the page is safe."
        )

    return ScanResult(
        score=score,
        verdict=verdict,
        summary=summary,
        signals=scored_signals,
        reasons=reasons,
    )
