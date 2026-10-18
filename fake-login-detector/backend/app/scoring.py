
"""
scoring.py — Weighted score computation and verdict assignment.
"""
from __future__ import annotations

import logging

from app.models import Reason, ScanResult, ScanSettings, SignalResult, Verdict

logger = logging.getLogger(__name__)

SIGNAL_WEIGHTS = {
    "visual": "weight_visual",
    "dom": "weight_dom",
    "form": "weight_form",
    "domain": "weight_domain",
    "assets": "weight_assets",
}


def _fallback_result() -> ScanResult:
    """Return a safe result if scoring encounters an unexpected error."""
    return ScanResult(
        score=0,
        verdict=Verdict.unrelated,
        summary="The scan score could not be calculated reliably.",
    )


def compute_score(
    signals: dict[str, SignalResult],
    scan_settings: ScanSettings | None = None,
) -> ScanResult:
    """
    Combine available analyzer scores into a 0–100 clone-likelihood score.

    Unavailable analyzers are excluded and the remaining weights are
    normalized. This avoids treating a failed analyzer as evidence of safety.
    """
    try:
        config = scan_settings or ScanSettings()

        configured_weights = {
            name: max(0.0, float(getattr(config, setting_name)))
            for name, setting_name in SIGNAL_WEIGHTS.items()
        }

        active_weight_total = sum(
            configured_weights.get(name, 0.0)
            for name, signal in signals.items()
            if signal.available
        )

        scored_signals: dict[str, SignalResult] = {}

        for name, signal in signals.items():
            updated = signal.model_copy(deep=True)

            if not signal.available or active_weight_total <= 0:
                updated.weight_used = 0.0
                updated.contribution = 0.0
            else:
                weight = configured_weights.get(name, 0.0) / active_weight_total
                updated.weight_used = weight
                updated.contribution = round(
                    weight * signal.score * 100.0, 2
                )

            scored_signals[name] = updated

        if active_weight_total <= 0:
            return ScanResult(
                score=0,
                verdict=Verdict.unrelated,
                summary=(
                    "No analyzers produced usable results. "
                    "The page could not be assessed reliably."
                ),
                signals=scored_signals,
                reasons=[],
            )

        raw_score = sum(
            signal.contribution for signal in scored_signals.values()
        )
        score = max(0, min(100, round(raw_score)))

        if score >= config.threshold_suspicious:
            verdict = Verdict.likely_clone
            summary = (
                "The page has strong indicators of being a cloned "
                "or impersonating login page."
            )
        elif score >= config.threshold_low_risk:
            verdict = Verdict.suspicious
            summary = (
                "The page has some suspicious indicators. "
                "Review the evidence before trusting it."
            )
        else:
            verdict = Verdict.low_risk
            summary = (
                "The available checks found limited evidence of cloning. "
                "This does not guarantee that the page is safe."
            )

        # Combine evidence, prioritizing more serious findings.
        severity_order = {
            "critical": 5,
            "high": 4,
            "medium": 3,
            "low": 2,
            "info": 1,
        }

        reasons: list[Reason] = []
        seen_codes: set[tuple[str, str]] = set()

        for signal in scored_signals.values():
            for reason in signal.reasons:
                key = (reason.signal, reason.code)
                if key not in seen_codes:
                    seen_codes.add(key)
                    reasons.append(reason)

        reasons.sort(
            key=lambda reason: (
                severity_order.get(reason.severity.value, 0),
                scored_signals.get(
                    reason.signal, SignalResult(name=reason.signal, score=0)
                ).weight_used,
            ),
            reverse=True,
        )

        unavailable = [
            name for name, signal in scored_signals.items()
            if not signal.available
        ]
        if unavailable:
            summary += (
                f" {len(unavailable)} analyzer(s) were unavailable, "
                "so the result is based on partial evidence."
            )

        return ScanResult(
            score=score,
            verdict=verdict,
            summary=summary,
            signals=scored_signals,
            reasons=reasons,
        )

    except Exception:
        logger.exception("Failed to compute scan score")
        return _fallback_result()
