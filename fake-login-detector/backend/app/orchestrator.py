
"""Coordinate page capture, analysis, and weighted scoring."""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from urllib.parse import urlparse

from app.analyzers.assets import AssetsAnalyzer
from app.analyzers.base import run_analyzer
from app.analyzers.dom import DomAnalyzer
from app.analyzers.domain import DomainAnalyzer
from app.analyzers.form import FormAnalyzer
from app.analyzers.visual import VisualAnalyzer
from app.config import settings
from app.fetcher import fetcher
from app.models import (
    FormComparison,
    ScanContext,
    ScanRequest,
    ScanResult,
    ScanSettings,
    SignalResult,
    Verdict,
)
from app.registry import match_brand
from app.scoring import compute_score
from app.evidence import build_evidence

logger = logging.getLogger(__name__)

ANALYZER_NAMES = ("domain", "form", "dom", "visual", "assets")


class Orchestrator:
    """Run the complete fake-login-page detection pipeline."""

    def __init__(self) -> None:
        self._semaphore = asyncio.Semaphore(
            max(1, int(getattr(settings, "max_concurrent_scans", 3)))
        )
        self._progress: dict[str, dict] = {}

        self._analyzers = [
            DomainAnalyzer(),
            FormAnalyzer(),
            DomAnalyzer(),
            VisualAnalyzer(),
            AssetsAnalyzer(),
        ]

    def _scan_settings(self) -> ScanSettings:
        """Translate application configuration into analyzer settings."""
        return ScanSettings(
            weight_visual=float(
                getattr(settings, "weight_visual", 0.30)
            ),
            weight_dom=float(
                getattr(settings, "weight_dom", 0.25)
            ),
            weight_form=float(
                getattr(settings, "weight_form", 0.20)
            ),
            weight_domain=float(
                getattr(settings, "weight_domain", 0.15)
            ),
            weight_assets=float(
                getattr(settings, "weight_assets", 0.10)
            ),
            threshold_low_risk=int(
                getattr(settings, "threshold_low_risk", 20)
            ),
            threshold_suspicious=int(
                getattr(settings, "threshold_suspicious", 70)
            ),
            phishing_keywords=list(
                getattr(settings, "phishing_keywords", [])
            ),
            risky_tlds=list(
                getattr(settings, "risky_tlds", [])
            ),
            enable_whois=bool(
                getattr(settings, "enable_whois", False)
            ),
            allow_private_hosts=bool(
                getattr(settings, "allow_private_hosts", True)
            ),
            whois_young_days=int(
                getattr(settings, "whois_young_days", 30)
            ),
        )

    def _set_progress(
        self,
        scan_id: str,
        stage: str,
        *,
        done: bool = False,
        error: str | None = None,
    ) -> None:
        """Update the in-memory status for a scan."""
        progress = self._progress.setdefault(
            scan_id,
            {
                "scan_id": scan_id,
                "stage": "queued",
                "done": False,
                "error": None,
            },
        )
        progress.update(
            {
                "stage": stage,
                "done": done,
                "error": error,
            }
        )

    @staticmethod
    def _failed_result(
        scan_id: str,
        url: str,
        message: str,
        duration_ms: int,
        timings: dict[str, float] | None = None,
    ) -> ScanResult:
        """Represent a failed scan without claiming the page is safe."""
        return ScanResult(
            scan_id=scan_id,
            suspect_url=url,
            verdict=Verdict.unrelated,
            score=0,
            summary=message,
            partial=True,
            duration_ms=duration_ms,
            timings=timings or {},
        )

    @staticmethod
    def _make_form_comparison(
        suspect,
        genuine,
    ) -> FormComparison | None:
        """Compare the first password forms on both pages."""
        if genuine is None:
            return None

        suspect_form = next(
            (form for form in suspect.forms if form.has_password),
            None,
        )
        genuine_form = next(
            (form for form in genuine.forms if form.has_password),
            None,
        )

        if suspect_form is None and genuine_form is None:
            return None

        suspect_action = (
            suspect_form.action_resolved if suspect_form else None
        )
        genuine_action = (
            genuine_form.action_resolved if genuine_form else None
        )

        action_host = None
        if suspect_action:
            try:
                action_host = urlparse(suspect_action).hostname
            except ValueError:
                action_host = None

        return FormComparison(
            genuine_action=genuine_action,
            suspect_action=suspect_action,
            genuine_field_names=(
                genuine_form.field_names if genuine_form else []
            ),
            suspect_field_names=(
                suspect_form.field_names if suspect_form else []
            ),
            is_cross_origin=(
                suspect_form.is_cross_origin if suspect_form else False
            ),
            action_host=action_host,
        )

    async def scan(self, request: ScanRequest) -> ScanResult:
        """Capture the target, run analyzers, and calculate its score."""
        started = time.perf_counter()
        scan_id = str(uuid.uuid4())
        timings: dict[str, float] = {}

        self._progress[scan_id] = {
            "scan_id": scan_id,
            "stage": "queued",
            "done": False,
            "error": None,
        }

        try:
            async with self._semaphore:
                self._set_progress(scan_id, "capturing_suspect")

                stage_started = time.perf_counter()
                suspect = await fetcher.fetch(request.url, scan_id)
                timings["suspect_capture"] = (
                    time.perf_counter() - stage_started
                )

                if suspect.load_error:
                    message = (
                        "The target page could not be captured. "
                        "No reliable safety verdict is available."
                    )
                    self._set_progress(
                        scan_id,
                        "failed",
                        done=True,
                        error="PageCaptureError",
                    )
                    return self._failed_result(
                        scan_id,
                        request.url,
                        message,
                        int((time.perf_counter() - started) * 1000),
                        timings,
                    )

                brand = match_brand(
                    suspect.final_url or suspect.requested_url,
                    title=suspect.title,
                    visible_text=suspect.visible_text,
                    favicon_path=suspect.favicon_path,
                )

                genuine = None
                genuine_url = request.genuine_url

                if not genuine_url and brand and brand.genuine_urls:
                    genuine_url = brand.genuine_urls[0]

                if genuine_url:
                    self._set_progress(scan_id, "capturing_reference")

                    stage_started = time.perf_counter()
                    candidate = await fetcher.fetch(
                        genuine_url,
                        f"{scan_id}-genuine",
                    )
                    timings["genuine_capture"] = (
                        time.perf_counter() - stage_started
                    )

                    if candidate.load_error:
                        logger.warning(
                            "Reference capture failed for scan %s: %s",
                            scan_id,
                            candidate.load_error,
                        )
                    else:
                        genuine = candidate

                scan_settings = self._scan_settings()
                context = ScanContext(
                    suspect=suspect,
                    genuine=genuine,
                    brand=brand,
                    settings=scan_settings,
                )

                self._set_progress(scan_id, "analyzing")
                stage_started = time.perf_counter()

                selected_analyzers = self._analyzers
                mode_value = getattr(request.mode, "value", request.mode)

                if mode_value == "fast":
                    selected_analyzers = [
                        analyzer
                        for analyzer in self._analyzers
                        if analyzer.name not in {"visual", "assets"}
                    ]

                results = await asyncio.gather(
                    *(
                        run_analyzer(analyzer, context)
                        for analyzer in selected_analyzers
                    )
                )

                signals: dict[str, SignalResult] = {
                    signal.name: signal for signal in results
                }

                # Keep the response schema stable in both scan modes.
                for name in ANALYZER_NAMES:
                    if name not in signals:
                        signals[name] = SignalResult(
                            name=name,
                            score=0.0,
                            available=False,
                            unavailable_reason=(
                                "This analyzer was skipped in fast mode."
                            ),
                        )

                timings["analysis"] = (
                    time.perf_counter() - stage_started
                )

                self._set_progress(scan_id, "scoring")
                stage_started = time.perf_counter()
                scored = compute_score(signals, scan_settings)
                timings["scoring"] = (
                    time.perf_counter() - stage_started
                )

                images: dict[str, str] = {}

                if suspect.screenshot_path:
                    images["suspect"] = suspect.screenshot_path

                if genuine and genuine.screenshot_path:
                    images["genuine"] = genuine.screenshot_path

                if genuine and suspect.screenshot_path and genuine.screenshot_path:
                    try:
                        evidence = await build_evidence(
                            scan_id,
                            suspect.screenshot_path,
                            genuine.screenshot_path,
                        )
                        images.update(evidence)
                    except Exception:
                        logger.exception("Failed to generate comparison evidence")

                for name, signal in scored.signals.items():
                    for evidence_name, path in signal.evidence_files.items():
                        images[f"{name}_{evidence_name}"] = path

                result = scored.model_copy(
                    update={
                        "scan_id": scan_id,
                        "suspect_url": (
                            suspect.final_url or suspect.requested_url
                        ),
                        "genuine_url": (
                            (genuine.final_url or genuine.requested_url)
                            if genuine else None
                        ),
                        "brand": brand.name if brand else None,
                        "images": images,
                        "form_comparison": self._make_form_comparison(
                            suspect,
                            genuine,
                        ),
                        "timings": timings,
                        "duration_ms": int(
                            (time.perf_counter() - started) * 1000
                        ),
                        "partial": any(
                            not signal.available
                            for signal in scored.signals.values()
                        ),
                    }
                )

                self._set_progress(scan_id, "complete", done=True)
                return result

        except Exception as exc:
            logger.exception("Scan %s failed unexpectedly", scan_id)

            self._set_progress(
                scan_id,
                "failed",
                done=True,
                error=type(exc).__name__,
            )

            return self._failed_result(
                scan_id,
                request.url,
                "The scan encountered an unexpected error. "
                "No reliable safety verdict is available.",
                int((time.perf_counter() - started) * 1000),
                timings,
            )

        finally:
            # Never overwrite an already failed scan as complete.
            progress = self._progress[scan_id]
            progress["done"] = True

            if progress["stage"] not in {"complete", "failed"}:
                self._set_progress(
                    scan_id,
                    "failed",
                    done=True,
                    error=progress.get("error") or "ScanInterrupted",
                )

    async def get_progress(self, scan_id: str) -> dict:
        """Return the latest in-memory progress state for a scan."""
        return self._progress.get(
            scan_id,
            {
                "scan_id": scan_id,
                "stage": "unknown",
                "done": False,
                "error": None,
            },
        )


orchestrator = Orchestrator()
