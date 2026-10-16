"""
models.py — All Pydantic v2 data contracts for the Fake Login Page Detector.

Every module imports from here; nothing is defined inline elsewhere.
Inputs:  none (this module is pure data-contract definitions)
Outputs: importable Pydantic models and enums
Failure: import errors only if pydantic is missing
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator


# ── Enumerations ──────────────────────────────────────────────────────────────

class Severity(str, Enum):
    """Evidence severity, ordered from least to most serious."""
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Verdict(str, Enum):
    """Final verdict for a scanned URL."""
    genuine = "genuine"
    low_risk = "low_risk"
    suspicious = "suspicious"
    likely_clone = "likely_clone"
    unrelated = "unrelated"


class ScanMode(str, Enum):
    """Scan depth: full runs all analyzers; fast skips visual and evidence."""
    full = "full"
    fast = "fast"


# ── Evidence types ─────────────────────────────────────────────────────────────

class Reason(BaseModel):
    """
    A single piece of evidence explaining why the page looks suspicious (or not).

    code:     Stable machine-readable identifier, e.g. FORM_FOREIGN_ACTION.
    title:    Short human title shown in the UI card header.
    detail:   One plain-English sentence readable by a non-expert.
    severity: How serious this finding is.
    signal:   Which analyzer produced this reason.
    evidence: Raw data supporting the claim, e.g. {"action_url": "http://evil.com/post"}.
    """
    code: str
    title: str
    detail: str
    severity: Severity
    signal: str
    evidence: dict[str, Any] = Field(default_factory=dict)


class SignalResult(BaseModel):
    """
    Output from one analyzer.

    score:             0.0 (benign) to 1.0 (strongly clone-like).
    available:         False when the analyzer could not run (missing dep, error, etc.).
    unavailable_reason: Human explanation when available=False.
    reasons:           Structured evidence items produced by this analyzer.
    metrics:           Raw numbers shown in the breakdown chart, e.g. {"ssim": 0.94}.
    evidence_files:    Named paths to generated images, e.g. {"diff": "artifacts/…/diff.png"}.
    weight_used:       Filled by scoring.py — the normalized weight this signal received.
    contribution:      Filled by scoring.py — points (0–100) this signal added to the score.
    """
    name: str
    score: float = Field(ge=0.0, le=1.0)
    available: bool = True
    unavailable_reason: Optional[str] = None
    reasons: list[Reason] = Field(default_factory=list)
    metrics: dict[str, Any] = Field(default_factory=dict)
    evidence_files: dict[str, str] = Field(default_factory=dict)
    weight_used: float = 0.0
    contribution: float = 0.0


# ── Page snapshot types ───────────────────────────────────────────────────────

class BoundingBox(BaseModel):
    """Pixel bounding box of a DOM element in the viewport."""
    x: float
    y: float
    width: float
    height: float


class FormInfo(BaseModel):
    """
    All attributes of a single HTML form element, as resolved by the fetcher.

    action_raw:       The literal action= attribute (may be empty or relative).
    action_resolved:  Absolute URL after resolving against the page's final URL.
    action_origin:    scheme://host:port of the resolved action.
    method:           "get" or "post" (lowercased).
    has_password:     True if any input[type=password] is inside this form.
    hidden_fields:    Names of input[type=hidden] elements.
    field_names:      All input names (excluding hidden).
    bounding_box:     Viewport box of the <form> element, or None if off-screen.
    is_cross_origin:  True if action_origin differs from the page's origin.
    is_http:          True if action_resolved uses plain http (not https).
    """
    action_raw: str = ""
    action_resolved: str = ""
    action_origin: str = ""
    method: str = "post"
    has_password: bool = False
    hidden_fields: list[str] = Field(default_factory=list)
    field_names: list[str] = Field(default_factory=list)
    bounding_box: Optional[BoundingBox] = None
    is_cross_origin: bool = False
    is_http: bool = False


class RequestRecord(BaseModel):
    """One outbound network request recorded by the Playwright page."""
    url: str
    method: str
    resource_type: str
    origin: str
    has_body: bool = False


class PageSnapshot(BaseModel):
    """
    Full captured state of a rendered page, produced by fetcher.py.

    requested_url:    The URL that was navigated to.
    final_url:        The URL after all redirects.
    redirect_chain:   Intermediate URLs visited.
    status:           HTTP status code of the final response (None on error).
    title:            document.title.
    html:             Full HTML source (capped at max_html_bytes).
    visible_text:     document.body.innerText.
    screenshot_path:  Absolute path to the saved PNG viewport screenshot.
    viewport:         {"width": int, "height": int}.
    forms:            All <form> elements parsed into FormInfo objects.
    requests:         All network requests the page made.
    favicon_path:     Absolute path to downloaded favicon, or None.
    logo_candidates:  [{"path": str, "box": BoundingBox, "src": str}].
    element_boxes:    Notable element bounding boxes, e.g. password inputs, forms.
    load_error:       Non-None when navigation or rendering failed.
    is_image_only:    True when the page is a screenshot/image with no real text.
    """
    requested_url: str
    final_url: str = ""
    redirect_chain: list[str] = Field(default_factory=list)
    status: Optional[int] = None
    title: str = ""
    html: str = ""
    visible_text: str = ""
    screenshot_path: Optional[str] = None
    viewport: dict[str, int] = Field(default_factory=lambda: {"width": 1366, "height": 768})
    forms: list[FormInfo] = Field(default_factory=list)
    requests: list[RequestRecord] = Field(default_factory=list)
    favicon_path: Optional[str] = None
    logo_candidates: list[dict[str, Any]] = Field(default_factory=list)
    element_boxes: dict[str, list[BoundingBox]] = Field(default_factory=dict)
    load_error: Optional[str] = None
    is_image_only: bool = False


# ── Brand ─────────────────────────────────────────────────────────────────────

class Brand(BaseModel):
    """Entry from brands.json describing a protected brand."""
    id: str
    name: str
    genuine_urls: list[str] = Field(default_factory=list)
    origins: list[str] = Field(default_factory=list)
    trusted_related_origins: list[str] = Field(default_factory=list)
    title_keywords: list[str] = Field(default_factory=list)
    lookalike_labels: list[str] = Field(default_factory=list)
    logo_phash: str = ""
    aliases_for_local_testing: list[str] = Field(default_factory=list)


# ── Scan pipeline types ───────────────────────────────────────────────────────

class ScanSettings(BaseModel):
    """Subset of Settings passed into ScanContext so analyzers are config-aware."""
    weight_visual: float = 0.30
    weight_dom: float = 0.25
    weight_form: float = 0.20
    weight_domain: float = 0.15
    weight_assets: float = 0.10
    threshold_low_risk: int = 20
    threshold_suspicious: int = 70
    phishing_keywords: list[str] = Field(default_factory=list)
    risky_tlds: list[str] = Field(default_factory=list)
    enable_whois: bool = False
    allow_private_hosts: bool = True
    whois_young_days: int = 30


class ScanContext(BaseModel):
    """
    Immutable context passed to every analyzer.

    suspect: The snapshot of the page under investigation.
    genuine: The snapshot of the real page (None when brand matching failed).
    brand:   The matched brand entry (None for unrelated pages).
    settings: Configuration subset so analyzers never import from config directly.
    """
    suspect: PageSnapshot
    genuine: Optional[PageSnapshot] = None
    brand: Optional[Brand] = None
    settings: ScanSettings = Field(default_factory=ScanSettings)


# ── API request / response types ──────────────────────────────────────────────

class ScanRequest(BaseModel):
    """Body for POST /api/scan."""
    url: str
    genuine_url: Optional[str] = None
    mode: ScanMode = ScanMode.full

    @field_validator("url", "genuine_url", mode="before")
    @classmethod
    def strip_whitespace(cls, v: Optional[str]) -> Optional[str]:
        return v.strip() if isinstance(v, str) else v


class FormComparison(BaseModel):
    """Side-by-side form action data shown in the UI."""
    genuine_action: Optional[str] = None
    suspect_action: Optional[str] = None
    genuine_field_names: list[str] = Field(default_factory=list)
    suspect_field_names: list[str] = Field(default_factory=list)
    is_cross_origin: bool = False
    action_host: Optional[str] = None


class ScanResult(BaseModel):
    """
    Complete result returned by POST /api/scan and GET /api/scan/{id}.

    scan_id:          Unique identifier for this scan run.
    created_at:       ISO timestamp when the scan was completed.
    duration_ms:      Wall-clock time from request to completion.
    suspect_url:      The URL that was scanned.
    brand:            Name of the matched brand, or None.
    score:            0–100 integer clone-likelihood score.
    verdict:          Machine-readable verdict string.
    summary:          One paragraph human-readable summary.
    signals:          Per-analyzer results with their contributions.
    reasons:          All reasons, sorted by severity then signal weight.
    images:           URLs to the saved image assets.
    form_comparison:  Genuine vs. suspect form action data.
    overrides_applied: List of override rule names that fired.
    timings:          Per-stage duration in seconds.
    partial:          True when the scan timed out before completion.
    """
    scan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    duration_ms: int = 0
    suspect_url: str = ""
    brand: Optional[str] = None
    score: int = Field(ge=0, le=100, default=0)
    verdict: Verdict = Verdict.unrelated
    summary: str = ""
    signals: dict[str, SignalResult] = Field(default_factory=dict)
    reasons: list[Reason] = Field(default_factory=list)
    images: dict[str, str] = Field(default_factory=dict)
    form_comparison: Optional[FormComparison] = None
    overrides_applied: list[str] = Field(default_factory=list)
    timings: dict[str, float] = Field(default_factory=dict)
    partial: bool = False


class ProgressUpdate(BaseModel):
    """Emitted at each orchestrator stage for the /progress endpoint."""
    scan_id: str
    stage: str
    done: bool = False
    error: Optional[str] = None


class QuickCheckRequest(BaseModel):
    """Body for POST /api/quick-check (extension fast path, no browser)."""
    url: str
    form_actions: list[str] = Field(default_factory=list)
    has_password: bool = False


class QuickCheckResult(BaseModel):
    """Response from POST /api/quick-check."""
    verdict: Verdict
    score: int = Field(ge=0, le=100)
    reasons: list[Reason] = Field(default_factory=list)
    brand: Optional[str] = None


class ErrorResponse(BaseModel):
    """Standard error body for all 4xx/5xx responses."""
    code: str
    message: str
