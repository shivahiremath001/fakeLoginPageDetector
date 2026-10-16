"""
config.py — Application configuration loaded from environment variables and scoring.json.

Inputs:  environment variables (prefixed FAKELD_) and backend/config/scoring.json
Outputs: a singleton Settings instance importable everywhere
Failure: raises on startup if required files are missing; individual optional
         sections fall back to documented defaults.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# Resolve config directory relative to this file
_CONFIG_DIR = Path(__file__).parent.parent / "config"
_SCORING_FILE = _CONFIG_DIR / "scoring.json"


def _load_scoring_json() -> dict[str, Any]:
    """Load scoring.json; return empty dict on any read/parse failure."""
    try:
        return json.loads(_SCORING_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


class Settings(BaseSettings):
    """
    Central configuration for the Fake Login Page Detector.

    All values can be overridden via environment variables prefixed with FAKELD_.
    Weights, thresholds, and keyword lists are loaded from scoring.json and exposed
    here so no magic numbers live in analyzer code.
    """

    model_config = SettingsConfigDict(env_prefix="FAKELD_", env_file=".env", extra="ignore")

    # ── Server ────────────────────────────────────────────────────────────────
    host: str = "0.0.0.0"
    port: int = 8000
    log_level: str = "info"

    # ── Playwright / fetcher ──────────────────────────────────────────────────
    page_timeout_ms: int = 8_000       # per-page navigation timeout (ms)
    network_idle_cap_ms: int = 4_000   # max extra wait for networkidle (ms)
    total_scan_timeout_s: float = 15.0 # hard wall-clock limit for a full scan
    viewport_width: int = 1366
    viewport_height: int = 768
    max_concurrent_scans: int = 3      # semaphore limit
    max_html_bytes: int = 5 * 1024 * 1024  # 5 MB cap on saved HTML

    # Image-only detection thresholds
    image_only_text_chars: int = 30    # fewer chars → suspect image-only
    image_only_coverage: float = 0.60  # single image > 60% viewport → image-only

    # ── Cache ────────────────────────────────────────────────────────────────
    genuine_cache_ttl_s: int = 600     # 10 minutes for genuine snapshot cache
    result_cache_ttl_s: int = 300      # 5 minutes for scan result cache

    # ── Analyzer weights (defaults; overridden by scoring.json) ──────────────
    weight_visual: float = 0.30
    weight_dom: float = 0.25
    weight_form: float = 0.20
    weight_domain: float = 0.15
    weight_assets: float = 0.10

    # ── Verdict thresholds ────────────────────────────────────────────────────
    threshold_low_risk: int = 20       # score < this → low_risk
    threshold_suspicious: int = 70     # score < this → suspicious; >= → likely_clone

    # ── Feature flags ────────────────────────────────────────────────────────
    enable_whois: bool = False         # WHOIS domain-age check (requires internet)
    enable_virustotal: bool = False    # VirusTotal reputation (requires API key + internet)
    enable_ai_summary: bool = False    # LLM-generated summary (requires API key)
    # SSRF note: allowing private hosts is a deliberate hackathon tradeoff.
    # In production this MUST be False to prevent SSRF via the Playwright fetcher.
    allow_private_hosts: bool = True

    # ── VirusTotal (only used when enable_virustotal=True) ────────────────────
    virustotal_api_key: str = ""

    # ── AI summary (only used when enable_ai_summary=True) ───────────────────
    openai_api_key: str = ""
    ai_model: str = "gpt-4o-mini"

    # ── Paths ────────────────────────────────────────────────────────────────
    artifacts_dir: Path = Path(__file__).parent.parent.parent / "artifacts"
    config_dir: Path = _CONFIG_DIR

    # ── Loaded from scoring.json ──────────────────────────────────────────────
    # These are populated in __init__ after scoring.json is read.
    phishing_keywords: list[str] = Field(default_factory=list)
    risky_tlds: list[str] = Field(default_factory=list)
    whois_young_days: int = 30         # domains younger than this are suspicious

    def model_post_init(self, __context: Any) -> None:  # noqa: ANN401
        """Merge values from scoring.json into this settings object."""
        scoring = _load_scoring_json()

        # Weights
        weights = scoring.get("weights", {})
        if "visual" in weights:
            object.__setattr__(self, "weight_visual", float(weights["visual"]))
        if "dom" in weights:
            object.__setattr__(self, "weight_dom", float(weights["dom"]))
        if "form" in weights:
            object.__setattr__(self, "weight_form", float(weights["form"]))
        if "domain" in weights:
            object.__setattr__(self, "weight_domain", float(weights["domain"]))
        if "assets" in weights:
            object.__setattr__(self, "weight_assets", float(weights["assets"]))

        # Thresholds
        thresholds = scoring.get("thresholds", {})
        if "low_risk" in thresholds:
            object.__setattr__(self, "threshold_low_risk", int(thresholds["low_risk"]))
        if "suspicious" in thresholds:
            object.__setattr__(self, "threshold_suspicious", int(thresholds["suspicious"]))

        # Keyword lists
        if "phishing_keywords" in scoring:
            object.__setattr__(self, "phishing_keywords", list(scoring["phishing_keywords"]))
        if "risky_tlds" in scoring:
            object.__setattr__(self, "risky_tlds", list(scoring["risky_tlds"]))

        # Ensure artifacts dir exists
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)


# Module-level singleton — import this everywhere.
settings = Settings()
