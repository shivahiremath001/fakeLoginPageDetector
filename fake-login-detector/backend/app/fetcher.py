"""
fetcher.py — Playwright wrapper that renders pages into PageSnapshot objects.

Full implementation in Phase 2.
"""
from __future__ import annotations

from app.models import PageSnapshot


class PageFetcher:
    """Manages a shared Chromium browser and fetches page snapshots."""

    async def startup(self) -> None:
        """Start the shared Playwright browser. Called from FastAPI lifespan."""
        pass  # Phase 2

    async def shutdown(self) -> None:
        """Close the browser. Called from FastAPI lifespan."""
        pass  # Phase 2

    async def fetch(self, url: str, scan_id: str) -> PageSnapshot:
        """
        Navigate to url and return a fully populated PageSnapshot.

        Stub — implemented in Phase 2.
        """
        return PageSnapshot(
            requested_url=url,
            final_url=url,
            load_error="Fetcher not yet implemented (Phase 2)",
        )


# Module-level singleton used by the orchestrator
fetcher = PageFetcher()
