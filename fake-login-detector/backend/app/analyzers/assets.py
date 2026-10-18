
"""
Asset similarity analyzer.

Compares network resources used by the suspect page and genuine reference.
Shared resources are supporting evidence of possible cloning, not proof
of phishing by themselves.
"""
from __future__ import annotations

from urllib.parse import urlparse

from app.models import Reason, ScanContext, Severity, SignalResult
from app.utils.urls import origin_key


class AssetsAnalyzer:
    name = "assets"

    # Common infrastructure should not count as meaningful clone evidence.
    COMMON_HOSTS = {
        "fonts.googleapis.com",
        "fonts.gstatic.com",
        "cdnjs.cloudflare.com",
        "cdn.jsdelivr.net",
        "unpkg.com",
    }

    ASSET_TYPES = {"image", "stylesheet", "script", "font"}

    @staticmethod
    def _normalized_url(url: str) -> str:
        """Normalize an HTTP(S) resource URL, ignoring query and fragment."""
        try:
            parsed = urlparse(url.strip())

            if (
                parsed.scheme.lower() not in {"http", "https"}
                or not parsed.hostname
            ):
                return ""

            host = parsed.hostname.lower()
            port = parsed.port

            # Preserve non-default ports because they can identify different
            # resources; omit standard HTTP and HTTPS ports.
            if port and not (
                (parsed.scheme.lower() == "http" and port == 80)
                or (parsed.scheme.lower() == "https" and port == 443)
            ):
                host = f"{host}:{port}"

            path = parsed.path or "/"
            return f"{parsed.scheme.lower()}://{host}{path}"

        except (ValueError, AttributeError):
            return ""

    @classmethod
    def _is_common_host(cls, url: str) -> bool:
        """Return True for well-known shared infrastructure hosts."""
        try:
            host = (urlparse(url).hostname or "").lower()
            return host in cls.COMMON_HOSTS
        except (ValueError, AttributeError):
            return False

    @classmethod
    def _collect_assets(cls, snapshot) -> set[str]:
        """Collect unique, relevant resource URLs from a page snapshot."""
        assets: set[str] = set()

        for request in snapshot.requests:
            if request.resource_type.lower() not in cls.ASSET_TYPES:
                continue

            normalized = cls._normalized_url(request.url)

            if not normalized or cls._is_common_host(normalized):
                continue

            assets.add(normalized)

        return assets

    async def analyze(self, ctx: ScanContext) -> SignalResult:
        """Compare asset requests and report shared-resource evidence."""
        if ctx.genuine is None:
            return SignalResult(
                name=self.name,
                score=0.0,
                available=False,
                unavailable_reason=(
                    "No genuine reference page is available for asset comparison."
                ),
            )

        genuine_origin = origin_key(
            ctx.genuine.final_url or ctx.genuine.requested_url
        )
        suspect_origin = origin_key(
            ctx.suspect.final_url or ctx.suspect.requested_url
        )

        if not genuine_origin or not suspect_origin:
            return SignalResult(
                name=self.name,
                score=0.0,
                available=False,
                unavailable_reason=(
                    "A valid HTTP(S) origin is required for both pages."
                ),
            )

        different_origin = genuine_origin != suspect_origin

        genuine_assets = self._collect_assets(ctx.genuine)
        suspect_assets = self._collect_assets(ctx.suspect)

        # No eligible assets means there is no positive evidence to report,
        # but the comparison itself was completed successfully.
        if not genuine_assets and not suspect_assets:
            return SignalResult(
                name=self.name,
                score=0.0,
                available=True,
                metrics={
                    "genuine_asset_count": 0,
                    "suspect_asset_count": 0,
                    "shared_asset_count": 0,
                    "different_origin": different_origin,
                },
            )

        shared_assets = genuine_assets & suspect_assets

        # Shared assets on the same origin are expected and are not useful
        # evidence of a cloned page.
        meaningful_shared = shared_assets if different_origin else set()

        score = 0.0
        reasons: list[Reason] = []

        if meaningful_shared:
            union_count = len(genuine_assets | suspect_assets)
            overlap = len(meaningful_shared) / max(1, union_count)

            # Keep this signal conservative: shared resources alone should
            # not independently label a page as phishing.
            score = min(0.65, 0.30 + 0.35 * overlap)

            reasons.append(
                Reason(
                    code="ASSET_SHARED_RESOURCE",
                    title="Shared page assets",
                    detail=(
                        f"The suspect page and genuine page load "
                        f"{len(meaningful_shared)} matching non-common asset "
                        "URL(s), despite having different page origins."
                    ),
                    severity=Severity.medium,
                    signal=self.name,
                    evidence={
                        "shared_count": len(meaningful_shared),
                        "shared_urls": sorted(meaningful_shared)[:10],
                    },
                )
            )

        return SignalResult(
            name=self.name,
            score=score,
            available=True,
            reasons=reasons,
            metrics={
                "genuine_asset_count": len(genuine_assets),
                "suspect_asset_count": len(suspect_assets),
                "shared_asset_count": len(meaningful_shared),
                "different_origin": different_origin,
            },
        )
