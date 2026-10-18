
"""Compare suspect and genuine page DOM/content for clone-like similarity."""
from __future__ import annotations

from difflib import SequenceMatcher
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from app.models import Reason, ScanContext, Severity, SignalResult


def _normalized_text(value: str) -> str:
    """Normalize text for comparison without depending on formatting."""
    return " ".join((value or "").lower().split())


def _page_origin(url: str) -> str:
    """Return the scheme and authority for a valid HTTP(S) URL."""
    try:
        parsed = urlparse(url.strip())
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return ""
        _ = parsed.port
        return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"
    except (AttributeError, TypeError, ValueError):
        return ""


def _parse_html(html: str) -> BeautifulSoup:
    return BeautifulSoup(html or "", "lxml")


def _structure_tokens(soup: BeautifulSoup) -> list[str]:
    """Represent element types and important attributes, not raw markup."""
    tokens: list[str] = []

    for element in soup.find_all(True):
        tag = element.name.lower()
        tokens.append(tag)

        if tag == "input":
            input_type = (element.get("type") or "text").lower()
            tokens.append(f"input:type:{input_type}")

    return tokens


def _similarity(left: str, right: str) -> float:
    if not left or not right:
        return 0.0
    return SequenceMatcher(None, left, right, autojunk=False).ratio()


def _field_signature(soup: BeautifulSoup) -> list[str]:
    """Extract a normalized signature of form controls."""
    fields: list[str] = []

    for element in soup.find_all(["input", "button", "select", "textarea"]):
        tag = element.name.lower()
        input_type = (element.get("type") or "text").lower()
        name = _normalized_text(str(element.get("name") or ""))
        placeholder = _normalized_text(
            str(element.get("placeholder") or "")
        )
        fields.append(f"{tag}|{input_type}|{name}|{placeholder}")

    return fields


def _page_title(page_title: str | None, soup: BeautifulSoup) -> str:
    """Read the captured title, falling back to the HTML title."""
    if page_title:
        return _normalized_text(page_title)

    if soup.title:
        return _normalized_text(soup.title.get_text(" ", strip=True))

    return ""


class DomAnalyzer:
    """Compare page content and structure with the genuine reference."""

    name = "dom"

    async def analyze(self, ctx: ScanContext) -> SignalResult:
        suspect = ctx.suspect
        genuine = ctx.genuine

        if genuine is None:
            return SignalResult(
                name=self.name,
                score=0.0,
                available=False,
                unavailable_reason="No genuine reference page is available.",
            )

        if not suspect.html or not genuine.html:
            return SignalResult(
                name=self.name,
                score=0.0,
                available=False,
                unavailable_reason=(
                    "The suspect or genuine page has no HTML to compare."
                ),
            )

        suspect_origin = _page_origin(
            suspect.final_url or suspect.requested_url
        )
        genuine_origin = _page_origin(
            genuine.final_url or genuine.requested_url
        )

        if not suspect_origin or not genuine_origin:
            return SignalResult(
                name=self.name,
                score=0.0,
                available=False,
                unavailable_reason="A page URL has no valid HTTP(S) origin.",
            )

        suspect_soup = _parse_html(suspect.html)
        genuine_soup = _parse_html(genuine.html)

        suspect_text = _normalized_text(
            suspect.visible_text
            or suspect_soup.get_text(" ", strip=True)
        )
        genuine_text = _normalized_text(
            genuine.visible_text
            or genuine_soup.get_text(" ", strip=True)
        )

        if not suspect_text and not genuine_text:
            return SignalResult(
                name=self.name,
                score=0.0,
                available=False,
                unavailable_reason="Neither page contains comparable text.",
            )

        text_similarity = _similarity(suspect_text, genuine_text)

        suspect_structure = _structure_tokens(suspect_soup)
        genuine_structure = _structure_tokens(genuine_soup)

        structure_similarity = _similarity(
            " ".join(suspect_structure),
            " ".join(genuine_structure),
        )

        suspect_fields = _field_signature(suspect_soup)
        genuine_fields = _field_signature(genuine_soup)

        field_similarity = _similarity(
            " ".join(suspect_fields),
            " ".join(genuine_fields),
        )

        suspect_title = _page_title(suspect.title, suspect_soup)
        genuine_title = _page_title(genuine.title, genuine_soup)
        title_similarity = _similarity(suspect_title, genuine_title)

        # Give page-specific content more influence than generic templates.
        combined_similarity = (
            0.50 * text_similarity
            + 0.10 * structure_similarity
            + 0.10 * field_similarity
            + 0.30 * title_similarity
        )

        different_origin = suspect_origin != genuine_origin

        # A low title match reduces the score when a page only shares
        # generic login structure and common form controls.
        #
        # Identical titles retain the full similarity score.
        distinctiveness_factor = 0.20 + 0.80 * title_similarity

        adjusted_similarity = (
            combined_similarity * distinctiveness_factor
        )

        # Same-origin pages are not treated as clone evidence by this signal.
        score = adjusted_similarity if different_origin else 0.0

        reasons: list[Reason] = []

        evidence = {
            "suspect_origin": suspect_origin,
            "genuine_origin": genuine_origin,
            "text_similarity": round(text_similarity, 3),
            "structure_similarity": round(structure_similarity, 3),
            "field_similarity": round(field_similarity, 3),
            "title_similarity": round(title_similarity, 3),
            "combined_similarity": round(combined_similarity, 3),
            "distinctiveness_factor": round(distinctiveness_factor, 3),
            "adjusted_similarity": round(adjusted_similarity, 3),
        }

        if different_origin and score >= 0.75:
            reasons.append(
                Reason(
                    code="DOM_HIGH_PAGE_SIMILARITY",
                    title="Page content closely resembles the genuine site",
                    detail=(
                        "The page shares substantial content with the genuine "
                        "reference, including page-specific text or title "
                        "similarity. Review the other signals before deciding "
                        "whether it is a clone."
                    ),
                    severity=Severity.high,
                    signal=self.name,
                    evidence=evidence,
                )
            )
        elif different_origin and score >= 0.40:
            reasons.append(
                Reason(
                    code="DOM_MODERATE_PAGE_SIMILARITY",
                    title="Some page content resembles the genuine site",
                    detail=(
                        "The page shares some content with the genuine "
                        "reference. Generic layouts and common login fields "
                        "receive less weight; similarity alone does not prove "
                        "a clone."
                    ),
                    severity=Severity.medium,
                    signal=self.name,
                    evidence=evidence,
                )
            )

        return SignalResult(
            name=self.name,
            score=max(0.0, min(1.0, float(score))),
            available=True,
            reasons=reasons,
            metrics={
                "text_similarity": round(text_similarity, 3),
                "structure_similarity": round(structure_similarity, 3),
                "field_similarity": round(field_similarity, 3),
                "title_similarity": round(title_similarity, 3),
                "combined_similarity": round(combined_similarity, 3),
                "distinctiveness_factor": round(distinctiveness_factor, 3),
                "adjusted_similarity": round(adjusted_similarity, 3),
                "different_origin": different_origin,
                "suspect_element_count": len(suspect_structure),
                "genuine_element_count": len(genuine_structure),
                "suspect_field_count": len(suspect_fields),
                "genuine_field_count": len(genuine_fields),
                "reason_count": len(reasons),
            },
        )
