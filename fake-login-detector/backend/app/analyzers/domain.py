
"""Detect suspicious domain and hostname patterns."""
from __future__ import annotations

import ipaddress
from difflib import SequenceMatcher
from urllib.parse import urlparse

from app.analyzers.base import Analyzer
from app.models import (
    Reason,
    ScanContext,
    Severity,
    SignalResult,
)
from app.utils.confusables import skeleton


def _parse_url(url: str):
    """Parse an HTTP(S) URL safely, returning None when unusable."""
    if not url:
        return None

    try:
        parsed = urlparse(url.strip())
        if parsed.scheme.lower() not in {"http", "https"}:
            return None
        if not parsed.hostname:
            return None

        # Accessing .port can raise ValueError for malformed ports.
        _ = parsed.port
        return parsed
    except (ValueError, TypeError):
        return None


def _hostname(url: str) -> str:
    parsed = _parse_url(url)
    return parsed.hostname.lower().rstrip(".") if parsed else ""


def _known_brand_hosts(ctx: ScanContext) -> set[str]:
    """Collect hostname references from the configured brand."""
    hosts: set[str] = set()
    brand = ctx.brand

    if brand is None:
        return hosts

    for url in [
        *brand.genuine_urls,
        *brand.origins,
        *brand.trusted_related_origins,
    ]:
        host = _hostname(url)
        if host:
            hosts.add(host)

    return hosts


def _registrable_domain(host: str) -> str:
    """Approximate a registrable domain without requiring network access."""
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass

    # Local test hosts do not have a public suffix.
    if host == "localhost" or host.endswith(".localhost"):
        return host

    labels = host.split(".")
    if len(labels) <= 2:
        return host

    # Handle common multi-label public suffixes without network lookups.
    common_two_part_suffixes = {
        "co.uk", "org.uk", "ac.uk", "gov.uk",
        "com.au", "net.au", "org.au",
        "co.in", "firm.in", "net.in", "org.in",
        "com.br", "com.cn", "co.jp",
    }
    suffix = ".".join(labels[-2:])
    if suffix in common_two_part_suffixes and len(labels) >= 3:
        return ".".join(labels[-3:])

    return ".".join(labels[-2:])


def _add_reason(
    reasons: list[Reason],
    *,
    code: str,
    title: str,
    detail: str,
    severity: Severity,
    evidence: dict,
) -> None:
    reasons.append(
        Reason(
            code=code,
            title=title,
            detail=detail,
            severity=severity,
            signal="domain",
            evidence=evidence,
        )
    )


class DomainAnalyzer:
    """Score URL-domain signals and explain every detected concern."""

    name = "domain"

    async def analyze(self, ctx: ScanContext) -> SignalResult:
        url = ctx.suspect.final_url or ctx.suspect.requested_url
        parsed = _parse_url(url)

        if parsed is None:
            return SignalResult(
                name=self.name,
                score=0.0,
                available=False,
                unavailable_reason="The page URL is missing or invalid.",
            )

        host = parsed.hostname.lower().rstrip(".")
        labels = host.split(".")
        reasons: list[Reason] = []
        score = 0.0
        known_hosts = _known_brand_hosts(ctx)

        # A known genuine or trusted hostname should not be flagged merely
        # because its URL contains words such as "login" or "portal".
        is_known_host = any(
            host == known or host.endswith("." + known)
            for known in known_hosts
        )

        if not is_known_host:
            # User-info can make a URL visually misleading:
            # https://trusted.example@attacker.example/
            if parsed.username is not None or parsed.password is not None:
                score = max(score, 0.65)
                _add_reason(
                    reasons,
                    code="DOMAIN_USERINFO_TRICK",
                    title="Misleading URL credentials",
                    detail=(
                        "The URL contains text before the @ symbol that "
                        "could be mistaken for the actual website hostname."
                    ),
                    severity=Severity.high,
                    evidence={"hostname": host},
                )

            try:
                ipaddress.ip_address(host)
                is_ip_address = True
            except ValueError:
                is_ip_address = False

            if is_ip_address:
                score = max(score, 0.45)
                _add_reason(
                    reasons,
                    code="DOMAIN_IP_ADDRESS",
                    title="IP address used as hostname",
                    detail=(
                        "The website is addressed directly by an IP address "
                        "rather than a conventional domain name."
                    ),
                    severity=Severity.medium,
                    evidence={"hostname": host},
                )

            if any(label.startswith("xn--") for label in labels):
                score = max(score, 0.55)
                _add_reason(
                    reasons,
                    code="DOMAIN_PUNYCODE",
                    title="Encoded hostname label",
                    detail=(
                        "The hostname contains an IDN punycode label, which "
                        "can represent international characters resembling "
                        "other letters."
                    ),
                    severity=Severity.medium,
                    evidence={"hostname": host},
                )

            risky_tlds = {
                tld.lower().lstrip(".")
                for tld in ctx.settings.risky_tlds
            }
            tld = labels[-1] if labels else ""

            if tld and tld in risky_tlds:
                score = max(score, 0.25)
                _add_reason(
                    reasons,
                    code="DOMAIN_RISKY_TLD",
                    title="Configured high-risk domain ending",
                    detail=(
                        "The hostname uses a domain ending listed in the "
                        "detector's risk configuration. This alone does not "
                        "prove the website is malicious."
                    ),
                    severity=Severity.low,
                    evidence={"tld": tld},
                )

            keyword_set = {
                word.lower()
                for word in ctx.settings.phishing_keywords
                if word.strip()
            }
            matching_keywords = sorted(
                keyword_set.intersection(labels[:-1])
            )

            if matching_keywords:
                score = max(score, 0.20)
                _add_reason(
                    reasons,
                    code="DOMAIN_SUSPICIOUS_KEYWORD",
                    title="Security-related hostname wording",
                    detail=(
                        "The hostname contains configured words commonly "
                        "used in login or account-verification lures."
                    ),
                    severity=Severity.low,
                    evidence={"keywords": matching_keywords},
                )

            if len(labels) >= 5:
                score = max(score, 0.20)
                _add_reason(
                    reasons,
                    code="DOMAIN_MANY_SUBDOMAINS",
                    title="Unusually deep subdomain structure",
                    detail=(
                        "The hostname has many labels, so check carefully "
                        "which domain actually controls the website."
                    ),
                    severity=Severity.low,
                    evidence={"hostname": host, "label_count": len(labels)},
                )

            # Compare against known brand hostnames, if a brand was matched.
            brand_hosts = {
                known for known in known_hosts
                if known != "localhost"
                and not known.endswith(".localhost")
            }

            suspect_domain = _registrable_domain(host)
            suspect_label = suspect_domain.split(".")[0]
            suspect_skeleton = skeleton(suspect_label)

            best_match: tuple[str, float, bool] | None = None

            for known in brand_hosts:
                genuine_domain = _registrable_domain(known)
                genuine_label = genuine_domain.split(".")[0]

                if not genuine_label or suspect_domain == genuine_domain:
                    continue

                genuine_skeleton = skeleton(genuine_label)
                if not genuine_skeleton or not suspect_skeleton:
                    continue

                similarity = SequenceMatcher(
                    None,
                    suspect_skeleton,
                    genuine_skeleton,
                    autojunk=False,
                ).ratio()

                # A skeleton match is a strong character-confusion signal.
                skeleton_match = (
                    suspect_skeleton == genuine_skeleton
                    and suspect_label.lower() != genuine_label.lower()
                )

                candidate = (genuine_domain, similarity, skeleton_match)
                if best_match is None or (
                    similarity > best_match[1]
                    or skeleton_match and not best_match[2]
                ):
                    best_match = candidate

            if best_match:
                genuine_domain, similarity, skeleton_match = best_match

                if skeleton_match:
                    score = max(score, 0.85)
                    _add_reason(
                        reasons,
                        code="DOMAIN_CONFUSABLE_BRAND",
                        title="Lookalike brand domain",
                        detail=(
                            f"The hostname resembles {genuine_domain} "
                            "after normalizing visually similar characters."
                        ),
                        severity=Severity.high,
                        evidence={
                            "hostname": host,
                            "reference_domain": genuine_domain,
                            "normalized_label": suspect_skeleton,
                        },
                    )
                elif similarity >= 0.80 and len(suspect_label) >= 4:
                    score = max(score, 0.65)
                    _add_reason(
                        reasons,
                        code="DOMAIN_SIMILAR_BRAND",
                        title="Domain resembles a known brand",
                        detail=(
                            f"The domain label resembles {genuine_domain}, "
                            "but uses a different domain."
                        ),
                        severity=Severity.high,
                        evidence={
                            "hostname": host,
                            "reference_domain": genuine_domain,
                            "label_similarity": round(similarity, 3),
                        },
                    )

                # The brand name appearing in a different registrable
                # domain is worth noting, but is not proof by itself.
                brand_tokens = {
                    skeleton(_registrable_domain(known).split(".")[0])
                    for known in brand_hosts
                }
                if (
                    suspect_domain != genuine_domain
                    and any(
                        token and token in skeleton(host)
                        for token in brand_tokens
                    )
                    and not any(
                        r.code in {
                            "DOMAIN_CONFUSABLE_BRAND",
                            "DOMAIN_SIMILAR_BRAND",
                        }
                        for r in reasons
                    )
                ):
                    score = max(score, 0.50)
                    _add_reason(
                        reasons,
                        code="DOMAIN_BRAND_IN_OTHER_DOMAIN",
                        title="Brand name appears in another domain",
                        detail=(
                            "The hostname contains a known brand label, "
                            "but the registrable domain is different."
                        ),
                        severity=Severity.medium,
                        evidence={
                            "hostname": host,
                            "reference_domain": genuine_domain,
                        },
                    )

        return SignalResult(
            name=self.name,
            score=max(0.0, min(1.0, score)),
            available=True,
            reasons=reasons,
            metrics={
                "hostname": host,
                "registrable_domain": _registrable_domain(host),
                "reason_count": len(reasons),
            },
        )
