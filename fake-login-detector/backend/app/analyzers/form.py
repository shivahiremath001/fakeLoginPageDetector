
"""Detect risky login-form submission behavior."""
from __future__ import annotations

from urllib.parse import urlparse

from app.models import (
    Reason,
    ScanContext,
    Severity,
    SignalResult,
)
from app.utils.urls import origin_key


def _origin(url: str) -> str:
    """Return a normalized host-and-port key, or an empty string."""
    if not url:
        return ""
    try:
        parsed = urlparse(url.strip())
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return ""
        # origin_key handles default ports and malformed URLs safely.
        return origin_key(url)
    except (ValueError, TypeError):
        return ""


def _form_action_origin(form) -> str:
    """Resolve the best available action origin from a FormInfo."""
    return _origin(form.action_resolved or form.action_origin)


def _trusted_origins(ctx: ScanContext) -> set[str]:
    """Collect origins that are explicitly trusted for this brand."""
    trusted: set[str] = set()

    if ctx.brand is not None:
        for url in [
            *ctx.brand.genuine_urls,
            *ctx.brand.origins,
            *ctx.brand.trusted_related_origins,
        ]:
            key = _origin(url)
            if key:
                trusted.add(key)

        # A genuine site's existing form actions are useful references.
        if ctx.genuine is not None:
            for form in ctx.genuine.forms:
                key = _form_action_origin(form)
                if key:
                    trusted.add(key)

    return trusted


def _reason(
    *,
    code: str,
    title: str,
    detail: str,
    severity: Severity,
    evidence: dict,
) -> Reason:
    return Reason(
        code=code,
        title=title,
        detail=detail,
        severity=severity,
        signal="form",
        evidence=evidence,
    )


class FormAnalyzer:
    """Analyze form actions without submitting forms or entering credentials."""

    name = "form"

    async def analyze(self, ctx: ScanContext) -> SignalResult:
        suspect = ctx.suspect
        page_url = suspect.final_url or suspect.requested_url
        page_origin = _origin(page_url)

        if not page_origin:
            return SignalResult(
                name=self.name,
                score=0.0,
                available=False,
                unavailable_reason="The suspect page has no valid HTTP(S) origin.",
            )

        forms = suspect.forms
        reasons: list[Reason] = []
        score = 0.0
        trusted_origins = _trusted_origins(ctx)

        # A different destination is not inherently malicious. Use the
        # genuine page and explicit trusted-origin configuration as context.
        genuine_password_forms = [
            form for form in (ctx.genuine.forms if ctx.genuine else [])
            if form.has_password
        ]
        genuine_password_actions = {
            _form_action_origin(form)
            for form in genuine_password_forms
            if _form_action_origin(form)
        }

        for index, form in enumerate(forms):
            action_origin = _form_action_origin(form)
            evidence = {
                "form_index": index,
                "method": form.method.lower(),
                "has_password": form.has_password,
                "action_origin": action_origin or None,
                "action_url": form.action_resolved or None,
                "page_origin": page_origin,
            }

            # Passwords submitted through GET may be exposed in URL
            # parameters, browser history, logs, and referrer data.
            if form.has_password and form.method.lower() == "get":
                score = max(score, 0.75)
                reasons.append(
                    _reason(
                        code="FORM_PASSWORD_GET",
                        title="Password form uses GET",
                        detail=(
                            "This form contains a password field but uses "
                            "GET, which can expose submitted values in the URL."
                        ),
                        severity=Severity.high,
                        evidence=evidence,
                    )
                )

            if form.has_password and form.is_http:
                # HTTP is a transport-security concern, not proof of cloning.
                # Do not add clone-risk score when this form matches the genuine
                # reference's password-form action on the same page origin.
                matches_genuine_action = action_origin in genuine_password_actions
                matches_genuine_origin = action_origin == page_origin
                if not (matches_genuine_action and matches_genuine_origin):
                    score = max(score, 0.85)

                reasons.append(
                    _reason(
                        code="FORM_PASSWORD_HTTP",
                        title="Password form uses an insecure HTTP action",
                        detail=(
                            "The password form submits over unencrypted HTTP, "
                            "so its data may be exposed in transit. This is a "
                            "transport-security warning, not proof of cloning."
                        ),
                        severity=Severity.high,
                        evidence=evidence,
                    )
                )

            # Prefer the explicit model flag, but also compare origins
            # ourselves when a resolved action URL is available.
            is_cross_origin = bool(
                form.is_cross_origin
                or (action_origin and action_origin != page_origin)
            )

            if not is_cross_origin:
                continue

            if not form.has_password:
                # Cross-origin non-password forms can be normal analytics,
                # search, or support forms. Keep this a weak signal.
                score = max(score, 0.10)
                continue

            is_trusted = action_origin in trusted_origins
            matches_genuine_action = (
                action_origin in genuine_password_actions
            )

            if is_trusted or matches_genuine_action:
                continue

            # If a genuine page exists and its password forms submit only
            # to its own/trusted origin, an unexpected destination is more
            # concerning than a cross-origin action without a reference.
            if genuine_password_forms:
                score = max(score, 0.95)
                detail = (
                    "The password form submits to an origin not used by "
                    "the genuine page's password forms or trusted origins."
                )
            else:
                score = max(score, 0.70)
                detail = (
                    "The password form submits to a different origin that "
                    "is not listed among this brand's trusted origins."
                )

            reasons.append(
                _reason(
                    code="FORM_PASSWORD_FOREIGN_ACTION",
                    title="Password form submits to an untrusted origin",
                    detail=detail,
                    severity=Severity.critical,
                    evidence=evidence,
                )
            )

        return SignalResult(
            name=self.name,
            score=max(0.0, min(1.0, score)),
            available=True,
            reasons=reasons,
            metrics={
                "form_count": len(forms),
                "password_form_count": sum(form.has_password for form in forms),
                "cross_origin_form_count": sum(
                    form.is_cross_origin
                    or (
                        bool(_form_action_origin(form))
                        and _form_action_origin(form) != page_origin
                    )
                    for form in forms
                ),
                "reason_count": len(reasons),
            },
        )
