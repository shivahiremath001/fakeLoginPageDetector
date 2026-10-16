"""
utils/urls.py — URL normalization, origin extraction, and action resolution.

All functions are pure (no I/O, no network).
Inputs:  raw URL strings
Outputs: normalized strings or None
Failure: all functions return a safe default (empty string or None) on bad input;
         they never raise.
"""
from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse, urlunparse


# Schemes we consider safe to fetch
ALLOWED_SCHEMES: frozenset[str] = frozenset({"http", "https"})

# Default ports per scheme — omitted from origin_key
_DEFAULT_PORTS: dict[str, int] = {"http": 80, "https": 443}


# Schemes that are dangerous and must never receive the http:// prefix treatment
_BLOCKED_SCHEME_PREFIXES: tuple[str, ...] = (
    "javascript:",
    "data:",
    "vbscript:",
    "blob:",
    "file:",
    "ftp:",
    "ftps:",
)


def normalize_url(raw: str) -> str | None:
    """
    Add a scheme if missing; strip leading/trailing whitespace.
    Return None for unsafe schemes (file:, data:, javascript:, etc.).

    Inputs:  raw URL string from user input
    Outputs: normalized URL string, or None if the URL is unusable
    Failure: returns None; never raises
    """
    if not raw:
        return None
    raw = raw.strip()

    # Reject dangerous non-http schemes *before* we add a prefix.
    # These schemes may not contain :// so we check the raw prefix.
    raw_lower = raw.lower()
    for blocked in _BLOCKED_SCHEME_PREFIXES:
        if raw_lower.startswith(blocked):
            return None

    # Add scheme if missing (only when no scheme-like prefix is present)
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", raw):
        raw = "http://" + raw
    try:
        parsed = urlparse(raw)
    except Exception:
        return None

    if parsed.scheme not in ALLOWED_SCHEMES:
        return None
    if not parsed.netloc:
        return None

    return urlunparse(parsed)


def origin_key(url: str) -> str:
    """
    Return a lowercase "host:port" string for the given URL.

    Default ports (80 for http, 443 for https) are omitted so that
    http://example.com:80/ and http://example.com/ share the same key.
    Scheme is excluded so that localhost:5001 is the key regardless of http/https.

    Inputs:  any URL string
    Outputs: "host:port" string, or "" on parse error
    Failure: returns ""; never raises
    """
    if not url:
        return ""
    try:
        parsed = urlparse(url)
    except Exception:
        return ""

    host = (parsed.hostname or "").lower()
    scheme = (parsed.scheme or "http").lower()

    if parsed.port:
        port = parsed.port
        if port == _DEFAULT_PORTS.get(scheme):
            return host
        return f"{host}:{port}"
    return host


def resolve_action(action: str, page_url: str) -> str:
    """
    Resolve a form action attribute against the page's final URL.

    An empty action means the form posts back to the current page.
    A relative path is resolved relative to page_url.

    Inputs:  action — the raw form action attribute value
             page_url — the final URL of the page that contains the form
    Outputs: absolute URL string, or "" on resolution failure
    Failure: returns ""; never raises
    """
    if not page_url:
        return ""
    try:
        if not action:
            # Empty action → same page
            return page_url
        return urljoin(page_url, action)
    except Exception:
        return ""


def is_same_origin(url_a: str, url_b: str) -> bool:
    """
    Return True if both URLs share the same scheme-less host:port.

    Inputs:  two URL strings
    Outputs: bool
    Failure: returns False; never raises
    """
    return bool(url_a and url_b and origin_key(url_a) == origin_key(url_b))


def extract_hostname(url: str) -> str:
    """
    Return just the hostname (no port, no scheme) from a URL.

    Inputs:  URL string
    Outputs: lowercase hostname string, or ""
    Failure: returns ""; never raises
    """
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""
