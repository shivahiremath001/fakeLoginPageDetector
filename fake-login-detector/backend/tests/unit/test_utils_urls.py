"""
tests/unit/test_utils_urls.py — Unit tests for utils/urls.py.
All inputs and expected outputs are inline (no network required).
"""
from __future__ import annotations

import pytest
from app.utils.urls import (
    extract_hostname,
    is_same_origin,
    normalize_url,
    origin_key,
    resolve_action,
)


class TestNormalizeUrl:
    def test_adds_scheme(self):
        assert normalize_url("example.com") == "http://example.com"

    def test_keeps_https(self):
        assert normalize_url("https://example.com") == "https://example.com"

    def test_strips_whitespace(self):
        assert normalize_url("  http://evil.com  ") == "http://evil.com"

    def test_rejects_file_scheme(self):
        assert normalize_url("file:///etc/passwd") is None

    def test_rejects_javascript(self):
        assert normalize_url("javascript:alert(1)") is None

    def test_rejects_data_url(self):
        assert normalize_url("data:text/html,<h1>hi</h1>") is None

    def test_empty_string(self):
        assert normalize_url("") is None

    def test_localhost_with_port(self):
        result = normalize_url("http://localhost:5001/login")
        assert result == "http://localhost:5001/login"


class TestOriginKey:
    def test_http_default_port_omitted(self):
        assert origin_key("http://example.com:80/") == "example.com"

    def test_https_default_port_omitted(self):
        assert origin_key("https://example.com:443/") == "example.com"

    def test_non_default_port_included(self):
        assert origin_key("http://localhost:5001") == "localhost:5001"

    def test_different_ports_different_keys(self):
        assert origin_key("http://localhost:5001") != origin_key("http://localhost:5002")

    def test_lowercased(self):
        assert origin_key("http://EXAMPLE.COM") == "example.com"

    def test_empty_string(self):
        assert origin_key("") == ""

    def test_no_port(self):
        assert origin_key("https://portal.college.edu/login") == "portal.college.edu"


class TestResolveAction:
    def test_empty_action_returns_page_url(self):
        assert resolve_action("", "http://example.com/login") == "http://example.com/login"

    def test_relative_action(self):
        result = resolve_action("/submit", "http://example.com/login")
        assert result == "http://example.com/submit"

    def test_absolute_action(self):
        result = resolve_action("http://evil.com/steal", "http://example.com/login")
        assert result == "http://evil.com/steal"

    def test_empty_page_url(self):
        assert resolve_action("/submit", "") == ""

    def test_relative_path(self):
        result = resolve_action("collect.php", "http://example.com/login/")
        assert result == "http://example.com/login/collect.php"


class TestIsSameOrigin:
    def test_same_host(self):
        assert is_same_origin("http://example.com/a", "http://example.com/b")

    def test_different_ports(self):
        assert not is_same_origin("http://localhost:5001", "http://localhost:5002")

    def test_default_port_equivalence(self):
        assert is_same_origin("http://example.com:80", "http://example.com/path")

    def test_different_hosts(self):
        assert not is_same_origin("http://evil.com", "http://example.com")

    def test_empty_strings(self):
        assert not is_same_origin("", "")


class TestExtractHostname:
    def test_basic(self):
        assert extract_hostname("http://example.com/path") == "example.com"

    def test_with_port(self):
        assert extract_hostname("http://localhost:5001") == "localhost"

    def test_empty(self):
        assert extract_hostname("") == ""
