"""
cache.py — TTL cache for genuine page snapshots and scan results.

Full implementation in Phase 3. Phase 0 provides the interface only.
"""
from __future__ import annotations

import time
from typing import Any, Optional


class TTLCache:
    """
    Simple in-memory TTL cache.

    Inputs:  ttl_seconds — how long entries live
    Outputs: stored and retrieved values
    Failure: get() returns None for missing/expired keys; never raises
    """

    def __init__(self, ttl_seconds: int) -> None:
        self._ttl = ttl_seconds
        self._store: dict[str, tuple[Any, float]] = {}

    def get(self, key: str) -> Optional[Any]:
        """Return the cached value or None if missing/expired."""
        entry = self._store.get(key)
        if entry is None:
            return None
        value, expires_at = entry
        if time.monotonic() > expires_at:
            del self._store[key]
            return None
        return value

    def set(self, key: str, value: Any) -> None:
        """Store a value with the configured TTL."""
        self._store[key] = (value, time.monotonic() + self._ttl)

    def clear(self) -> None:
        """Remove all entries."""
        self._store.clear()
