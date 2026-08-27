"""SQLite-backed cache for NVD CVE lookups, keyed by CPE string.

Avoids hammering the NVD API on every scan: a cached result younger than
the TTL is returned without touching the network at all.
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import List, Optional, Union

DEFAULT_CACHE_PATH = Path.home() / ".cache" / "tusk" / "cve_cache.db"
DEFAULT_TTL_SECONDS = 24 * 60 * 60


class CVECache:
    """Caches NVD lookup results (a list of vuln dicts) per CPE string."""

    def __init__(
        self,
        db_path: Union[str, Path, None] = None,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
    ):
        self.db_path = Path(db_path) if db_path else DEFAULT_CACHE_PATH
        self.ttl_seconds = ttl_seconds
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        # A fresh connection per call keeps this safe to use from the
        # multiple worker threads CVELookup runs concurrently.
        return sqlite3.connect(self.db_path, timeout=10)

    def _init_schema(self) -> None:
        conn = self._connect()
        try:
            with conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS cve_cache (
                        cpe TEXT PRIMARY KEY,
                        data TEXT NOT NULL,
                        fetched_at REAL NOT NULL
                    )
                    """
                )
        finally:
            conn.close()

    def get(self, cpe: str) -> Optional[List[dict]]:
        """Return cached vulnerabilities for `cpe`, or None if missing/expired."""
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT data, fetched_at FROM cve_cache WHERE cpe = ?",
                (cpe,),
            ).fetchone()
        finally:
            conn.close()

        if row is None:
            return None

        data, fetched_at = row
        if (time.time() - fetched_at) > self.ttl_seconds:
            return None

        return json.loads(data)

    def set(self, cpe: str, vulnerabilities: List[dict]) -> None:
        conn = self._connect()
        try:
            with conn:
                conn.execute(
                    """
                    INSERT INTO cve_cache (cpe, data, fetched_at)
                    VALUES (?, ?, ?)
                    ON CONFLICT(cpe) DO UPDATE SET
                        data = excluded.data,
                        fetched_at = excluded.fetched_at
                    """,
                    (cpe, json.dumps(vulnerabilities), time.time()),
                )
        finally:
            conn.close()
