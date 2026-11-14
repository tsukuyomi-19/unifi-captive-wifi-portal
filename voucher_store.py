"""Redemption state and brute-force limiting for guest access codes.

Why this exists at all
----------------------
The controller runs `auth=custom`, so UniFi hands authentication entirely to this
app and never observes a redemption. Its own voucher `used` counter therefore
stays at 0 forever and cannot be used to enforce single-use, device counts or
expiry. UniFi is only the *registry* of which codes exist; this module owns
whether a code has been redeemed, by which devices, and until when.

Why rate limiting is not optional
---------------------------------
The codes UniFi generates are 10 digits, and the guest entering one is sitting on
an *open* SSID with unlimited attempts. 10^10 is a respectable keyspace only if
the attempt rate is bounded; without that, code length is irrelevant. Attempts
are counted per MAC and per source address, because a MAC is trivially spoofable
and an address is shared behind NAT - either alone is weak.

Expiry is computed at FIRST USE, not at issue
---------------------------------------------
A code handed out at 4pm would otherwise be nearly worthless. `first_used` is
recorded once, the expiry is derived from it, and every later device on the same
code inherits that same deadline - so a code cannot be renewed indefinitely by
adding devices.
"""

from __future__ import annotations

import os
import sqlite3
import time


class VoucherStore:
    def __init__(self, db_path: str):
        self.db_path = db_path

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def init_db(self) -> None:
        parent = os.path.dirname(self.db_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with self._conn() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS voucher_use (
                    code       TEXT PRIMARY KEY,
                    class      TEXT NOT NULL,
                    first_used INTEGER NOT NULL,
                    expires    INTEGER NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS voucher_device (
                    code        TEXT NOT NULL,
                    mac         TEXT NOT NULL,
                    redeemed_at INTEGER NOT NULL,
                    PRIMARY KEY (code, mac)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS voucher_attempt (
                    bucket TEXT NOT NULL,
                    ts     INTEGER NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_attempt ON voucher_attempt(bucket, ts)"
            )

    # ---------------------------------------------------------------- attempts

    def record_attempt(self, bucket: str) -> None:
        """Log a failed redemption against a bucket ("mac:..." or "ip:...")."""
        with self._conn() as conn:
            conn.execute("INSERT INTO voucher_attempt (bucket, ts) VALUES (?, ?)",
                         (bucket, int(time.time())))

    def recent_attempts(self, bucket: str, window_seconds: int) -> int:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS n FROM voucher_attempt "
                "WHERE bucket = ? AND ts > ?",
                (bucket, int(time.time()) - window_seconds),
            ).fetchone()
        return int(row["n"] or 0)

    def clear_attempts(self, bucket: str) -> None:
        """Called after a success, so one good entry resets the counter."""
        with self._conn() as conn:
            conn.execute("DELETE FROM voucher_attempt WHERE bucket = ?", (bucket,))

    def purge_attempts(self, older_than_seconds: int = 86400) -> int:
        with self._conn() as conn:
            cur = conn.execute("DELETE FROM voucher_attempt WHERE ts < ?",
                               (int(time.time()) - older_than_seconds,))
        return cur.rowcount or 0

    # -------------------------------------------------------------- redemption

    def get_use(self, code: str) -> sqlite3.Row | None:
        with self._conn() as conn:
            return conn.execute("SELECT * FROM voucher_use WHERE code = ?",
                                (code,)).fetchone()

    def begin_or_get(self, code: str, klass: str, expires_at: int) -> sqlite3.Row:
        """Record first use, or return the existing record.

        `expires_at` is only honoured for the FIRST redemption; later devices
        inherit the original deadline. INSERT OR IGNORE makes this safe when two
        devices redeem the same code simultaneously - one insert wins and both
        read back the same row, rather than the second overwriting the deadline.
        """
        now = int(time.time())
        with self._conn() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO voucher_use "
                "(code, class, first_used, expires) VALUES (?, ?, ?, ?)",
                (code, klass, now, int(expires_at)),
            )
            return conn.execute("SELECT * FROM voucher_use WHERE code = ?",
                                (code,)).fetchone()

    def record_device(self, code: str, mac: str) -> None:
        with self._conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO voucher_device "
                "(code, mac, redeemed_at) VALUES (?, ?, ?)",
                (code, mac.strip().casefold(), int(time.time())),
            )

    def device_count(self, code: str) -> int:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS n FROM voucher_device WHERE code = ?", (code,)
            ).fetchone()
        return int(row["n"] or 0)

    def has_device(self, code: str, mac: str) -> bool:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT 1 FROM voucher_device WHERE code = ? AND mac = ?",
                (code, mac.strip().casefold()),
            ).fetchone()
        return row is not None

    def devices_for(self, code: str) -> list[str]:
        with self._conn() as conn:
            return [r["mac"] for r in conn.execute(
                "SELECT mac FROM voucher_device WHERE code = ? ORDER BY redeemed_at",
                (code,))]

    def forget(self, code: str) -> None:
        """Drop all local state for a code, so a re-issued code starts clean."""
        with self._conn() as conn:
            conn.execute("DELETE FROM voucher_use WHERE code = ?", (code,))
            conn.execute("DELETE FROM voucher_device WHERE code = ?", (code,))
