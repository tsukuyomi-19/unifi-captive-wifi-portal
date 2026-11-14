import os
import secrets
import sqlite3
import time


class SessionStore:
    """Binds a MAC address to a one-time-use OAuth state token, server-side.

    The MAC is captured from UniFi's redirect at /login and never trusted
    from request args again after this point - /callback reads it back out
    of here, keyed only by the opaque state token.
    """

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
                CREATE TABLE IF NOT EXISTS oauth_sessions (
                    state    TEXT PRIMARY KEY,
                    mac      TEXT NOT NULL,
                    ssid     TEXT NOT NULL,
                    expires  INTEGER NOT NULL,
                    next_url TEXT
                )
                """
            )
            # A database created before next_url existed keeps its 4-column
            # table across an upgrade, and every INSERT would then fail. Add the
            # column in place rather than requiring the file be deleted.
            cols = {r["name"] for r in conn.execute("PRAGMA table_info(oauth_sessions)")}
            if "next_url" not in cols:
                conn.execute("ALTER TABLE oauth_sessions ADD COLUMN next_url TEXT")
            # `purpose` distinguishes the captive-portal sign-in from a staff
            # sign-in to the voucher page. Both use the SAME registered OAuth
            # redirect URI, because adding a second one means a change in the
            # Google Cloud console; /callback branches on this instead.
            if "purpose" not in cols:
                conn.execute(
                    "ALTER TABLE oauth_sessions ADD COLUMN purpose TEXT "
                    "NOT NULL DEFAULT 'portal'"
                )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_oauth_sessions_expires ON oauth_sessions(expires)"
            )

    def create_session(
        self, mac: str, ssid: str, ttl_seconds: int = 600, next_url: str | None = None,
        purpose: str = "portal",
    ) -> str:
        state = secrets.token_urlsafe(32)
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO oauth_sessions "
                "(state, mac, ssid, expires, next_url, purpose) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (state, mac, ssid, int(time.time()) + ttl_seconds, next_url, purpose),
            )
        return state

    def read_session(self, state: str) -> sqlite3.Row | None:
        """Look at a session WITHOUT consuming it. Returns None if expired.

        The guest access-code form needs this: a wrong code must not burn the
        binding, or the guest could never retry and the MAC would be lost. The
        row is consumed only once a code actually succeeds. The OAuth flow keeps
        using consume_session, which stays strictly one-time-use.
        """
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM oauth_sessions WHERE state=?",
                               (state,)).fetchone()
        if row is None or time.time() > row["expires"]:
            return None
        return row

    def consume_session(self, state: str) -> sqlite3.Row | None:
        """Read-then-delete (one-time use). Returns None if missing or expired."""
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM oauth_sessions WHERE state=?", (state,)).fetchone()
            conn.execute("DELETE FROM oauth_sessions WHERE state=?", (state,))
        if row is None or time.time() > row["expires"]:
            return None
        return row

    def cleanup_expired(self) -> None:
        with self._conn() as conn:
            conn.execute("DELETE FROM oauth_sessions WHERE expires < ?", (int(time.time()),))
