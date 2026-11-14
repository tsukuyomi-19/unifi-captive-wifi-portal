import time


def test_create_and_consume_session(session_store):
    state = session_store.create_session("AA:BB:CC:DD:EE:FF", "Student WiFi")
    row = session_store.consume_session(state)
    assert row is not None
    assert row["mac"] == "AA:BB:CC:DD:EE:FF"
    assert row["ssid"] == "Student WiFi"


def test_consuming_twice_fails(session_store):
    state = session_store.create_session("AA:BB:CC:DD:EE:FF", "Student WiFi")
    assert session_store.consume_session(state) is not None
    assert session_store.consume_session(state) is None


def test_next_url_round_trips(session_store):
    state = session_store.create_session(
        "AA:BB:CC:DD:EE:FF", "Campus Student", next_url="https://example.org/x"
    )
    assert session_store.consume_session(state)["next_url"] == "https://example.org/x"


def test_next_url_defaults_to_null(session_store):
    state = session_store.create_session("AA:BB:CC:DD:EE:FF", "Campus Student")
    assert session_store.consume_session(state)["next_url"] is None


def test_init_db_migrates_a_pre_next_url_table(tmp_path):
    """A database created by the previous schema must survive the upgrade -
    otherwise every INSERT fails until someone deletes the file."""
    import sqlite3

    from session_store import SessionStore

    path = str(tmp_path / "old.db")
    with sqlite3.connect(path) as conn:
        conn.execute(
            "CREATE TABLE oauth_sessions (state TEXT PRIMARY KEY, mac TEXT NOT NULL, "
            "ssid TEXT NOT NULL, expires INTEGER NOT NULL)"
        )

    store = SessionStore(path)
    store.init_db()
    state = store.create_session("AA:BB:CC:DD:EE:FF", "Campus Student", next_url="https://x.test")
    assert store.consume_session(state)["next_url"] == "https://x.test"


def test_init_db_creates_missing_parent_directory(tmp_path):
    from session_store import SessionStore

    store = SessionStore(str(tmp_path / "nested" / "dir" / "sessions.db"))
    store.init_db()
    assert store.consume_session(store.create_session("A", "B")) is not None


def test_unknown_state_returns_none(session_store):
    assert session_store.consume_session("does-not-exist") is None


def test_expired_session_returns_none(session_store):
    state = session_store.create_session("AA:BB:CC:DD:EE:FF", "Student WiFi", ttl_seconds=-1)
    assert session_store.consume_session(state) is None


def test_cleanup_expired_removes_stale_rows(session_store):
    session_store.create_session("AA:BB:CC:DD:EE:FF", "Student WiFi", ttl_seconds=-1)
    session_store.create_session("11:22:33:44:55:66", "Campus Staff", ttl_seconds=600)
    session_store.cleanup_expired()

    with session_store._conn() as conn:
        rows = conn.execute("SELECT * FROM oauth_sessions").fetchall()
    assert len(rows) == 1
    assert rows[0]["mac"] == "11:22:33:44:55:66"
