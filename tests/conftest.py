import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from config import Config
from policy import parse_policy
from session_store import SessionStore
from unifi_client import MockUniFiClient

# Mirrors ou-policy.conf.example, but with staff enabled on the staff SSID so
# both roles are exercised. Kept deliberately small so each test's expected
# behaviour is obvious from this one block.
TEST_POLICY_TEXT = """
[roles]
ou=_DISABLE ME -> disabled
ou=Non-Standard Accounts -> disabled
ou=Students -> student
ou=Staff & Teachers -> staff
/Students -> student
/Staff & Teachers -> staff

[ssids]
Campus Student -> student
Campus Staff -> staff
"""

# Real DN shapes, enumerated from the live directory on 2026-08-03.
STUDENT_DN = "uid=jstudent,ou=2027-2028,ou=Students,ou=Users,dc=example,dc=org"
STAFF_DN = (
    "uid=astaff,ou=High School Staff,ou=Staff,ou=Staff & Teachers,"
    "ou=Users,dc=example,dc=org"
)
# A teacher's DN has no "ou=Staff" component of its own - it is only covered
# because "ou=Staff & Teachers" is an ancestor.
TEACHER_DN = (
    "uid=ateacher,ou=High School Teachers,ou=Teachers,ou=Staff & Teachers,"
    "ou=Users,dc=example,dc=org"
)
# Disabled accounts live here, including former students filed by graduation year.
# Critically, this DN contains no "ou=Students" component.
DISABLED_STUDENT_DN = (
    "uid=alumnus,ou=2025-2026,ou=_DISABLE ME,ou=Users,dc=example,dc=org"
)
SERVICE_ACCOUNT_DN = (
    "uid=svc,ou=Non-User & Group Accounts,ou=Non-Standard Accounts,"
    "ou=Users,dc=example,dc=org"
)


def make_config(tmp_path, **overrides):
    defaults = dict(
        GOOGLE_CLIENT_ID="test-client-id",
        GOOGLE_CLIENT_SECRET="test-secret",
        OAUTH_REDIRECT_URI="http://localhost:5000/callback",
        IDENTITY_BACKEND="ldap",
        LDAP_HOST="ldap.google.com",
        LDAP_PORT=636,
        LDAP_CERT_FILE="/dev/null",
        LDAP_KEY_FILE="/dev/null",
        LDAP_BASE_DN="ou=Users,dc=example,dc=org",
        LDAP_CA_FILE="",
        LDAP_TLS_INSECURE=False,
        DIRECTORY_SA_FILE="",
        DIRECTORY_IMPERSONATE="",
        UNIFI_HOST="",
        UNIFI_SITE="default",
        UNIFI_API_KEY="",
        UNIFI_USER="",
        UNIFI_PASS="",
        UNIFI_MODE="mock",
        SESSION_DB_PATH=str(tmp_path / "sessions.db"),
        SESSION_TTL_SECONDS=600,
        AUTHORIZE_MINUTES=43200,
        HOSTED_DOMAIN="example.org",
        PORT=5000,
        CONNECTION_LOG_PATH=str(tmp_path / "connections.log"),
        BLOCKLIST_FILE=str(tmp_path / "block_email.txt"),
        POLICY_FILE=str(tmp_path / "ou-policy.conf"),
        TRUST_PROXY_HOPS=0,
        # Guest access codes are ON in tests so the routes are exercised; the
        # production default is off, so the feature can ship dark.
        VOUCHERS_ENABLED=True,
        VOUCHER_DB_PATH=str(tmp_path / "vouchers.db"),
        VOUCHER_MAX_ATTEMPTS=5,
        VOUCHER_ATTEMPT_WINDOW=900,
        SECRET_KEY="test-secret-key-not-for-production",
        STAFF_SESSION_MINUTES=60,
    )
    defaults.update(overrides)
    return Config(**defaults)


class FakeIdentity:
    """Stands in for either OU-lookup backend: email -> raw OU path."""

    def __init__(self, mapping=None):
        self.mapping = mapping or {}
        self.queried: list[str] = []

    def lookup_ou_path(self, email):
        self.queried.append(email)
        return self.mapping.get(email)


@pytest.fixture
def policy():
    return parse_policy(TEST_POLICY_TEXT)


@pytest.fixture
def session_store(tmp_path):
    store = SessionStore(str(tmp_path / "sessions.db"))
    store.init_db()
    return store


@pytest.fixture
def mock_unifi():
    return MockUniFiClient()
