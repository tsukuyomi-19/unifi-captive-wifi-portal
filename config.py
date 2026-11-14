import os
from dataclasses import dataclass


def _bool(name: str, default: str = "0") -> bool:
    return os.environ.get(name, default).strip().casefold() in ("1", "true", "yes", "on")


def _expand(name: str, default: str = "") -> str:
    """Env var as a filesystem path, with ~ expanded.

    A missing expanduser here was a real bug: python-ldap received the literal
    string "~/Downloads/..." and failed with a cryptic
    `ValueError: option error` from inside set_option(OPT_X_TLS_NEWCTX).
    """
    return os.path.expanduser(os.environ.get(name, default))


@dataclass
class Config:
    GOOGLE_CLIENT_ID: str
    GOOGLE_CLIENT_SECRET: str
    OAUTH_REDIRECT_URI: str

    # Which directory to ask for a user's OU: "ldap" or "directory".
    IDENTITY_BACKEND: str

    LDAP_HOST: str
    LDAP_PORT: int
    LDAP_CERT_FILE: str
    LDAP_KEY_FILE: str
    LDAP_BASE_DN: str
    LDAP_CA_FILE: str
    LDAP_TLS_INSECURE: bool

    DIRECTORY_SA_FILE: str
    DIRECTORY_IMPERSONATE: str

    UNIFI_HOST: str
    UNIFI_SITE: str
    UNIFI_API_KEY: str
    UNIFI_USER: str
    UNIFI_PASS: str
    UNIFI_MODE: str

    SESSION_DB_PATH: str
    SESSION_TTL_SECONDS: int
    AUTHORIZE_MINUTES: int
    HOSTED_DOMAIN: str
    PORT: int
    CONNECTION_LOG_PATH: str
    BLOCKLIST_FILE: str
    POLICY_FILE: str

    # Number of proxies in front of the app. 1 when nginx terminates TLS.
    # Without this the app sees http:// on every request and OAuth token
    # exchange fails against an https:// redirect URI - see app.py.
    TRUST_PROXY_HOPS: int

    # --- guest access codes -------------------------------------------------
    # Master switch. Off means /guest and /staff/vouchers 404, so the feature
    # can be deployed dark and enabled once the office has codes to hand out.
    VOUCHERS_ENABLED: bool
    VOUCHER_DB_PATH: str
    # Brute-force limits. The codes are 10 digits and the guest is on an OPEN
    # SSID, so an unbounded attempt rate makes the keyspace irrelevant.
    # Counted per MAC and per source address: a MAC is spoofable, an address is
    # shared behind NAT, so either alone is weak.
    VOUCHER_MAX_ATTEMPTS: int
    VOUCHER_ATTEMPT_WINDOW: int
    # Signs the staff session cookie for /staff/vouchers. Generated per
    # deployment; rotating it just logs staff out.
    SECRET_KEY: str
    # How long a staff member stays signed in to the voucher page.
    STAFF_SESSION_MINUTES: int

    @classmethod
    def from_env(cls) -> "Config":
        mode = os.environ.get("UNIFI_MODE", "apikey").strip().casefold()
        # The deployed .env predates named modes and says "real", which meant
        # the username/password client.
        if mode == "real":
            mode = "login"

        return cls(
            GOOGLE_CLIENT_ID=os.environ["GOOGLE_CLIENT_ID"],
            GOOGLE_CLIENT_SECRET=os.environ["GOOGLE_CLIENT_SECRET"],
            OAUTH_REDIRECT_URI=os.environ["OAUTH_REDIRECT_URI"],
            IDENTITY_BACKEND=os.environ.get("IDENTITY_BACKEND", "ldap"),
            LDAP_HOST=os.environ.get("LDAP_HOST", "ldap.google.com"),
            LDAP_PORT=int(os.environ.get("LDAP_PORT", "636")),
            # Optional so that IDENTITY_BACKEND=directory needs no LDAP config
            # at all; preflight.py checks the pair the chosen backend requires.
            LDAP_CERT_FILE=_expand("LDAP_CERT_FILE"),
            LDAP_KEY_FILE=_expand("LDAP_KEY_FILE"),
            LDAP_BASE_DN=os.environ.get("LDAP_BASE_DN", "ou=Users,dc=example,dc=org"),
            LDAP_CA_FILE=_expand("LDAP_CA_FILE"),
            LDAP_TLS_INSECURE=_bool("LDAP_TLS_INSECURE"),
            DIRECTORY_SA_FILE=_expand("DIRECTORY_SA_FILE"),
            DIRECTORY_IMPERSONATE=os.environ.get("DIRECTORY_IMPERSONATE", ""),
            UNIFI_HOST=os.environ.get("UNIFI_HOST", ""),
            UNIFI_SITE=os.environ.get("UNIFI_SITE", "default"),
            UNIFI_API_KEY=os.environ.get("UNIFI_API_KEY", ""),
            UNIFI_USER=os.environ.get("UNIFI_USER", ""),
            UNIFI_PASS=os.environ.get("UNIFI_PASS", ""),
            UNIFI_MODE=mode,
            SESSION_DB_PATH=os.environ.get("SESSION_DB_PATH", "./instance/sessions.db"),
            SESSION_TTL_SECONDS=int(os.environ.get("SESSION_TTL_SECONDS", "600")),
            AUTHORIZE_MINUTES=int(os.environ.get("AUTHORIZE_MINUTES", "43200")),
            HOSTED_DOMAIN=os.environ.get("HOSTED_DOMAIN", "example.org"),
            PORT=int(os.environ.get("PORT", "5000")),
            CONNECTION_LOG_PATH=os.environ.get(
                "CONNECTION_LOG_PATH", "./instance/connections.log"
            ),
            BLOCKLIST_FILE=os.environ.get("BLOCKLIST_FILE", "./instance/block_email.txt"),
            POLICY_FILE=os.environ.get("POLICY_FILE", "./instance/ou-policy.conf"),
            TRUST_PROXY_HOPS=int(os.environ.get("TRUST_PROXY_HOPS", "0")),
            VOUCHERS_ENABLED=_bool("VOUCHERS_ENABLED"),
            VOUCHER_DB_PATH=os.environ.get("VOUCHER_DB_PATH",
                                           "./instance/vouchers.db"),
            VOUCHER_MAX_ATTEMPTS=int(os.environ.get("VOUCHER_MAX_ATTEMPTS", "5")),
            VOUCHER_ATTEMPT_WINDOW=int(
                os.environ.get("VOUCHER_ATTEMPT_WINDOW", "900")),
            SECRET_KEY=os.environ.get("SECRET_KEY", ""),
            STAFF_SESSION_MINUTES=int(
                os.environ.get("STAFF_SESSION_MINUTES", "60")),
        )
