"""Google Admin Directory OU lookup - alternative to Secure LDAP.

Returns the account's orgUnitPath (e.g. "/Students"). Classification into a
role is policy.Policy's job.

Why offer this alongside LDAP
-----------------------------
The 2025 Node implementation of this same system used the Directory API and it
worked. The 2026 Python rewrite switched to Secure LDAP, which cost days:
python-ldap needs a compiler plus libsasl2/libldap/libssl headers, the cert and
key paths have to be right (a missing os.path.expanduser produced a
`ValueError: option error` from deep inside set_option), and the TLS options are
silently ignored unless OPT_X_TLS_NEWCTX is set last. None of that applies here
- this backend is a pip install and a service-account JSON file.

LDAP remains the default because it is the configuration currently proven on
the server. This is the recommended migration target: fewer moving parts, and
one less credential (the LDAP cert/key) to rotate in 2029.

Setup
-----
1. Google Cloud Console -> the project already holding the OAuth client ->
   Create a service account. No IAM roles needed.
2. Create a JSON key for it; put it on the server, chmod 600.
3. Note the service account's numeric Client ID.
4. Google Admin Console -> Security -> Access and data control -> API controls
   -> Domain-wide delegation -> Add new. Client ID from step 3, scope:
     https://www.googleapis.com/auth/admin.directory.user.readonly
5. Set IDENTITY_BACKEND=directory, DIRECTORY_SA_FILE=/path/key.json,
   DIRECTORY_IMPERSONATE=an-admin@example.org

Domain-wide delegation means this key can read every user in the domain, so it
is a high-value credential: keep it 600, off shared storage, and out of git.
"""

from __future__ import annotations

import logging

logger = logging.getLogger("wifi_portal.directory")

SCOPES = ["https://www.googleapis.com/auth/admin.directory.user.readonly"]


class DirectoryOuLookup:
    def __init__(self, sa_file: str, impersonate: str):
        self.sa_file = sa_file
        self.impersonate = impersonate
        self._service = None

    def _build(self):
        # Imported lazily so that installations using IDENTITY_BACKEND=ldap do
        # not need google-api-python-client present at all.
        from google.oauth2 import service_account
        from googleapiclient.discovery import build

        creds = service_account.Credentials.from_service_account_file(
            self.sa_file, scopes=SCOPES, subject=self.impersonate
        )
        return build("admin", "directory_v1", credentials=creds, cache_discovery=False)

    def lookup_ou_path(self, email: str) -> str | None:
        """Return the account's orgUnitPath, or None if absent / on error."""
        try:
            if self._service is None:
                self._service = self._build()
            user = self._service.users().get(userKey=email, fields="orgUnitPath,suspended").execute()
        except Exception as e:  # googleapiclient raises a wide range of types
            # A 404 here means "no such account", which is a legitimate outcome
            # rather than a fault, but the client surfaces it the same way as a
            # transport error, so log it and let the caller deny.
            logger.error("Directory lookup failed for %s: %s", email, e)
            return None

        if user.get("suspended"):
            # A suspended account still has an orgUnitPath and would otherwise
            # classify normally and be granted WiFi. LDAP has no equivalent
            # cheap check, which is a genuine advantage of this backend.
            logger.info("denying suspended account %s", email)
            return None

        return user.get("orgUnitPath")


def build_identity_lookup(config):
    """Construct the OU lookup named by config.IDENTITY_BACKEND.

    Both backends expose the same single method, lookup_ou_path(email) -> str|None.
    """
    backend = (config.IDENTITY_BACKEND or "").strip().casefold()
    if backend == "directory":
        if not config.DIRECTORY_SA_FILE or not config.DIRECTORY_IMPERSONATE:
            raise ValueError(
                "IDENTITY_BACKEND=directory requires DIRECTORY_SA_FILE and DIRECTORY_IMPERSONATE"
            )
        return DirectoryOuLookup(config.DIRECTORY_SA_FILE, config.DIRECTORY_IMPERSONATE)
    if backend == "ldap":
        from ldap_client import LdapOuLookup

        return LdapOuLookup(
            config.LDAP_HOST,
            config.LDAP_PORT,
            config.LDAP_CERT_FILE,
            config.LDAP_KEY_FILE,
            config.LDAP_BASE_DN,
            ca_file=config.LDAP_CA_FILE,
            insecure=config.LDAP_TLS_INSECURE,
        )
    raise ValueError(f"IDENTITY_BACKEND must be ldap or directory, got {config.IDENTITY_BACKEND!r}")
