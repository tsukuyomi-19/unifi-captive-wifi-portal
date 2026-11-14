"""Google Secure LDAP OU lookup via SASL EXTERNAL (client-cert auth, no password).

Returns the raw DN. Turning a DN into a role is policy.Policy's job - see
policy.py for why that mapping is no longer hardcoded here.

Mirrors the confirmed-working manual invocation:
  ldapsearch -H ldaps://ldap.google.com:636 -Y EXTERNAL \
    -b "ou=Users,dc=example,dc=org" "(mail=USER@example.org)" dn
"""

from __future__ import annotations

import logging

import ldap
import ldap.filter
import ldap.sasl

logger = logging.getLogger("wifi_portal.ldap")


class LdapOuLookup:
    def __init__(
        self,
        host: str,
        port: int,
        cert_file: str,
        key_file: str,
        base_dn: str,
        ca_file: str = "",
        insecure: bool = False,
    ):
        self.host = host
        self.port = port
        self.cert_file = cert_file
        self.key_file = key_file
        self.base_dn = base_dn
        self.ca_file = ca_file
        self.insecure = insecure

    def _connect(self) -> ldap.ldapobject.LDAPObject:
        conn = ldap.initialize(f"ldaps://{self.host}:{self.port}")
        conn.set_option(ldap.OPT_X_TLS_CERTFILE, self.cert_file)
        conn.set_option(ldap.OPT_X_TLS_KEYFILE, self.key_file)

        if self.insecure:
            # Previously the unconditional default, which meant ldap.google.com's
            # server certificate was never validated - the client authenticated
            # itself but had no assurance who it was talking to. A MITM on the
            # path could then answer OU lookups, i.e. decide which accounts count
            # as staff. Kept only as an escape hatch for a broken local CA
            # bundle; set LDAP_TLS_INSECURE=1 knowingly.
            logger.warning("LDAP server certificate validation is DISABLED (LDAP_TLS_INSECURE=1)")
            conn.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
        else:
            conn.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND)
            if self.ca_file:
                conn.set_option(ldap.OPT_X_TLS_CACERTFILE, self.ca_file)

        # Forces python-ldap to build a fresh TLS context using the options set
        # above; without this they are silently ignored. Must come last.
        conn.set_option(ldap.OPT_X_TLS_NEWCTX, 0)

        conn.sasl_interactive_bind_s("", ldap.sasl.external())
        return conn

    def lookup_ou_path(self, email: str) -> str | None:
        """Return the account's full DN, or None if not found / on error."""
        try:
            conn = self._connect()
        except ldap.LDAPError as e:
            # Logged distinctly from "account genuinely absent", which matters:
            # a directory outage and an unknown account otherwise produce the
            # same user-facing message with no way to tell them apart.
            logger.error("LDAP connect/bind failed: %s", e)
            return None
        try:
            filt = ldap.filter.filter_format("(mail=%s)", [email])
            results = conn.search_s(self.base_dn, ldap.SCOPE_SUBTREE, filt, ["dn"])
        except ldap.LDAPError as e:
            logger.error("LDAP search failed for %s: %s", email, e)
            return None
        finally:
            try:
                conn.unbind_s()
            except ldap.LDAPError:
                pass

        if not results:
            return None
        dn, _attrs = results[0]
        return dn
