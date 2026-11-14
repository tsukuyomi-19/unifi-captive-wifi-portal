"""Externalised OU->role and SSID->allowed-roles policy.

Why this isn't hardcoded any more
---------------------------------
Two independent sources of truth for the same OU tree disagreed across this
project's history, and both were hardcoded in code at different times:

  - Google Secure LDAP returns DNs like
      uid=jstudent,ou=2027-2028,ou=Students,ou=Users,dc=example,dc=org
      uid=astaff,ou=High School Staff,ou=Staff,ou=Staff & Teachers,ou=Users,...
  - The Google Admin Directory API returns orgUnitPath like
      /Students
      /Faculty & Management      <- note: no "Staff" substring at all

The 2025 Node backend keyed off "/Faculty & Management"; the 2026 Python
rewrite keyed off a compiled r"ou=Staff" regex. Whichever is stale, a
mismatch fails *silently* - lookup_ou() returns None and every affected user
is told "Could not determine your account type", with nothing in the code to
indicate which pattern was wrong.

Likewise the SSID names were written three different ways across the docs and
code ("Student WiFi", "Campus Student", "Campus Guest") while the controller's
actual configured name is a fourth question entirely.

So both mappings live in a config file that can be corrected without a code
change or redeploy, and `scripts/preflight.py` verifies them against the live
controller and a real directory lookup.

Format (see ou-policy.conf.example) - "->" separates key from value so that
patterns may contain "=" (as every LDAP RDN does):

    [roles]
    ou=Students -> student
    /Faculty & Management -> staff

    [ssids]
    Campus Student -> student
    Campus Staff -> staff
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


class PolicyError(Exception):
    pass


@dataclass
class Policy:
    # Ordered: first pattern found in the DN / orgUnitPath wins, so a more
    # specific pattern can be listed above a broader one.
    role_rules: list[tuple[str, str]] = field(default_factory=list)
    # SSID name (exact, case-sensitive) -> roles permitted on that SSID.
    ssid_roles: dict[str, set[str]] = field(default_factory=dict)

    def classify(self, ou_path_or_dn: str) -> str | None:
        """Map an LDAP DN or Directory API orgUnitPath to a role, or None."""
        if not ou_path_or_dn:
            return None
        haystack = ou_path_or_dn.casefold()
        for pattern, role in self.role_rules:
            if pattern.casefold() in haystack:
                return role
        return None

    def is_allowed(self, ssid: str, role: str) -> bool:
        """Fail closed: an SSID absent from the policy permits nobody.

        The previous implementation only compared against two hardcoded SSID
        constants, so any *other* SSID value (a rename, a third SSID, a typo,
        or an attacker-supplied value before MAC binding was in place) matched
        neither branch and fell through to authorize-guest unconditionally.
        """
        allowed = self.ssid_roles.get(ssid)
        if not allowed:
            return False
        return role in allowed

    def other_ssids_for(self, role: str) -> list[str]:
        """SSIDs this role *would* be allowed on - used to tell a user where to go."""
        return sorted(s for s, roles in self.ssid_roles.items() if role in roles)

    def known_ssids(self) -> list[str]:
        return sorted(self.ssid_roles)


def _strip_comment(line: str) -> str:
    return line.split("#", 1)[0].strip()


def parse_policy(text: str) -> Policy:
    policy = Policy()
    section: str | None = None

    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = _strip_comment(raw)
        if not line:
            continue

        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip().casefold()
            if section not in ("roles", "ssids"):
                raise PolicyError(f"line {lineno}: unknown section [{section}]")
            continue

        if section is None:
            raise PolicyError(f"line {lineno}: entry before any [section]: {line!r}")

        if "->" not in line:
            raise PolicyError(f"line {lineno}: expected 'key -> value', got {line!r}")

        key, value = (part.strip() for part in line.split("->", 1))
        if not key or not value:
            raise PolicyError(f"line {lineno}: empty key or value in {line!r}")

        if section == "roles":
            policy.role_rules.append((key, value.casefold()))
        else:
            roles = {r.strip().casefold() for r in value.split(",") if r.strip()}
            if not roles:
                raise PolicyError(f"line {lineno}: no roles listed for SSID {key!r}")
            # Same SSID listed twice unions rather than silently replacing.
            policy.ssid_roles.setdefault(key, set()).update(roles)

    if not policy.role_rules:
        raise PolicyError("policy defines no [roles] rules - every lookup would fail")
    if not policy.ssid_roles:
        raise PolicyError("policy defines no [ssids] rules - every device would be denied")
    return policy


def load_policy(path: str) -> Policy:
    if not path or not os.path.exists(path):
        raise PolicyError(
            f"policy file not found: {path!r}. Copy ou-policy.conf.example to it and "
            "verify the OU patterns with scripts/preflight.py before deploying."
        )
    with open(path, encoding="utf-8") as f:
        return parse_policy(f.read())
