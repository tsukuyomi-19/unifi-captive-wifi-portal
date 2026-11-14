"""LDAP backend tests.

DN-to-role classification moved to policy.py (see test_policy.py) - it is no
longer this module's job. What's left here is the lookup itself, which needs
either mocking or the live directory.
"""

import os

import pytest

pytest.importorskip("ldap", reason="python-ldap not installed (IDENTITY_BACKEND=directory only)")

from ldap_client import LdapOuLookup  # noqa: E402


def make_lookup(**kw):
    defaults = dict(
        host="ldap.google.com",
        port=636,
        cert_file="/dev/null",
        key_file="/dev/null",
        base_dn="ou=Users,dc=example,dc=org",
    )
    defaults.update(kw)
    return LdapOuLookup(**defaults)


def test_returns_dn_not_a_role(mocker):
    """The backend's contract is the raw DN; classification happens in policy."""
    dn = "uid=jstudent,ou=2027-2028,ou=Students,ou=Users,dc=example,dc=org"
    lookup = make_lookup()
    conn = mocker.MagicMock()
    conn.search_s.return_value = [(dn, {})]
    mocker.patch.object(lookup, "_connect", return_value=conn)
    assert lookup.lookup_ou_path("jstudent@example.org") == dn


def test_absent_account_returns_none(mocker):
    lookup = make_lookup()
    conn = mocker.MagicMock()
    conn.search_s.return_value = []
    mocker.patch.object(lookup, "_connect", return_value=conn)
    assert lookup.lookup_ou_path("nobody@example.org") is None


def test_connect_failure_returns_none_rather_than_raising(mocker):
    """A directory outage must deny, not 500 the callback."""
    import ldap as ldap_mod

    lookup = make_lookup()
    mocker.patch.object(lookup, "_connect", side_effect=ldap_mod.SERVER_DOWN("nope"))
    assert lookup.lookup_ou_path("jstudent@example.org") is None


def test_search_failure_returns_none(mocker):
    import ldap as ldap_mod

    lookup = make_lookup()
    conn = mocker.MagicMock()
    conn.search_s.side_effect = ldap_mod.TIMEOUT("slow")
    mocker.patch.object(lookup, "_connect", return_value=conn)
    assert lookup.lookup_ou_path("jstudent@example.org") is None


def test_email_is_escaped_into_the_filter(mocker):
    """A crafted email must not be able to alter the LDAP filter."""
    lookup = make_lookup()
    conn = mocker.MagicMock()
    conn.search_s.return_value = []
    mocker.patch.object(lookup, "_connect", return_value=conn)
    lookup.lookup_ou_path("a)(uid=*@example.org")
    filt = conn.search_s.call_args[0][2]
    assert "*" not in filt.replace("\\2a", "")
    assert filt.startswith("(mail=")


def test_tls_validation_is_on_by_default():
    assert make_lookup().insecure is False


@pytest.mark.live_ldap
def test_live_ldap_lookup_smoke():
    """Hits the real Google Secure LDAP directory - run with `pytest -m live_ldap`.

    Needs LDAP_CERT_FILE / LDAP_KEY_FILE / LIVE_LDAP_TEST_EMAIL pointing at a
    real cert pair and a known account.
    """
    lookup = make_lookup(
        cert_file=os.path.expanduser(os.environ["LDAP_CERT_FILE"]),
        key_file=os.path.expanduser(os.environ["LDAP_KEY_FILE"]),
    )
    dn = lookup.lookup_ou_path(os.environ["LIVE_LDAP_TEST_EMAIL"])
    assert dn, "no DN returned - check the cert pair and that the account exists"

    # Prove the shipped policy actually classifies whatever the directory
    # returns. This is the check that would have caught the ou=Staff vs
    # /Faculty & Management divergence.
    from pathlib import Path

    from policy import parse_policy

    example = Path(__file__).resolve().parent.parent / "ou-policy.conf.example"
    role = parse_policy(example.read_text(encoding="utf-8")).classify(dn)
    assert role in ("student", "staff"), f"policy did not classify {dn!r}"
