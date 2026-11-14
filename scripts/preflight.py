#!/usr/bin/env python3
"""Verify the portal's configuration against live reality before deploying.

Every stall in this project's history was a mismatch between what the config
said and what the world actually looked like, and each one failed silently:

  - SSID names were written four different ways across docs and code; a
    mismatch just means every user is told "wrong network".
  - The two OU sources disagree (ou=Staff vs /Faculty & Management); a stale
    pattern means every affected user is told "could not determine your
    account type".
  - The TLS certificate quietly stopped renewing in Oct 2025 and expired in
    Jan 2026. Nothing noticed.
  - UNIFI_MODE/credentials wrong means authorize-guest fails at the last step,
    after the user has already signed in.

Run this after any config change, and from cron if you want early warning:

    python scripts/preflight.py
    python scripts/preflight.py --email astudent@example.org

Exit code is 0 only if every check passes. Read-only: it never authorizes a
device or changes controller state.
"""

from __future__ import annotations

import argparse
import os
import socket
import ssl
import subprocess
import sys
from datetime import datetime, timezone
from urllib.parse import urlparse

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import requests  # noqa: E402
from dotenv import load_dotenv  # noqa: E402

GREEN, RED, YELLOW, DIM, RESET = "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[0m"
_failed: list[str] = []
_warned: list[str] = []


def ok(msg: str) -> None:
    print(f"  {GREEN}PASS{RESET}  {msg}")


def fail(msg: str) -> None:
    _failed.append(msg)
    print(f"  {RED}FAIL{RESET}  {msg}")


def warn(msg: str) -> None:
    _warned.append(msg)
    print(f"  {YELLOW}WARN{RESET}  {msg}")


def info(msg: str) -> None:
    print(f"        {DIM}{msg}{RESET}")


def section(title: str) -> None:
    print(f"\n{title}")


# --------------------------------------------------------------------------
def check_clock():
    """Clock skew first - every other check depends on it, and it fails silently.

    Found 2026-08-03: this server's clock was 107 days behind. Ubuntu's default
    chrony config uses NTS, whose TLS handshake fails when the clock is wrong,
    so chrony could never acquire a source to fix the clock - a bootstrap
    deadlock that persisted for months. Consequences, none of which name the
    clock in their error messages:

      - LDAP over TLS fails with "certificate is not yet valid"
      - Google ID-token verification fails on iat/exp (small skew tolerance)
      - certbot cannot issue, and any issued cert reads as not-yet-valid
        locally - the likely reason renewals stopped in October 2025

    Compared against an HTTP Date header rather than HTTPS, so that this check
    still works when the skew is bad enough to break TLS.
    """
    section("0. System clock")
    import email.utils

    try:
        # Plain HTTP on purpose: no certificate validation to be defeated by
        # the very skew we are trying to measure.
        resp = requests.head("http://clients3.google.com/generate_204", timeout=10,
                             allow_redirects=False)
        server_date = resp.headers.get("Date")
    except Exception as e:
        warn(f"could not reach an HTTP time reference: {e}")
        server_date = None

    if server_date:
        ref = email.utils.parsedate_to_datetime(server_date)
        skew = abs((datetime.now(timezone.utc) - ref).total_seconds())
        if skew > 300:
            fail(f"clock is off by {skew / 86400:.1f} days vs {ref:%Y-%m-%d %H:%M} UTC")
            info("OAuth, LDAP over TLS and certbot will all fail. Fix first:")
            info("  sudo systemctl stop chrony")
            info("  sudo chronyd -q 'server time.cloudflare.com iburst'   # plain NTP, no NTS")
            info("  sudo hwclock --systohc && sudo systemctl start chrony")
        elif skew > 30:
            warn(f"clock is off by {skew:.0f}s - tighten this before it grows")
        else:
            ok(f"clock within {skew:.1f}s of reference")

    # Independent confirmation that something is keeping it synced going forward.
    try:
        out = subprocess.run(
            ["timedatectl", "show", "-p", "NTPSynchronized", "--value"],
            capture_output=True, text=True, timeout=10,
        ).stdout.strip()
        if out == "yes":
            ok("NTP synchronised (timedatectl)")
        elif out == "no":
            fail("NTP is NOT synchronised - the clock will drift again")
            info("chronyc sources   # an empty list means no usable time source")
        # anything else: timedatectl absent or unexpected output, stay quiet
    except (FileNotFoundError, subprocess.SubprocessError):
        pass


def check_config():
    section("1. Configuration")
    load_dotenv()
    try:
        from config import Config

        cfg = Config.from_env()
    except KeyError as e:
        fail(f"required environment variable missing: {e}")
        return None
    except Exception as e:
        fail(f"config failed to load: {e}")
        return None
    ok("config loaded")

    redirect = cfg.OAUTH_REDIRECT_URI
    parsed = urlparse(redirect)
    if parsed.scheme == "http" and parsed.hostname not in ("localhost", "127.0.0.1"):
        fail(f"OAUTH_REDIRECT_URI is plain http and not localhost: {redirect}")
    elif parsed.scheme == "http":
        warn(f"OAUTH_REDIRECT_URI is a localhost dev value: {redirect}")
        info("production must be https://<real-domain>/callback")
    else:
        ok(f"OAUTH_REDIRECT_URI = {redirect}")

    if parsed.hostname and parsed.hostname.replace(".", "").isdigit():
        fail("redirect URI uses a bare IP - Google rejects these unconditionally")

    if not parsed.path.endswith("/callback"):
        warn(f"redirect URI path is {parsed.path!r}, expected /callback")

    if parsed.scheme == "https" and not cfg.TRUST_PROXY_HOPS:
        warn("redirect URI is https but TRUST_PROXY_HOPS=0")
        info("if nginx terminates TLS, set TRUST_PROXY_HOPS=1 or OAuth will fail")

    if os.environ.get("OAUTHLIB_INSECURE_TRANSPORT") == "1" and parsed.scheme == "https":
        warn("OAUTHLIB_INSECURE_TRANSPORT=1 is set in a https deployment - remove it")

    if os.environ.get("OAUTHLIB_RELAX_TOKEN_SCOPE") != "1":
        fail("OAUTHLIB_RELAX_TOKEN_SCOPE is not set to 1")
        info("Google returns the `email` scope as .../auth/userinfo.email; oauthlib")
        info("treats the mismatch as fatal, so EVERY sign-in fails at /callback.")
        info("Add OAUTHLIB_RELAX_TOKEN_SCOPE=1 to .env (systemd reads it from there).")
    else:
        ok("OAUTHLIB_RELAX_TOKEN_SCOPE=1")

    return cfg


def check_policy(cfg):
    section("2. OU / SSID policy")
    try:
        from policy import load_policy

        policy = load_policy(cfg.POLICY_FILE)
    except Exception as e:
        fail(f"{e}")
        return None
    ok(f"parsed {cfg.POLICY_FILE}")
    for pattern, role in policy.role_rules:
        info(f"role: {pattern!r} -> {role}")
    for ssid in policy.known_ssids():
        info(f"ssid: {ssid!r} -> {', '.join(sorted(policy.ssid_roles[ssid]))}")
    return policy


def _unifi_get(cfg, path):
    import requests
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    url = f"https://{cfg.UNIFI_HOST}/proxy/network/api/s/{cfg.UNIFI_SITE}{path}"
    headers = {"Accept": "application/json"}
    if cfg.UNIFI_MODE == "apikey":
        headers["X-API-KEY"] = cfg.UNIFI_API_KEY
        return requests.get(url, headers=headers, verify=False, timeout=10)
    sess = requests.Session()
    login = sess.post(
        f"https://{cfg.UNIFI_HOST}/api/auth/login",
        json={"username": cfg.UNIFI_USER, "password": cfg.UNIFI_PASS},
        verify=False,
        timeout=10,
    )
    login.raise_for_status()
    csrf = login.headers.get("x-csrf-token")
    if csrf:
        sess.headers["x-csrf-token"] = csrf
    return sess.get(url, headers=headers, verify=False, timeout=10)


def check_unifi(cfg, policy):
    section("3. UniFi controller")
    if cfg.UNIFI_MODE == "mock":
        warn("UNIFI_MODE=mock - no device will actually be authorized")
        return
    if not cfg.UNIFI_HOST:
        fail("UNIFI_HOST is empty")
        return
    if cfg.UNIFI_MODE == "apikey" and not cfg.UNIFI_API_KEY:
        fail("UNIFI_MODE=apikey but UNIFI_API_KEY is empty")
        return

    try:
        resp = _unifi_get(cfg, "/rest/wlanconf")
    except Exception as e:
        fail(f"cannot reach controller at {cfg.UNIFI_HOST}: {e}")
        return
    if not resp.ok:
        fail(f"wlanconf returned HTTP {resp.status_code}: {resp.text[:200]}")
        return
    body = resp.json()
    if (body.get("meta") or {}).get("rc") != "ok":
        fail(f"controller rejected the request: {body.get('meta')}")
        return
    ok(f"authenticated to {cfg.UNIFI_HOST} via {cfg.UNIFI_MODE}")

    live = {w["name"]: w for w in body.get("data", [])}
    info(f"controller reports {len(live)} SSID entries: {', '.join(sorted(live))}")

    # The check that matters: does every SSID in the policy actually exist, and
    # is it shaped like something that can reach a captive portal?
    if policy is None:
        return
    for ssid in policy.known_ssids():
        w = live.get(ssid)
        if w is None:
            fail(f"policy SSID {ssid!r} does not exist on the controller")
            close = [n for n in live if n.casefold() == ssid.casefold()]
            if close:
                info(f"case mismatch? controller has {close[0]!r} - comparison is case-sensitive")
            continue
        if w.get("security") != "open":
            fail(f"SSID {ssid!r} is security={w.get('security')}, not open")
            info("a captive portal requires an open SSID; users will never see the portal")
        elif not w.get("is_guest"):
            fail(f"SSID {ssid!r} is open but is_guest=false, so no portal redirect happens")
        else:
            ok(f"SSID {ssid!r} is open + guest - portal redirect will occur")

    # Guest portal must point at this app.
    try:
        ga = _unifi_get(cfg, "/rest/setting/guest_access").json().get("data", [{}])[0]
    except Exception as e:
        warn(f"could not read guest_access settings: {e}")
        return
    if not ga.get("portal_enabled"):
        fail("guest portal is disabled on the controller (portal_enabled=false)")
    elif ga.get("auth") != "custom":
        fail(f"guest portal auth is {ga.get('auth')!r}, expected 'custom' (External Portal Server)")
    else:
        ok("guest portal is enabled and set to an external portal server")

    target = ga.get("portal_hostname") if ga.get("portal_use_hostname") else ga.get("custom_ip")
    expected = urlparse(cfg.OAUTH_REDIRECT_URI).hostname
    if target and expected and target != expected:
        warn(f"controller sends users to {target!r} but OAUTH_REDIRECT_URI host is {expected!r}")
        info("these must be the same host or the OAuth round trip will not come back")
    elif target:
        ok(f"controller portal target = {target}")

    if not ga.get("redirect_https", False) and expected and target == expected:
        warn("controller 'redirect using HTTPS' is off; the portal will be reached over http")


def check_identity(cfg, policy, email):
    section("4. Directory lookup")
    if not email:
        warn("no --email given, skipping live OU lookup")
        info("rerun with --email someone@example.org to verify role mapping")
        return
    try:
        from directory_client import build_identity_lookup

        lookup = build_identity_lookup(cfg)
    except Exception as e:
        fail(f"could not build {cfg.IDENTITY_BACKEND} backend: {e}")
        return
    try:
        path = lookup.lookup_ou_path(email)
    except Exception as e:
        fail(f"lookup raised: {e}")
        return
    if not path:
        fail(f"{email} produced no OU path (not found, or the lookup errored - check logs)")
        return
    ok(f"{email} -> {path}")
    if policy is None:
        return
    role = policy.classify(path)
    if role is None:
        fail(f"no [roles] rule matches {path!r} - this user would be denied")
        info("add a matching pattern to the policy file")
    else:
        ok(f"classified as {role!r}")
        allowed = policy.other_ssids_for(role)
        if allowed:
            ok(f"permitted on: {', '.join(allowed)}")
        elif role == "disabled":
            ok("role is denied everywhere, as intended")
        else:
            # Not a failure: with the students-only rollout, staff are
            # deliberately absent from [ssids] and stay on WPA2-PSK. Reporting
            # that as FAIL would make preflight red in the correct
            # configuration, and a check that always fails gets ignored.
            warn(f"role {role!r} is not permitted on any SSID in the policy")
            info("expected for staff under the students-only rollout")
            info("to put this role on the portal, add it to [ssids]")


def check_tls(cfg):
    section("5. Portal hostname and certificate")
    host = urlparse(cfg.OAUTH_REDIRECT_URI).hostname
    if not host or host in ("localhost", "127.0.0.1"):
        warn("redirect URI is localhost - no DNS or certificate to check yet")
        return
    try:
        addrs = sorted({ai[4][0] for ai in socket.getaddrinfo(host, None)})
        ok(f"{host} resolves to {', '.join(addrs)}")
    except socket.gaierror as e:
        fail(f"{host} does not resolve: {e}")
        return

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
    except Exception as e:
        fail(f"no valid TLS on https://{host} : {e}")
        info("Google requires https for the redirect URI; a browser warning here breaks the portal")
        return

    not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(
        tzinfo=timezone.utc
    )
    days = (not_after - datetime.now(timezone.utc)).days
    if days < 0:
        fail(f"certificate EXPIRED {-days} days ago ({not_after:%Y-%m-%d})")
    elif days < 21:
        warn(f"certificate expires in {days} days ({not_after:%Y-%m-%d}) - is renewal automated?")
    else:
        ok(f"certificate valid for {days} more days ({not_after:%Y-%m-%d})")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--email", help="account to verify the OU->role mapping against")
    args = ap.parse_args()

    print("Campus WiFi portal preflight")
    check_clock()
    cfg = check_config()
    if cfg is None:
        print(f"\n{RED}Cannot continue without a loadable config.{RESET}")
        return 1
    policy = check_policy(cfg)
    check_unifi(cfg, policy)
    check_identity(cfg, policy, args.email)
    check_tls(cfg)

    print()
    if _failed:
        print(f"{RED}{len(_failed)} check(s) failed:{RESET}")
        for m in _failed:
            print(f"  - {m}")
    if _warned:
        print(f"{YELLOW}{len(_warned)} warning(s):{RESET}")
        for m in _warned:
            print(f"  - {m}")
    if not _failed:
        print(f"{GREEN}All checks passed.{RESET}")
    return 1 if _failed else 0


if __name__ == "__main__":
    sys.exit(main())
