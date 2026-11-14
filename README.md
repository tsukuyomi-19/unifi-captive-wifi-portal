# Campus WiFi captive portal

Students (and optionally staff) join an open SSID, sign in with their school
Google account, and their device is authorized on the UniFi controller for 30
days. Replaces the two-step voucher flow ("go to wifi.example.org,
generate a code, type the code into the portal").

```
device joins open SSID
  -> UniFi redirects to https://wifi.example.org/?id=<mac>&ssid=<ssid>&url=<dest>
  -> /login binds {state -> mac, ssid} server-side (SQLite, 10 min TTL)
  -> Google OAuth in the real browser
  -> /callback: verify ID token -> check email domain -> blocklist
       -> directory lookup (OU) -> policy: is this role allowed on this SSID?
  -> UniFi authorize-guest for the MAC from the *session*, never the URL
  -> /success
```

## Layout

| File | Role |
|---|---|
| `app.py` | app factory; `create_application()` is the gunicorn entry point |
| `routes.py` | the five endpoints plus `/health` |
| `auth.py` | Google OAuth + real OIDC ID-token verification |
| `policy.py` | OU→role and SSID→roles rules, loaded from config |
| `ldap_client.py` | OU lookup via Google Secure LDAP (default) |
| `directory_client.py` | OU lookup via Google Admin Directory API; backend factory |
| `unifi_client.py` | guest authorization (`apikey` / `login` / `mock`) |
| `session_store.py` | one-time state tokens bound to a MAC |
| `blocklist.py` | per-email denylist |
| `connection_log.py` | one audit line per attempt |
| `scripts/preflight.py` | verifies config against the live controller and directory |

## Local development

```bash
python -m venv .venv && .venv/bin/pip install -r requirements.txt
cp .env.example .env                       # fill in GOOGLE_CLIENT_ID/SECRET
cp ou-policy.conf.example instance/ou-policy.conf
./scripts/run_local.sh
```

`UNIFI_MODE=mock` (the default) means no controller is touched. Google
permits `http://localhost` redirect URIs, so real OAuth works locally.

```bash
.venv/bin/python -m pytest              # unit tests, no network
.venv/bin/python -m pytest -m live_ldap # hits the real directory; needs certs
```

`python-ldap` needs a compiler and `libsasl2-dev libldap2-dev libssl-dev`. It
does not build on Windows out of the box, so `test_ldap_client.py` skips itself
there; everything else runs.

## Before deploying

```bash
python scripts/preflight.py --email someone@example.org
```

It checks the redirect URI's shape, that the policy file parses, that every
policy SSID exists on the controller *and is open + guest-enabled*, that the
controller's portal target matches the redirect URI's host, that a real account
resolves to a role, and that the TLS certificate isn't about to expire. Exit
code is non-zero if anything fails, so it works from cron.

## Two configuration files decide behaviour

**`.env`** — credentials and endpoints. See `.env.example`. The two settings
most likely to be wrong:

- `TRUST_PROXY_HOPS=1` whenever nginx terminates TLS. Otherwise the app
  believes it is serving `http://`, and the OAuth token exchange fails against
  an `https://` redirect URI with an error that mentions neither.
- `UNIFI_MODE=apikey` with `UNIFI_API_KEY` set. `real` is accepted as a legacy
  alias for `login`.

**`instance/ou-policy.conf`** — who is allowed where. See
`ou-policy.conf.example`. An SSID absent from `[ssids]` denies everyone, so
adding an SSID to the portal is always a deliberate edit. Changing which roles
may use which SSID — including whether staff go through the portal at all —
is a change to this file only, no code edit.

## Notes for whoever picks this up next

- The MAC is captured once at `/login` and read back out of the session store at
  `/callback`. It is never taken from `/callback`'s query string, so a tampered
  `?mac=` cannot authorize somebody else's device. There is a test for this.
- `auth.py` verifies the ID token against Google's live JWKS (signature, `iss`,
  `aud`, `exp`) and separately checks `email_verified`, which
  `verify_oauth2_token` does not. The `hd` parameter is a hint only — the real
  domain check is in `routes.py`.
- The UniFi API returns HTTP 200 with `meta.rc == "error"` for application-level
  failures, so `resp.ok` is not a success test. `unifi_client.py` checks
  `meta.rc`.
- Certificate renewal should be unattended (DNS-01 via the `scripts/acme-*-hook.sh`
  hooks); `preflight.py` warns when the certificate is within 21 days of expiry.
