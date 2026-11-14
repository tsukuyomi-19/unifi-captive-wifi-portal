# Manual End-to-End Checklist

Not a pytest file. Run this before any deploy, and once now to prove the design works
end-to-end with real Google OAuth and real Google Secure LDAP (only UniFi is stubbed).

## One-time setup

1. Google Cloud Console → APIs & Services → Credentials → Create Credentials → OAuth client ID → Web application.
   - Authorized redirect URI: `http://localhost:5000/callback`
2. Copy `.env.example` to `.env`, fill in `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET`.
3. Confirm `LDAP_CERT_FILE`/`LDAP_KEY_FILE` point at the existing working cert pair.
4. `./scripts/run_local.sh`

## Positive cases

- [ ] Visit `http://localhost:5000/login?mac=AA:BB:CC:DD:EE:FF&ip=10.0.0.5&ssid=Student%20WiFi`, sign in with a known **student** `@example.org` account → lands on `/success`.
- [ ] Check `instance/sessions.db` — the state row used is gone (consumed).
- [ ] Repeat with a known **staff** account against `ssid=Campus%20Staff` → lands on `/success`.

## Negative cases

- [ ] Staff account against `ssid=Student%20WiFi` → redirected to `/wrong-network`.
- [ ] Student account against `ssid=Campus%20Staff` → redirected to `/wrong-network`.
- [ ] Sign in with a non-`@example.org` Google account → 403 error page.
- [ ] Reload/revisit a `/callback?state=...` URL after it's already succeeded once → 403 (state already consumed).
- [ ] Wait >10 minutes between `/login` and completing sign-in → 403 (session expired).
- [ ] Missing `mac`/`ssid` on `/login` → 400.

## What this proves

Real OAuth (full browser, not embedded webview) + real OIDC signature/claims verification +
real LDAP OU lookup against `ldap.google.com`, with only the UniFi `authorize-guest` call
stubbed (`UNIFI_MODE=mock`). This is the actual proof the design works — the pytest suite
only proves the logic is internally consistent under mocks.
