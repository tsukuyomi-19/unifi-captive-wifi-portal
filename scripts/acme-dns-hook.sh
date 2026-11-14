#!/usr/bin/env bash
# certbot --manual-auth-hook: publish the DNS-01 challenge via acme-dns.
#
# Replaces acme-manual-hook.sh, which could only PRINT the required TXT record
# and then wait up to an hour for a human to type it into the DNS registrar,
# so every renewal was blocked on a person being available at the right moment.
#
# Many registrars have no DNS API. Instead, _acme-challenge.<portal host> is a
# CNAME to an acme-dns account, so the challenge value is written THERE, over an
# API, and the registrar never needs to be touched again.
#
# Credentials live in ACMEDNS_CREDS (root-only, 600), as written by the
# registration step:
#   { "<domain>": { "username": ..., "password": ...,
#                   "subdomain": ..., "fulldomain": ... } }
#
# certbot supplies CERTBOT_DOMAIN and CERTBOT_VALIDATION.
set -u

CREDS="${ACMEDNS_CREDS:-/etc/letsencrypt/acmedns.json}"
API="${ACMEDNS_API:-https://auth.acme-dns.io}"
TRIES="${ACMEDNS_WAIT_TRIES:-30}"     # 30 x 5s = 2.5 min
SLEEP="${ACMEDNS_WAIT_SLEEP:-5}"

die() { echo "acme-dns-hook: $*" >&2; exit 1; }

[ -r "$CREDS" ] || die "cannot read $CREDS (run as root?)"
[ -n "${CERTBOT_DOMAIN:-}" ] || die "CERTBOT_DOMAIN unset - not called by certbot?"
[ -n "${CERTBOT_VALIDATION:-}" ] || die "CERTBOT_VALIDATION unset"

# Pull the credentials for this domain. Keyed by the certificate's domain so a
# second hostname can be added later with its own acme-dns account.
read -r USER_ KEY_ SUB_ FULL_ < <(
  python3 - "$CREDS" "$CERTBOT_DOMAIN" <<'PY'
import json, sys
creds = json.load(open(sys.argv[1]))
dom = sys.argv[2]
# Accept an exact match, or a parent entry, so a wildcard/multi-name cert whose
# CERTBOT_DOMAIN is the base still finds its account.
entry = creds.get(dom)
if entry is None:
    for k, v in creds.items():
        if dom.endswith("." + k) or k.endswith("." + dom):
            entry = v
            break
if entry is None:
    raise SystemExit(f"no acme-dns account in {sys.argv[1]} for {dom}; have {list(creds)}")
missing = [f for f in ("username", "password", "subdomain", "fulldomain")
           if not entry.get(f)]
if missing:
    raise SystemExit(f"account for {dom} is missing {missing}")
print(entry["username"], entry["password"], entry["subdomain"], entry["fulldomain"])
PY
) || die "could not load credentials for $CERTBOT_DOMAIN"

[ -n "${USER_:-}" ] && [ -n "${KEY_:-}" ] || die "empty credentials"

echo "acme-dns-hook: publishing challenge for $CERTBOT_DOMAIN -> $FULL_"

# The response body is echoed on failure only; on success it merely repeats the
# value we just sent, and there is no reason to put a credential-adjacent
# response into a log.
resp=$(curl -sS --max-time 30 -o /tmp/acmedns-update.out -w '%{http_code}' \
  -X POST "$API/update" \
  -H "X-Api-User: ${USER_}" \
  -H "X-Api-Key: ${KEY_}" \
  -H "Content-Type: application/json" \
  --data "{\"subdomain\":\"${SUB_}\",\"txt\":\"${CERTBOT_VALIDATION}\"}" 2>&1)

if [ "$resp" != "200" ]; then
  echo "acme-dns-hook: update failed, HTTP ${resp}" >&2
  sed 's/^/  /' /tmp/acmedns-update.out >&2 2>/dev/null || true
  rm -f /tmp/acmedns-update.out
  die "could not publish the challenge to acme-dns"
fi
rm -f /tmp/acmedns-update.out

# Do not hand control back to certbot until the value is actually visible.
# acme-dns is authoritative for its own zone, so query it directly rather than a
# recursive resolver, which may still hold a negative answer for this name.
ns=$(dig +short NS "$(echo "$FULL_" | cut -d. -f2-)" 2>/dev/null | head -1)
ns="${ns:-ns.auth.acme-dns.io.}"
i=0
while [ "$i" -lt "$TRIES" ]; do
  if dig +short TXT "$FULL_" @"${ns%.}" 2>/dev/null | grep -qF -- "$CERTBOT_VALIDATION"; then
    echo "acme-dns-hook: challenge visible at $FULL_ (via ${ns%.}) after $((i * SLEEP))s"
    exit 0
  fi
  i=$((i + 1))
  sleep "$SLEEP"
done

die "published, but the value never became visible at $FULL_ after $((TRIES * SLEEP))s"
