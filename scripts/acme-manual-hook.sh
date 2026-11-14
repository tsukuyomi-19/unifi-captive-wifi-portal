#!/usr/bin/env bash
# certbot --manual-auth-hook for DNS-01 against a registrar with no API.
#
# The DNS registrar has no public DNS API, so the TXT record has to be created
# by hand. Rather than requiring someone to sit in an interactive certbot
# prompt, this hook prints the exact record to create and then polls the
# domain's AUTHORITATIVE nameservers until the value shows up, at which point
# certbot proceeds on its own.
#
# Queries the authoritative servers directly, not a recursive resolver: a
# resolver that has already cached NXDOMAIN for the challenge name would
# otherwise keep us waiting long after the record is live, and a resolver
# answering from a stale positive cache could let us continue too early.
#
# certbot supplies CERTBOT_DOMAIN and CERTBOT_VALIDATION.
#   ACME_NS         space-separated authoritative servers (default: worldnic)
#   ACME_WAIT_TRIES number of 30s polls before giving up (default 120 = 1h)
set -u

NAME="_acme-challenge.${CERTBOT_DOMAIN}"
VALUE="${CERTBOT_VALIDATION}"
NS_LIST="${ACME_NS:-ns83.worldnic.com ns84.worldnic.com}"
TRIES="${ACME_WAIT_TRIES:-120}"

# Also written to a file: certbot buffers hook stdout and only surfaces it at
# higher verbosity, so relying on the log alone to learn the value is fragile.
STATUS_FILE="${ACME_STATUS_FILE:-/tmp/acme-challenge.txt}"
{
    echo "type=TXT"
    echo "name=${NAME}"
    echo "value=${VALUE}"
    echo "started=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
} > "${STATUS_FILE}" 2>/dev/null || true
chmod 644 "${STATUS_FILE}" 2>/dev/null || true

echo "=============================================================="
echo "CREATE THIS DNS RECORD:"
echo
echo "    Type  : TXT"
echo "    Name  : ${NAME}"
echo "    Value : ${VALUE}"
echo "    TTL   : lowest offered (600s if available)"
echo
echo "Waiting for it to appear on: ${NS_LIST}"
echo "=============================================================="

for i in $(seq 1 "${TRIES}"); do
    for ns in ${NS_LIST}; do
        # +short strips formatting; TXT values come back quoted.
        # "--" is essential: ACME validation values are random base64url and
        # frequently start with "-", which grep would otherwise parse as an
        # option. Without it this comparison silently never matches, and the
        # hook polls forever against a record that is already correct.
        if dig +short +time=5 +tries=1 TXT "${NAME}" "@${ns}" 2>/dev/null \
             | tr -d '"' | grep -qxF -- "${VALUE}"; then
            echo "[$(date -u '+%H:%M:%S')] found on ${ns} after ${i} check(s)"
            # Brief settle so the ACME server's own resolver is unlikely to
            # query a secondary that has not caught up yet.
            sleep 10
            exit 0
        fi
    done
    echo "[$(date -u '+%H:%M:%S')] not visible yet (check ${i}/${TRIES})"
    sleep 30
done

echo "TIMED OUT after ${TRIES} checks waiting for ${NAME}" >&2
exit 1
