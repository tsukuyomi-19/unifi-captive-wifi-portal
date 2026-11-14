#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

# oauthlib enforces HTTPS by default; this exemption is required to test the
# real OAuth flow over plain http://localhost. Local dev only - never set
# this in production, where the redirect URI will be a real https:// URL.
export OAUTHLIB_INSECURE_TRANSPORT=1

# Google sometimes echoes back the scope as a full URL
# (https://www.googleapis.com/auth/userinfo.email) instead of the bare
# "email" requested; oauthlib treats that mismatch as fatal unless relaxed.
export OAUTHLIB_RELAX_TOKEN_SCOPE=1

if [ ! -f .env ]; then
  echo ".env not found - copy .env.example to .env and fill in GOOGLE_CLIENT_ID/SECRET first." >&2
  exit 1
fi

mkdir -p instance
venv/bin/python app.py
