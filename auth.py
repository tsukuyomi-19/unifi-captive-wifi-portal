import google.auth.transport.requests
import google.oauth2.id_token
from google_auth_oauthlib.flow import Flow

from config import Config


class TokenVerificationError(Exception):
    pass


def build_flow(config: Config, redirect_uri: str) -> Flow:
    return Flow.from_client_config(
        {
            "web": {
                "client_id": config.GOOGLE_CLIENT_ID,
                "client_secret": config.GOOGLE_CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
            }
        },
        scopes=["openid", "email"],
        redirect_uri=redirect_uri,
    )


def get_authorization_url(flow: Flow, state: str, hosted_domain: str) -> str:
    auth_url, _ = flow.authorization_url(
        state=state,
        hd=hosted_domain,  # hint only, per design - NOT the security boundary
        prompt="select_account",
    )
    return auth_url


def verify_id_token(flow: Flow, authorization_response_url: str, config: Config) -> dict:
    """Exchange the auth code for tokens, then properly verify the ID token.

    google.oauth2.id_token.verify_oauth2_token fetches Google's live JWKS and
    checks the JWT signature, iss, aud, and exp/iat - this is real OIDC
    verification, not a manually-decoded, unverified JWT payload.
    """
    try:
        flow.fetch_token(authorization_response=authorization_response_url)
    except Exception as e:
        # Deliberately broad. oauthlib raises a bare `Warning` (which *is* an
        # Exception subclass) for "Scope has changed from ... to ...", because
        # Google echoes the requested `email` back as the full URL
        # https://www.googleapis.com/auth/userinfo.email. It also raises
        # InsecureTransportError, MissingCodeError, invalid_grant and others.
        # None of them are ValueError, so anything not caught here escaped as a
        # raw HTTP 500 - which in a captive portal is a dead end for the user
        # and tells whoever is debugging nothing about which step failed.
        raise TokenVerificationError(f"token exchange failed: {e}") from e

    credentials = flow.credentials
    request = google.auth.transport.requests.Request()
    try:
        id_info = google.oauth2.id_token.verify_oauth2_token(
            credentials._id_token, request, audience=config.GOOGLE_CLIENT_ID
        )
    except Exception as e:
        raise TokenVerificationError(f"id_token verification failed: {e}") from e

    # verify_oauth2_token does NOT check email_verified - do it explicitly.
    if not id_info.get("email_verified", False):
        raise TokenVerificationError("email_verified is false")

    return id_info
