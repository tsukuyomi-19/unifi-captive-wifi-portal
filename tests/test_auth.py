"""Token-exchange failures must surface as TokenVerificationError, never escape.

Regression: on the first real deployment every sign-in returned HTTP 500.
oauthlib raises a bare `Warning` from fetch_token when Google echoes the
requested `email` scope back as https://www.googleapis.com/auth/userinfo.email.
`Warning` is an Exception subclass but not a ValueError, so it bypassed the only
handler and Flask turned it into a 500 - a dead end for the user and no
indication of which step failed.
"""

import pytest

import auth
from conftest import make_config


class FakeFlow:
    def __init__(self, exc=None, id_token="fake-id-token"):
        self.exc = exc
        self._id_token = id_token

    def fetch_token(self, authorization_response=None):
        if self.exc:
            raise self.exc

    @property
    def credentials(self):
        return type("Creds", (), {"_id_token": self._id_token})()


# The real message oauthlib produces, verified in production logs 2026-08-03.
SCOPE_WARNING = Warning(
    'Scope has changed from "email openid" to '
    '"https://www.googleapis.com/auth/userinfo.email openid".'
)


def test_scope_change_warning_becomes_token_verification_error(tmp_path):
    """`Warning` is not a ValueError, which is why it used to escape."""
    with pytest.raises(auth.TokenVerificationError) as e:
        auth.verify_id_token(FakeFlow(exc=SCOPE_WARNING), "https://x/callback", make_config(tmp_path))
    assert "token exchange failed" in str(e.value)
    assert "Scope has changed" in str(e.value)


def test_warning_really_is_an_exception_subclass():
    """Guards the assumption the fix rests on."""
    assert issubclass(Warning, Exception)
    assert not issubclass(Warning, ValueError)


@pytest.mark.parametrize(
    "exc",
    [
        Warning("Scope has changed"),
        ValueError("invalid_grant"),
        RuntimeError("insecure transport"),
        KeyError("code"),
        Exception("anything at all"),
    ],
)
def test_any_fetch_token_failure_is_wrapped(tmp_path, exc):
    with pytest.raises(auth.TokenVerificationError):
        auth.verify_id_token(FakeFlow(exc=exc), "https://x/callback", make_config(tmp_path))


def test_id_token_verification_failure_is_wrapped(tmp_path, mocker):
    mocker.patch(
        "google.oauth2.id_token.verify_oauth2_token", side_effect=ValueError("bad signature")
    )
    with pytest.raises(auth.TokenVerificationError, match="id_token verification failed"):
        auth.verify_id_token(FakeFlow(), "https://x/callback", make_config(tmp_path))


def test_unverified_email_is_rejected(tmp_path, mocker):
    """verify_oauth2_token does not check email_verified; we must."""
    mocker.patch(
        "google.oauth2.id_token.verify_oauth2_token",
        return_value={"email": "a@example.org", "email_verified": False},
    )
    with pytest.raises(auth.TokenVerificationError, match="email_verified"):
        auth.verify_id_token(FakeFlow(), "https://x/callback", make_config(tmp_path))


def test_verified_email_passes_through(tmp_path, mocker):
    mocker.patch(
        "google.oauth2.id_token.verify_oauth2_token",
        return_value={"email": "a@example.org", "email_verified": True},
    )
    info = auth.verify_id_token(FakeFlow(), "https://x/callback", make_config(tmp_path))
    assert info["email"] == "a@example.org"


def test_authorization_url_requests_bare_email_scope(tmp_path):
    """The bare `email` scope is what Google echoes back expanded - documenting
    the cause, so nobody 'fixes' it by requesting the full URL instead (which
    Google would then echo back as `email`, inverting the same failure)."""
    cfg = make_config(tmp_path)
    flow = auth.build_flow(cfg, cfg.OAUTH_REDIRECT_URI)
    assert set(flow.oauth2session.scope) == {"openid", "email"}


def test_callback_renders_error_page_not_500(tmp_path, policy, mocker):
    """End to end through Flask: a scope-change failure must render the friendly
    error page with 403, not a bare Internal Server Error."""
    from app import create_app
    from conftest import STUDENT_DN, FakeIdentity
    from unifi_client import MockUniFiClient

    unifi = MockUniFiClient(ssids={"AA:BB:CC:DD:EE:FF": "Campus Student"})
    app = create_app(
        make_config(tmp_path),
        unifi_client=unifi,
        identity=FakeIdentity({"jstudent@example.org": STUDENT_DN}),
        policy=policy,
    )
    app.config["TESTING"] = False  # do not let Flask re-raise
    client = app.test_client()

    # No ?ssid= - the portal resolves it from the controller.
    resp = client.get("/login?mac=AA:BB:CC:DD:EE:FF")
    from urllib.parse import parse_qs, urlparse

    state = parse_qs(urlparse(resp.headers["Location"]).query)["state"][0]

    mocker.patch("auth.verify_id_token", side_effect=auth.TokenVerificationError("scope changed"))
    resp = client.get(f"/callback?state={state}&code=fake")
    assert resp.status_code == 403
    assert b"Internal Server Error" not in resp.data
    assert b"could not be verified" in resp.data
