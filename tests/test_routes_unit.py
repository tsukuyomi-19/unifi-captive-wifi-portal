from urllib.parse import parse_qs, urlparse

import pytest

from app import create_app
from conftest import STAFF_DN, STUDENT_DN, FakeIdentity, make_config
from unifi_client import MockUniFiClient

STUDENT_EMAIL = "jstudent@example.org"
STAFF_EMAIL = "astaff@example.org"


@pytest.fixture
def identity():
    return FakeIdentity({STUDENT_EMAIL: STUDENT_DN, STAFF_EMAIL: STAFF_DN})


@pytest.fixture
def client(tmp_path, policy, identity):
    config = make_config(tmp_path)
    unifi = MockUniFiClient()
    app = create_app(config, unifi_client=unifi, identity=identity, policy=policy)
    app.config["TESTING"] = True
    app.unifi = unifi  # stashed for assertions
    app.config_obj = config
    return app.test_client()


def mock_verify(mocker, email: str):
    return mocker.patch(
        "auth.verify_id_token", return_value={"email": email, "email_verified": True}
    )


def start_login(client, mac="AA:BB:CC:DD:EE:FF", ssid="Campus Student", extra=""):
    """Begin a sign-in, with the SSID supplied the way production supplies it.

    The portal does not trust ?ssid= - it is client-supplied and selects which
    role policy applies, so a crafted value could pick its own policy. Seeding
    the mock controller is what /stat/sta does in production. Note the URL below
    carries no ssid parameter at all, which is also the real shape of the
    gateway's redirect since the move to the Hotspot zone.
    """
    unifi = getattr(client.application, "unifi", None)
    assert unifi is not None, "the app fixture must stash .unifi for this helper"
    unifi.ssids[mac] = ssid
    resp = client.get(f"/login?mac={mac}{extra}")
    assert resp.status_code == 302
    query = parse_qs(urlparse(resp.headers["Location"]).query)
    return query["state"][0]


def test_health_lists_configured_ssids(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json["status"] == "ok"
    assert resp.json["ssids"] == ["Campus Staff", "Campus Student"]


def test_login_requires_mac_and_ssid(client):
    assert client.get("/login").status_code == 400


def _client_with_controller_ssids(tmp_path, policy, identity, ssids, ip_ssids=None):
    unifi = MockUniFiClient(ssids=ssids, ip_ssids=ip_ssids)
    app = create_app(make_config(tmp_path), unifi_client=unifi, identity=identity,
                     policy=policy)
    app.config["TESTING"] = True
    app.unifi = unifi
    return app.test_client(), unifi


MAC = "AA:BB:CC:DD:EE:FF"


def test_login_resolves_ssid_from_controller_when_redirect_omits_it(
    tmp_path, policy, identity
):
    """Since the student SSID moved to the Hotspot zone the gateway generates the
    external-portal redirect and drops &ssid=, which 400'd every /login on
    2026-08-17. The controller is asked instead.
    """
    c, unifi = _client_with_controller_ssids(
        tmp_path, policy, identity, {MAC: "Campus Student"}
    )
    resp = c.get(f"/login?mac={MAC}&ip=&url=http://www.google.com/gen_204")
    assert resp.status_code == 302
    assert "accounts.google.com" in resp.headers["Location"]
    assert MAC in unifi.ssid_lookups


def test_login_fails_closed_when_no_source_knows_the_ssid(tmp_path, policy, identity):
    c, _ = _client_with_controller_ssids(tmp_path, policy, identity, {})
    resp = c.get(f"/login?mac={MAC}")
    assert resp.status_code == 400


def test_controller_ssid_beats_a_spoofed_query_param(tmp_path, policy, identity, mocker):
    """?ssid= is client-supplied and selects which role policy applies. A student
    crafting ?ssid=Campus+Student while actually associated with the staff SSID must
    still be judged against the staff SSID.
    """
    c, unifi = _client_with_controller_ssids(
        tmp_path, policy, identity, {MAC: "Campus Staff"}
    )
    resp = c.get(f"/login?mac={MAC}&ssid=Campus+Student")
    assert resp.status_code == 302
    state = parse_qs(urlparse(resp.headers["Location"]).query)["state"][0]
    mock_verify(mocker, STUDENT_EMAIL)
    resp = c.get(f"/callback?state={state}&code=fake")
    assert resp.status_code == 302
    assert "/wrong-network" in resp.headers["Location"]
    assert unifi.calls == []


def test_landing_resolves_ssid_from_controller(tmp_path, policy, identity):
    c, _ = _client_with_controller_ssids(
        tmp_path, policy, identity, {MAC: "Campus Student"}
    )
    resp = c.get(f"/guest/s/default/?id={MAC}&t=1786976627")
    assert resp.status_code == 200
    # The resolved SSID has to reach the sign-in link, url-encoded.
    assert b"ssid=Campus+Student" in resp.data
    # ...and the page must not show the "wrong network" warning, which is what a
    # blank SSID used to produce.
    assert b"not a network" not in resp.data.lower()


def test_login_creates_redirect_to_google(client):
    client.application.unifi.ssids["AA:BB:CC:DD:EE:FF"] = "Campus Student"
    resp = client.get("/login?mac=AA:BB:CC:DD:EE:FF")
    assert resp.status_code == 302
    assert "accounts.google.com" in resp.headers["Location"]


def test_callback_rejects_missing_state(client):
    assert client.get("/callback").status_code == 400


def test_callback_rejects_unknown_state(client):
    assert client.get("/callback?state=nope&code=whatever").status_code == 403


def test_callback_rejects_non_domain_email(client, mocker):
    state = start_login(client)
    mock_verify(mocker, "someone@gmail.com")
    resp = client.get(f"/callback?state={state}&code=fake")
    assert resp.status_code == 403
    assert client.application.unifi.calls == []


def test_callback_rejects_unrecognized_ou(client, mocker):
    state = start_login(client)
    mock_verify(mocker, "nobody@example.org")  # absent from FakeIdentity
    resp = client.get(f"/callback?state={state}&code=fake")
    assert resp.status_code == 403
    assert client.application.unifi.calls == []


def test_callback_rejects_staff_on_student_ssid(client, mocker):
    state = start_login(client, ssid="Campus Student")
    mock_verify(mocker, STAFF_EMAIL)
    resp = client.get(f"/callback?state={state}&code=fake")
    assert resp.status_code == 302
    assert "/wrong-network" in resp.headers["Location"]
    assert client.application.unifi.calls == []


def test_callback_rejects_student_on_staff_ssid(client, mocker):
    state = start_login(client, ssid="Campus Staff")
    mock_verify(mocker, STUDENT_EMAIL)
    resp = client.get(f"/callback?state={state}&code=fake")
    assert resp.status_code == 302
    assert "/wrong-network" in resp.headers["Location"]
    assert client.application.unifi.calls == []


def test_callback_success_authorizes_bound_mac(client, mocker):
    state = start_login(client, mac="AA:BB:CC:DD:EE:FF", ssid="Campus Student")
    mock_verify(mocker, STUDENT_EMAIL)
    resp = client.get(f"/callback?state={state}&code=fake")
    assert resp.status_code == 302
    assert "/success" in resp.headers["Location"]
    assert client.application.unifi.calls == [("AA:BB:CC:DD:EE:FF", 43200)]


def test_staff_succeeds_on_staff_ssid(client, mocker):
    state = start_login(client, mac="11:22:33:44:55:66", ssid="Campus Staff")
    mock_verify(mocker, STAFF_EMAIL)
    resp = client.get(f"/callback?state={state}&code=fake")
    assert resp.status_code == 302
    assert "/success" in resp.headers["Location"]
    assert client.application.unifi.calls == [("11:22:33:44:55:66", 43200)]


def test_unknown_ssid_is_denied_not_authorized(client, mocker):
    """Regression: an SSID absent from the policy previously matched neither
    hardcoded branch and fell through to authorize-guest unconditionally."""
    state = start_login(client, ssid="Some Other Network")
    mock_verify(mocker, STUDENT_EMAIL)
    resp = client.get(f"/callback?state={state}&code=fake")
    assert resp.status_code == 302
    assert "/wrong-network" in resp.headers["Location"]
    assert client.application.unifi.calls == []


def test_barred_role_gets_a_dead_end_message_not_wrong_network(tmp_path, policy, mocker):
    """A role no SSID admits (disabled / service accounts) must be told it is not
    permitted, not sent to "wrong network" - that invites endless SSID hopping.
    Observed with a real ou=_TEST GROUP account on 2026-08-03."""
    from conftest import SERVICE_ACCOUNT_DN

    email = "svc@example.org"
    unifi = MockUniFiClient()
    app = create_app(
        make_config(tmp_path),
        unifi_client=unifi,
        identity=FakeIdentity({email: SERVICE_ACCOUNT_DN}),
        policy=policy,
    )
    app.config["TESTING"] = True
    app.unifi = unifi
    c = app.test_client()
    state = start_login(c, ssid="Campus Student")
    mock_verify(mocker, email)
    resp = c.get(f"/callback?state={state}&code=fake")
    assert resp.status_code == 403
    assert b"not permitted" in resp.data
    assert b"wrong-network" not in resp.data.lower()
    assert unifi.calls == []


def test_ssid_match_is_case_sensitive(client, mocker):
    """The controller's SSID name is compared exactly; 'campus student' is not it."""
    state = start_login(client, ssid="campus student")
    mock_verify(mocker, STUDENT_EMAIL)
    client.get(f"/callback?state={state}&code=fake")
    assert client.application.unifi.calls == []


def test_callback_returns_502_when_unifi_fails(tmp_path, policy, identity, mocker):
    config = make_config(tmp_path)
    unifi = MockUniFiClient(fail=True)
    app = create_app(config, unifi_client=unifi, identity=identity, policy=policy)
    app.config["TESTING"] = True
    app.unifi = unifi
    client = app.test_client()
    state = start_login(client)
    mock_verify(mocker, STUDENT_EMAIL)
    resp = client.get(f"/callback?state={state}&code=fake")
    assert resp.status_code == 502


def test_callback_rejects_replayed_state(client, mocker):
    state = start_login(client)
    mock_verify(mocker, STUDENT_EMAIL)
    assert client.get(f"/callback?state={state}&code=fake").status_code == 302
    assert client.get(f"/callback?state={state}&code=fake").status_code == 403


def test_callback_rejects_blocklisted_email(client, mocker):
    state = start_login(client, ssid="Campus Student")
    mock_verify(mocker, STUDENT_EMAIL)
    with open(client.application.config_obj.BLOCKLIST_FILE, "w") as f:
        f.write(f"{STUDENT_EMAIL}\n")
    resp = client.get(f"/callback?state={state}&code=fake")
    assert resp.status_code == 403
    assert client.application.unifi.calls == []


def test_mac_never_trusted_from_callback_query_args(client, mocker):
    """Even if a caller passes a different mac= on the callback URL, the MAC used
    for authorization must come from the server-side session bound at /login."""
    state = start_login(client, mac="AA:BB:CC:DD:EE:FF", ssid="Campus Student")
    mock_verify(mocker, STUDENT_EMAIL)
    resp = client.get(f"/callback?state={state}&code=fake&mac=11:11:11:11:11:11")
    assert resp.status_code == 302
    assert client.application.unifi.calls == [("AA:BB:CC:DD:EE:FF", 43200)]


def test_landing_accepts_unifi_os_id_param(client):
    """UniFi OS sends the client MAC as ?id=, not ?mac=."""
    resp = client.get("/?id=AA:BB:CC:DD:EE:FF&ssid=Campus Student&ap=1&t=2")
    assert resp.status_code == 200
    assert b"AA:BB:CC:DD:EE:FF" in resp.data


def test_landing_warns_when_ssid_not_in_policy(client):
    # The controller reports an SSID this portal has no policy for.
    client.application.unifi.ssids["AA:BB:CC:DD:EE:FF"] = "Totally Unknown"
    resp = client.get("/?id=AA:BB:CC:DD:EE:FF")
    assert resp.status_code == 200
    assert b"Sign in with Google" not in resp.data


def test_landing_rejects_dangerous_next_url(client):
    """A javascript: url= from the redirect must not be echoed into the page."""
    resp = client.get("/?id=AA:BB:CC:DD:EE:FF&ssid=Campus Student&url=javascript:alert(1)")
    assert resp.status_code == 200
    assert b"javascript:" not in resp.data


def test_success_page_only_echoes_http_next_url(client):
    good = client.get("/success?next=https://example.org")
    assert b"https://example.org" in good.data
    bad = client.get("/success?next=javascript:alert(1)")
    assert b"javascript:" not in bad.data


def test_original_destination_survives_the_oauth_round_trip(client, mocker):
    state = start_login(client, extra="&url=https://example.org/page")
    mock_verify(mocker, STUDENT_EMAIL)
    resp = client.get(f"/callback?state={state}&code=fake")
    location = resp.headers["Location"]
    assert location.startswith("/success?")
    assert parse_qs(urlparse(location).query)["next"] == ["https://example.org/page"]


def test_login_falls_back_to_client_ip_when_controller_lacks_the_mac(
    tmp_path, policy, identity
):
    """The real 2026-08-24 failure: the client was actively fetching pages from
    the portal while absent from /stat/sta, because its AP was not reporting
    client telemetry. The source address still identifies the network.
    """
    c, unifi = _client_with_controller_ssids(
        tmp_path, policy, identity, {}, ip_ssids={"10.0.20.15": "Campus Student"}
    )
    resp = c.get(f"/login?mac={MAC}&ip=&url=http://www.google.com/gen_204",
                 environ_overrides={"REMOTE_ADDR": "10.0.20.15"})
    assert resp.status_code == 302
    assert "accounts.google.com" in resp.headers["Location"]
    assert unifi.ssid_lookups == [MAC]          # controller tried first
    assert unifi.ip_lookups == ["10.0.20.15"]  # then the address


def test_controller_wins_over_client_ip(tmp_path, policy, identity):
    """The controller is more specific, so it must not be overridden by the
    network-wide mapping when both can answer.
    """
    c, unifi = _client_with_controller_ssids(
        tmp_path, policy, identity, {MAC: "Campus Staff"},
        ip_ssids={"10.0.20.15": "Campus Student"},
    )
    resp = c.get(f"/login?mac={MAC}",
                 environ_overrides={"REMOTE_ADDR": "10.0.20.15"})
    assert resp.status_code == 302
    assert unifi.ip_lookups == []  # never consulted


def test_spoofed_query_ssid_loses_to_client_ip_too(tmp_path, policy, identity, mocker):
    """?ssid= is not trusted even when it is the ONLY parameter present and the
    controller cannot help. A student on the staff SSID crafting
    ?ssid=Campus+Student must still be judged against the staff SSID.
    """
    c, unifi = _client_with_controller_ssids(
        tmp_path, policy, identity, {}, ip_ssids={"10.0.30.15": "Campus Staff"}
    )
    resp = c.get(f"/login?mac={MAC}&ssid=Campus+Student",
                 environ_overrides={"REMOTE_ADDR": "10.0.30.15"})
    assert resp.status_code == 302
    state = parse_qs(urlparse(resp.headers["Location"]).query)["state"][0]
    mock_verify(mocker, STUDENT_EMAIL)
    resp = c.get(f"/callback?state={state}&code=fake")
    assert resp.status_code == 302
    assert "/wrong-network" in resp.headers["Location"]
    assert unifi.calls == []


def test_landing_falls_back_to_client_ip(tmp_path, policy, identity):
    c, _ = _client_with_controller_ssids(
        tmp_path, policy, identity, {}, ip_ssids={"10.0.20.15": "Campus Student"}
    )
    resp = c.get(f"/guest/s/default/?id={MAC}&t=1787575905",
                 environ_overrides={"REMOTE_ADDR": "10.0.20.15"})
    assert resp.status_code == 200
    assert b"ssid=Campus+Student" in resp.data


def test_favicon_does_not_404(client):
    """It 404'd on every single page load, in both the nginx and app logs."""
    resp = client.get("/favicon.ico")
    assert resp.status_code == 204


def test_pages_declare_an_inline_icon(client):
    """The icon must be inline: a pre-auth client has no internet, so an
    external URL could not load."""
    resp = client.get("/?id=AA:BB:CC:DD:EE:FF")
    assert resp.status_code == 200
    assert b'rel="icon"' in resp.data
    assert b"data:image/svg+xml" in resp.data
    # No resource in <head> may be fetched from off-box. The SVG's xmlns is an
    # http:// namespace *identifier*, never requested, so match on the attribute
    # that would actually cause a fetch.
    head = resp.data.split(b"</head>")[0]
    assert b'href="http' not in head
    assert b'src="http' not in head
