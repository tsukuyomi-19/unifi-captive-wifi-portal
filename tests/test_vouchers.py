"""Guest access codes: classification, expiry, redemption, and the limits."""

import re
from datetime import datetime, timezone

import pytest

import vouchers
from app import create_app
from conftest import STAFF_DN, STUDENT_DN, FakeIdentity, make_config
from unifi_client import MockUniFiClient
from voucher_store import VoucherStore

STUDENT_EMAIL = "jstudent@example.org"
STAFF_EMAIL = "astaff@example.org"
MAC = "AA:BB:CC:DD:EE:FF"

GUEST_V = {"code": "1234567890", "note": "GUEST - Smith tour (by staff@x)",
           "quota": 0, "used": 0, "status": "VALID_MULTI"}
FILTER_V = {"code": "2222222222", "note": "FILTER - jdoe covenant eyes (by staff@x)",
            "quota": 0, "used": 0, "status": "VALID_MULTI"}
# Shape of the ten vouchers a dash_script left on the real controller in 2025.
LEGACY_V = {"code": "1234567890", "note": "legacyuser@example.org",
            "quota": 0, "used": 0, "status": "VALID_MULTI"}


# ------------------------------------------------------------------ unit level

def test_classify_recognises_both_prefixes():
    assert vouchers.classify("GUEST - Smith tour") == vouchers.GUEST
    assert vouchers.classify("GUEST- no space") == vouchers.GUEST
    assert vouchers.classify("FILTER - jdoe") == vouchers.FILTER
    assert vouchers.classify("filter - lowercase") == vouchers.FILTER


def test_legacy_vouchers_are_not_redeemable():
    """The ten 2025 dash_script vouchers have bare-email notes. They must not
    become live keys the moment code login is switched on."""
    assert vouchers.classify("legacyuser@example.org") is None
    assert vouchers.classify("") is None
    assert vouchers.classify(None) is None


def test_school_year_end_anchors_to_30_june():
    sept = datetime(2026, 9, 1, tzinfo=timezone.utc)
    may = datetime(2027, 5, 1, tzinfo=timezone.utc)
    # A September code runs to the following June, a May code only to that June -
    # a rolling ten months would have carried the May one into the next school
    # year.
    assert datetime.fromtimestamp(vouchers.school_year_end(sept),
                                  timezone.utc).year == 2027
    assert datetime.fromtimestamp(vouchers.school_year_end(may),
                                  timezone.utc).year == 2027
    assert datetime.fromtimestamp(vouchers.school_year_end(sept),
                                  timezone.utc).month == 6


def test_guest_expiry_is_one_day_from_first_use():
    now = 1_800_000_000
    assert vouchers.expiry_for(vouchers.GUEST, now) == now + 86400


def test_remaining_minutes_does_not_extend_on_later_devices():
    """A second device joining an 18-hour-old guest code gets the remainder, not
    a fresh day - otherwise each device silently renews the code."""
    now = 1_800_000_000
    expires = vouchers.expiry_for(vouchers.GUEST, now)
    assert vouchers.remaining_minutes(expires, now) == 1440
    later = now + 18 * 3600
    assert vouchers.remaining_minutes(expires, later) == 6 * 60


def test_normalise_code_strips_what_people_actually_type():
    assert vouchers.normalise_code("04885-65485") == "0488565485"
    assert vouchers.normalise_code(" 1234 5678 90 ") == "1234567890"


def test_store_first_use_is_not_overwritten(tmp_path):
    st = VoucherStore(str(tmp_path / "v.db"))
    st.init_db()
    first = st.begin_or_get("abc", vouchers.GUEST, 1000)
    second = st.begin_or_get("abc", vouchers.GUEST, 999999)
    assert first["expires"] == second["expires"] == 1000


# ------------------------------------------------------------- route level

@pytest.fixture
def app_and_unifi(tmp_path, policy):
    def _build(vlist=None, ip_ssids=None, **cfg):
        unifi = MockUniFiClient(vouchers=list(vlist or []),
                                ip_ssids=ip_ssids or {})
        app = create_app(
            make_config(tmp_path, **cfg),
            unifi_client=unifi,
            identity=FakeIdentity({STUDENT_EMAIL: STUDENT_DN,
                                   STAFF_EMAIL: STAFF_DN}),
            policy=policy,
        )
        app.config["TESTING"] = True
        return app, unifi
    return _build


def _token(client, mac=MAC, ssid="Campus+Student"):
    """Obtain a binding token the way a real client does.

    The MAC is bound server-side at GET /guest; the form carries only this
    token. Tests must go through it, because posting a bare MAC is exactly the
    tampering the binding exists to prevent.
    """
    q = f"/guest?ssid={ssid}" + (f"&mac={mac}" if mac else "")
    r = client.get(q)
    assert r.status_code == 200
    return re.search(rb'name="token" value="([^"]+)"', r.data).group(1).decode()


def _redeem(client, code, mac=MAC):
    return client.post("/guest", data={"token": _token(client, mac), "code": code})


def test_a_client_cannot_authorize_a_different_device(app_and_unifi):
    """The MAC must come from the controller's redirect, never the form.

    /callback has always bound it server-side for this reason; the code flow
    initially took it from a hidden field, which let a guest with a valid code
    authorize somebody else's device.
    """
    app, unifi = app_and_unifi([GUEST_V])
    c = app.test_client()
    token = _token(c, mac=MAC)
    # Try to smuggle a different MAC alongside the legitimate token.
    r = c.post("/guest", data={"token": token, "code": "1234567890",
                              "mac": "99:99:99:99:99:99"})
    assert r.status_code == 200
    assert len(unifi.calls) == 1
    assert unifi.calls[0][0] == MAC          # the bound MAC, not the posted one


def test_post_without_a_token_is_refused(app_and_unifi):
    app, unifi = app_and_unifi([GUEST_V])
    c = app.test_client()
    assert c.post("/guest", data={"code": "1234567890"}).status_code == 403
    assert c.post("/guest", data={"token": "forged", "code": "1234567890"}
                  ).status_code == 403
    assert unifi.calls == []


def test_a_wrong_code_does_not_burn_the_binding(app_and_unifi):
    """A mistyped code must be retryable: the token survives, so the guest is
    not sent back to the start with the MAC lost."""
    app, unifi = app_and_unifi([GUEST_V])
    c = app.test_client()
    token = _token(c)
    assert c.post("/guest", data={"token": token, "code": "0000000000"}
                  ).status_code == 400
    assert c.post("/guest", data={"token": token, "code": "1234567890"}
                  ).status_code == 200
    assert unifi.calls[0][0] == MAC


def test_binding_is_spent_once_a_code_succeeds(app_and_unifi):
    app, unifi = app_and_unifi([GUEST_V])
    c = app.test_client()
    token = _token(c)
    assert c.post("/guest", data={"token": token, "code": "1234567890"}
                  ).status_code == 200
    # replaying the same token cannot authorize again
    assert c.post("/guest", data={"token": token, "code": "1234567890"}
                  ).status_code == 403
    assert len(unifi.calls) == 1


def test_empty_code_does_not_count_towards_lockout(app_and_unifi):
    """Fumbling the form is not a guess; counting it would let a guest lock
    themselves out without ever entering a wrong code."""
    app, unifi = app_and_unifi([GUEST_V], VOUCHER_MAX_ATTEMPTS=2)
    c = app.test_client()
    token = _token(c)
    for _ in range(4):
        assert c.post("/guest", data={"token": token, "code": ""}).status_code == 400
    assert c.post("/guest", data={"token": token, "code": "1234567890"}
                  ).status_code == 200


def test_guest_code_authorizes_and_rate_limits(app_and_unifi):
    app, unifi = app_and_unifi([GUEST_V])
    c = app.test_client()
    r = _redeem(c, "1234567890")
    assert r.status_code == 200
    assert unifi.calls and unifi.calls[0][0] == MAC
    # one day, and bandwidth-capped so a tour cannot crowd out students
    assert unifi.calls[0][1] == 1440
    assert unifi.rate_caps[0] == (10000, 5000)


def test_filter_code_is_uncapped_and_long_lived(app_and_unifi):
    app, unifi = app_and_unifi([FILTER_V])
    c = app.test_client()
    r = _redeem(c, "2222222222")
    assert r.status_code == 200
    assert unifi.rate_caps[0] == (None, None)
    # runs to the end of the school year, so far more than a day
    assert unifi.calls[0][1] > 1440


def test_legacy_voucher_is_refused_end_to_end(app_and_unifi):
    app, unifi = app_and_unifi([LEGACY_V])
    c = app.test_client()
    r = _redeem(c, "1234567890")
    assert r.status_code == 400
    assert unifi.calls == []


def test_unknown_code_is_refused(app_and_unifi):
    app, unifi = app_and_unifi([GUEST_V])
    c = app.test_client()
    r = _redeem(c, "0000000000")
    assert r.status_code == 400
    assert unifi.calls == []


def test_brute_force_is_locked_out(app_and_unifi):
    """Without this the 10-digit keyspace is irrelevant: the guest is on an open
    SSID and can submit the form as fast as it will accept."""
    app, unifi = app_and_unifi([GUEST_V], VOUCHER_MAX_ATTEMPTS=3)
    c = app.test_client()
    token = _token(c)
    for _ in range(3):
        assert c.post("/guest", data={"token": token, "code": "0000000000"}
                      ).status_code == 400
    # locked out now - and even the CORRECT code is refused while locked
    r = c.post("/guest", data={"token": token, "code": "1234567890"})
    assert r.status_code == 429
    assert unifi.calls == []


def test_a_good_code_clears_the_attempt_counter(app_and_unifi):
    app, unifi = app_and_unifi([GUEST_V], VOUCHER_MAX_ATTEMPTS=3)
    c = app.test_client()
    token = _token(c)
    c.post("/guest", data={"token": token, "code": "0000000000"})
    c.post("/guest", data={"token": token, "code": "0000000000"})
    assert c.post("/guest", data={"token": token, "code": "1234567890"}
                  ).status_code == 200
    # counter reset, so a later typo does not immediately lock the guest out
    assert _redeem(c, "0000000000").status_code == 400


def test_redemption_without_a_mac_is_refused(app_and_unifi):
    """Nothing to authorize, and accepting it would let someone burn codes
    anonymously."""
    app, unifi = app_and_unifi([GUEST_V])
    c = app.test_client()
    # A binding created without a MAC (no ?mac= in the redirect) has nothing to
    # authorize, so redemption is refused rather than silently doing nothing.
    token = _token(c, mac="")
    assert c.post("/guest", data={"token": token, "code": "1234567890"}
                  ).status_code == 400
    assert unifi.calls == []


def test_second_device_inherits_the_original_deadline(app_and_unifi):
    app, unifi = app_and_unifi([GUEST_V])
    c = app.test_client()
    _redeem(c, "1234567890", mac=MAC)
    _redeem(c, "1234567890", mac="11:22:33:44:55:66")
    assert len(unifi.calls) == 2
    # second device gets no MORE time than the first
    assert unifi.calls[1][1] <= unifi.calls[0][1]


def test_staff_page_requires_sign_in(app_and_unifi):
    app, _ = app_and_unifi([])
    c = app.test_client()
    r = c.get("/staff/vouchers")
    assert r.status_code == 302
    assert "accounts.google.com" in r.headers["Location"]


def test_staff_creation_requires_a_session(app_and_unifi):
    app, unifi = app_and_unifi([])
    c = app.test_client()
    r = c.post("/staff/vouchers", data={"class": "guest", "label": "x"})
    assert r.status_code == 403
    assert unifi.created == []


def test_routes_absent_when_feature_disabled(app_and_unifi):
    app, _ = app_and_unifi([GUEST_V], VOUCHERS_ENABLED=False)
    c = app.test_client()
    assert c.get("/guest").status_code == 404
    assert c.get("/staff/vouchers").status_code == 404


def test_enabling_without_a_secret_key_fails_at_startup(tmp_path, policy):
    """Otherwise the staff session cookie is unsigned - discovered at first use
    rather than at deploy."""
    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        create_app(
            make_config(tmp_path, VOUCHERS_ENABLED=True, SECRET_KEY=""),
            unifi_client=MockUniFiClient(),
            identity=FakeIdentity({}),
            policy=policy,
        )


def _staff_signin(app, unifi, mocker, email=STAFF_EMAIL):
    """Drive the real staff OAuth round trip: /staff/vouchers -> Google -> /callback."""
    from urllib.parse import parse_qs, urlparse
    c = app.test_client()
    r = c.get("/staff/vouchers")
    state = parse_qs(urlparse(r.headers["Location"]).query)["state"][0]
    mocker.patch("auth.verify_id_token",
                 return_value={"email": email, "email_verified": True})
    r = c.get(f"/callback?state={state}&code=fake")
    return c, r


def test_staff_signin_opens_the_voucher_page(app_and_unifi, mocker):
    app, unifi = app_and_unifi([GUEST_V])
    c, r = _staff_signin(app, unifi, mocker)
    assert r.status_code == 302
    assert "/staff/vouchers" in r.headers["Location"]
    page = c.get("/staff/vouchers")
    assert page.status_code == 200
    assert b"Issue a WiFi code" in page.data


def test_a_student_cannot_reach_the_voucher_page(app_and_unifi, mocker):
    """The staff branch reuses the same OU lookup as the portal, so role is
    authoritative - a student completing Google sign-in must still be refused."""
    app, unifi = app_and_unifi([])
    c, r = _staff_signin(app, unifi, mocker, email=STUDENT_EMAIL)
    assert r.status_code == 403
    assert b"Only staff" in r.data
    assert c.post("/staff/vouchers",
                  data={"class": "guest", "label": "x"}).status_code == 403
    assert unifi.created == []


def test_staff_can_create_each_class(app_and_unifi, mocker):
    app, unifi = app_and_unifi([])
    c, _ = _staff_signin(app, unifi, mocker)
    for klass, prefix in (("guest", "GUEST -"), ("filter", "FILTER -")):
        # Creation redirects (post/redirect/get) so a refresh cannot mint
        # another code.
        r = c.post("/staff/vouchers", data={"class": klass, "label": "Smith"})
        assert r.status_code == 302
        note = unifi.created[-1]["note"]
        assert note.startswith(prefix)
        # the issuer is recorded on the voucher itself, so attribution survives
        # even if our local database is lost
        assert STAFF_EMAIL in note
    assert len(unifi.created) == 2


def test_created_code_is_immediately_redeemable(app_and_unifi, mocker):
    app, unifi = app_and_unifi([])
    c, _ = _staff_signin(app, unifi, mocker)
    c.post("/staff/vouchers", data={"class": "guest", "label": "tour"})
    code = unifi.created[-1]["code"]
    guest = app.test_client()
    r = _redeem(guest, code)
    assert r.status_code == 200
    assert unifi.calls[-1][0] == MAC


def test_unknown_class_is_rejected(app_and_unifi, mocker):
    app, unifi = app_and_unifi([])
    c, _ = _staff_signin(app, unifi, mocker)
    assert c.post("/staff/vouchers",
                  data={"class": "admin", "label": "x"}).status_code == 400
    assert unifi.created == []


def test_staff_logout_ends_the_session(app_and_unifi, mocker):
    app, unifi = app_and_unifi([])
    c, _ = _staff_signin(app, unifi, mocker)
    assert c.get("/staff/vouchers").status_code == 200
    c.get("/staff/logout")
    assert c.get("/staff/vouchers").status_code == 302
