import pytest
import requests

from conftest import make_config
from unifi_client import (
    ApiKeyUniFiClient,
    LoginUniFiClient,
    MockUniFiClient,
    _rc_ok,
    build_unifi_client,
)


# --- Mock -----------------------------------------------------------------
def test_mock_records_call_and_succeeds():
    client = MockUniFiClient()
    assert client.authorize_guest("AA:BB:CC:DD:EE:FF", 43200) is True
    assert client.calls == [("AA:BB:CC:DD:EE:FF", 43200)]


def test_mock_fail_mode_returns_false():
    client = MockUniFiClient(fail=True)
    assert client.authorize_guest("AA:BB:CC:DD:EE:FF", 43200) is False
    assert client.calls == [("AA:BB:CC:DD:EE:FF", 43200)]


def test_mock_records_multiple_calls():
    client = MockUniFiClient()
    client.authorize_guest("AA:AA:AA:AA:AA:AA")
    client.authorize_guest("BB:BB:BB:BB:BB:BB", 100)
    assert client.calls == [("AA:AA:AA:AA:AA:AA", 43200), ("BB:BB:BB:BB:BB:BB", 100)]


def test_mock_records_revocations():
    client = MockUniFiClient()
    assert client.unauthorize_guest("AA:AA:AA:AA:AA:AA") is True
    assert client.revoked == ["AA:AA:AA:AA:AA:AA"]


# --- meta.rc handling -----------------------------------------------------
class FakeResponse:
    def __init__(self, status_code=200, payload=None, text=""):
        self.status_code = status_code
        self.ok = 200 <= status_code < 300
        self._payload = payload
        self.text = text

    def json(self):
        if self._payload is None:
            raise ValueError("no json")
        return self._payload


def test_rc_ok_accepts_rc_ok():
    assert _rc_ok(FakeResponse(200, {"meta": {"rc": "ok"}, "data": []})) is True


def test_rc_ok_rejects_http_200_with_rc_error():
    """The bug this replaces: resp.ok alone reported this as success, so the
    user saw "you're connected" while having no internet."""
    resp = FakeResponse(200, {"meta": {"rc": "error", "msg": "api.err.NoSiteContext"}})
    assert _rc_ok(resp) is False


def test_rc_ok_rejects_non_2xx():
    assert _rc_ok(FakeResponse(403, {"meta": {"rc": "ok"}})) is False


def test_rc_ok_rejects_non_json_body():
    assert _rc_ok(FakeResponse(200, None, text="<html>login</html>")) is False


# --- API-key client -------------------------------------------------------
def test_apikey_client_requires_a_key():
    with pytest.raises(ValueError, match="UNIFI_API_KEY"):
        ApiKeyUniFiClient("192.168.1.1", "")


def test_apikey_client_sends_header_and_hits_stamgr(mocker):
    client = ApiKeyUniFiClient("192.168.1.1", "secret-key", site="default")
    post = mocker.patch.object(
        client._session, "post", return_value=FakeResponse(200, {"meta": {"rc": "ok"}})
    )
    assert client.authorize_guest("aa:bb:cc:dd:ee:ff", 60) is True
    assert post.call_args[0][0] == "https://192.168.1.1/proxy/network/api/s/default/cmd/stamgr"
    assert post.call_args[1]["json"] == {
        "cmd": "authorize-guest",
        "mac": "aa:bb:cc:dd:ee:ff",
        "minutes": 60,
    }
    assert client._session.headers["X-API-KEY"] == "secret-key"


def test_apikey_client_honours_site_override(mocker):
    client = ApiKeyUniFiClient("h", "k", site="other")
    post = mocker.patch.object(
        client._session, "post", return_value=FakeResponse(200, {"meta": {"rc": "ok"}})
    )
    client.authorize_guest("aa:bb:cc:dd:ee:ff")
    assert "/s/other/cmd/stamgr" in post.call_args[0][0]


def test_unauthorize_sends_the_right_command(mocker):
    client = ApiKeyUniFiClient("h", "k")
    post = mocker.patch.object(
        client._session, "post", return_value=FakeResponse(200, {"meta": {"rc": "ok"}})
    )
    assert client.unauthorize_guest("aa:bb:cc:dd:ee:ff") is True
    assert post.call_args[1]["json"] == {"cmd": "unauthorize-guest", "mac": "aa:bb:cc:dd:ee:ff"}


def test_network_error_returns_false_rather_than_raising(mocker):
    client = ApiKeyUniFiClient("h", "k")
    mocker.patch.object(client._session, "post", side_effect=requests.ConnectionError("down"))
    assert client.authorize_guest("aa:bb:cc:dd:ee:ff") is False


# --- Login client ---------------------------------------------------------
def test_login_client_retries_once_after_session_expiry(mocker):
    """Regression: _logged_in was latched true forever, so once the UniFi
    session expired every authorize_guest() returned False until a restart."""
    client = LoginUniFiClient("h", "u", "p")
    login = mocker.patch.object(
        client, "_login", side_effect=lambda: setattr(client, "_logged_in", True)
    )
    mocker.patch.object(
        client._session,
        "post",
        side_effect=[
            FakeResponse(401, {"meta": {"rc": "error"}}),
            FakeResponse(200, {"meta": {"rc": "ok"}}),
        ],
    )
    assert client.authorize_guest("aa:bb:cc:dd:ee:ff") is True
    assert login.call_count == 2  # initial login + one forced re-login


def test_login_client_gives_up_after_one_retry(mocker):
    client = LoginUniFiClient("h", "u", "p")
    mocker.patch.object(client, "_login", side_effect=lambda: setattr(client, "_logged_in", True))
    mocker.patch.object(
        client._session, "post", return_value=FakeResponse(403, {"meta": {"rc": "error"}})
    )
    assert client.authorize_guest("aa:bb:cc:dd:ee:ff") is False


def test_login_client_stores_csrf_token(mocker):
    client = LoginUniFiClient("h", "u", "p")

    class LoginResponse(FakeResponse):
        headers = {"x-csrf-token": "tok123"}

        def raise_for_status(self):
            return None

    mocker.patch.object(client._session, "post", return_value=LoginResponse(200, {}))
    client._login()
    assert client._session.headers["x-csrf-token"] == "tok123"


# --- Factory --------------------------------------------------------------
def test_factory_builds_mock(tmp_path):
    assert isinstance(build_unifi_client(make_config(tmp_path, UNIFI_MODE="mock")), MockUniFiClient)


def test_factory_builds_apikey(tmp_path):
    cfg = make_config(tmp_path, UNIFI_MODE="apikey", UNIFI_HOST="h", UNIFI_API_KEY="k")
    assert isinstance(build_unifi_client(cfg), ApiKeyUniFiClient)


def test_factory_builds_login(tmp_path):
    cfg = make_config(tmp_path, UNIFI_MODE="login", UNIFI_HOST="h", UNIFI_USER="u", UNIFI_PASS="p")
    assert isinstance(build_unifi_client(cfg), LoginUniFiClient)


def test_factory_rejects_unknown_mode(tmp_path):
    with pytest.raises(ValueError, match="UNIFI_MODE"):
        build_unifi_client(make_config(tmp_path, UNIFI_MODE="banana"))
