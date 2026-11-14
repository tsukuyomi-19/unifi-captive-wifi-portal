"""UniFi guest-authorization clients.

Three implementations, chosen by UNIFI_MODE:

  apikey  - X-API-KEY against the UniFi OS proxied Network API. Preferred.
  login   - username/password + CSRF. Kept as a fallback only.
  mock    - no network at all, for tests and local dev.

Why apikey is the default
-------------------------
The login path has to keep a session alive, and UniFi OS additionally requires
echoing back the x-csrf-token from the login response on every state-changing
request or the call silently 403s. Verified against a UDM Pro Max
(Network 10.5.67) on 2026-07-31: an API key issued from
Settings -> Integrations authenticates POST /cmd/stamgr directly, with no
login, no session, and no CSRF token:

    POST /proxy/network/api/s/default/cmd/stamgr
    X-API-KEY: <key>
    {"cmd":"authorize-guest","mac":"aa:bb:cc:dd:ee:ff","minutes":1}
    -> 200 {"meta":{"rc":"ok"},"data":[{...,"authorized_by":"api",...}]}

That removes the entire session/CSRF failure class.

Two real bugs in the previous implementation, both fixed here
------------------------------------------------------------
1. `resp.ok` was the success test. UniFi answers application-level failures
   with HTTP 200 and {"meta":{"rc":"error","msg":"api.err.NoSiteContext"}}, so
   a failed authorization was reported to the caller as success and the user
   saw "you're connected" while still having no internet. Success is now
   meta.rc == "ok".

2. `_logged_in` was set once and never cleared. UniFi sessions expire; after
   that every authorize_guest() returned False forever with no recovery short
   of restarting gunicorn. The login client now retries once on 401/403 after
   forcing a fresh login.
"""

from __future__ import annotations

import ipaddress
import logging
import time
from abc import ABC, abstractmethod
from typing import Any

import requests

logger = logging.getLogger("wifi_portal.unifi")

# 30 days, matching AUTHORIZE_MINUTES' default.
DEFAULT_MINUTES = 43200


class UniFiClient(ABC):
    @abstractmethod
    def authorize_guest(self, mac: str, minutes: int = DEFAULT_MINUTES) -> bool:
        """Authorize a MAC on the controller. True only on confirmed success."""

    @abstractmethod
    def unauthorize_guest(self, mac: str) -> bool:
        """Revoke a MAC's authorization. Used by admin tooling and tests."""

    @abstractmethod
    def client_ssid(self, mac: str) -> str | None:
        """The SSID a MAC is currently associated with, per the controller.

        None if the controller does not know the MAC, or on any error.
        """

    @abstractmethod
    def list_vouchers(self) -> list[dict[str, Any]]:
        """Every voucher the controller knows about.

        The controller is the registry of which codes exist; redemption state
        lives locally (see voucher_store) because `auth=custom` means UniFi
        never sees a redemption and its own `used` counter never moves.
        """

    @abstractmethod
    def create_voucher(self, note: str, minutes: int, quota: int = 0,
                       down_kbps: int | None = None,
                       up_kbps: int | None = None) -> list[str]:
        """Create one voucher and return the code(s) created.

        quota=0 means unlimited devices, matching UniFi's VALID_MULTI.
        """

    @abstractmethod
    def ssid_for_client_ip(self, ip: str) -> str | None:
        """The SSID implied by a client's own source address.

        Maps ip -> the network whose subnet contains it -> the SSID bound to
        that network. None if the address matches no network, or if the network
        has zero or several SSIDs, in which case the answer is ambiguous.
        """


def _rc_ok(resp: requests.Response) -> bool:
    """UniFi signals application errors with HTTP 200 + meta.rc == "error"."""
    if not resp.ok:
        logger.warning("unifi HTTP %s: %s", resp.status_code, resp.text[:300])
        return False
    try:
        payload: Any = resp.json()
    except ValueError:
        logger.warning("unifi returned non-JSON body: %s", resp.text[:300])
        return False
    rc = (payload.get("meta") or {}).get("rc")
    if rc != "ok":
        msg = (payload.get("meta") or {}).get("msg", "<no msg>")
        logger.warning("unifi rc=%s msg=%s", rc, msg)
        return False
    return True


class _HttpUniFiClientBase(UniFiClient):
    def __init__(
        self, host: str, site: str = "default", verify_tls: bool = False, timeout: int = 10
    ):
        self.host = host
        self.site = site
        self.verify_tls = verify_tls
        self.timeout = timeout
        self._session = requests.Session()
        self._session.verify = verify_tls
        if not verify_tls:
            # The UDM presents a self-signed cert on the LAN. This client is only
            # ever pointed at UNIFI_HOST, never a third party, so pinning off
            # verification here is contained - but don't let it spam the logs.
            import urllib3

            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    @property
    def _cmd_url(self) -> str:
        return f"https://{self.host}/proxy/network/api/s/{self.site}/cmd/stamgr"

    @property
    def _sta_url(self) -> str:
        return f"https://{self.host}/proxy/network/api/s/{self.site}/stat/sta"

    def _conf_url(self, name: str) -> str:
        return f"https://{self.host}/proxy/network/api/s/{self.site}/rest/{name}"

    # Config endpoints are stable, so a short cache keeps the portal off the
    # controller on every request without risking a stale answer for long.
    _CONF_TTL = 60.0

    def _config(self, name: str) -> list[dict[str, Any]]:
        cache = getattr(self, "_conf_cache", None)
        if cache is None:
            cache = self._conf_cache = {}
        hit = cache.get(name)
        now = time.monotonic()
        if hit and now - hit[0] < self._CONF_TTL:
            return hit[1]
        try:
            resp = self._get(self._conf_url(name))
        except requests.RequestException as e:
            logger.warning("unifi /rest/%s request failed: %s", name, e)
            return hit[1] if hit else []
        if not _rc_ok(resp):
            return hit[1] if hit else []
        try:
            data = resp.json().get("data") or []
        except ValueError:
            return hit[1] if hit else []
        cache[name] = (now, data)
        return data

    @property
    def _voucher_url(self) -> str:
        return f"https://{self.host}/proxy/network/api/s/{self.site}/stat/voucher"

    @property
    def _hotspot_url(self) -> str:
        return f"https://{self.host}/proxy/network/api/s/{self.site}/cmd/hotspot"

    def list_vouchers(self) -> list[dict[str, Any]]:
        try:
            resp = self._get(self._voucher_url)
        except requests.RequestException as e:
            logger.warning("unifi voucher list failed: %s", e)
            return []
        if not _rc_ok(resp):
            return []
        try:
            return resp.json().get("data") or []
        except ValueError:
            return []

    def create_voucher(self, note: str, minutes: int, quota: int = 0,
                       down_kbps: int | None = None,
                       up_kbps: int | None = None) -> list[str]:
        payload: dict[str, Any] = {
            "cmd": "create-voucher",
            "n": 1,                 # how many vouchers
            "quota": int(quota),    # 0 = unlimited devices (VALID_MULTI)
            "expire": int(minutes),
            "note": note,
        }
        if down_kbps or up_kbps:
            payload["down"] = int(down_kbps or 0)
            payload["up"] = int(up_kbps or 0)
        try:
            resp = self._post(self._hotspot_url, payload)
        except requests.RequestException as e:
            logger.warning("unifi create-voucher failed: %s", e)
            return []
        if not _rc_ok(resp):
            return []
        # create-voucher returns a create_time, not the codes. The codes have to
        # be read back and matched - UniFi offers no better handle than this.
        try:
            created = (resp.json().get("data") or [{}])[0].get("create_time")
        except (ValueError, IndexError, AttributeError):
            created = None
        if created is None:
            return []
        return [v.get("code") for v in self.list_vouchers()
                if v.get("create_time") == created and v.get("code")]

    def _post(self, url: str, payload: dict[str, Any]) -> requests.Response:
        """POST with whatever auth the subclass established."""
        return self._session.post(url, json=payload, timeout=self.timeout)

    def ssid_for_client_ip(self, ip: str) -> str | None:
        """See UniFiClient.ssid_for_client_ip.

        This deliberately does NOT use /stat/sta. That endpoint depends on the
        APs reporting client telemetry to the controller, and on 2026-08-24 a
        client that was actively fetching pages from this portal was absent from
        it entirely - 14 of 28 APs sit in an "isolated" state and only 60 of 101
        wireless clients carried an essid at all. The client's own source
        address needs no such cooperation.

        Both lookups read live config, so a subnet change is picked up on the
        next cache expiry rather than baking in an address range.
        """
        if not ip:
            return None
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            logger.warning("unroutable client ip %r", ip)
            return None

        best, best_len = None, -1
        for net in self._config("networkconf"):
            subnet = net.get("ip_subnet")
            if not subnet:
                continue
            try:
                candidate = ipaddress.ip_interface(subnet).network
            except ValueError:
                continue
            # Longest prefix wins, so a /21 does not shadow a /27 inside it.
            if addr in candidate and candidate.prefixlen > best_len:
                best, best_len = net, candidate.prefixlen
        if best is None:
            logger.info("no configured network contains client ip %s", ip)
            return None

        names = [w.get("name") for w in self._config("wlanconf")
                 if w.get("networkconf_id") == best.get("_id") and w.get("name")]
        if len(names) == 1:
            return str(names[0])
        logger.warning(
            "network %r (%s) has %d SSIDs %r, so the SSID for ip %s is ambiguous",
            best.get("name"), best.get("ip_subnet"), len(names), names, ip,
        )
        return None

    def _post_cmd(self, payload: dict[str, Any]) -> requests.Response:
        raise NotImplementedError

    def _get(self, url: str) -> requests.Response:
        """GET with whatever auth the subclass established. Overridden by the
        login client, which has to log in first.
        """
        return self._session.get(url, timeout=self.timeout)

    def client_ssid(self, mac: str) -> str | None:
        if not mac:
            return None
        want = mac.strip().casefold()
        try:
            resp = self._get(self._sta_url)
        except requests.RequestException as e:
            logger.warning("unifi /stat/sta request failed: %s", e)
            return None
        if not _rc_ok(resp):
            return None
        try:
            data = resp.json().get("data") or []
        except ValueError:
            return None
        for client in data:
            if str(client.get("mac", "")).casefold() == want:
                essid = client.get("essid")
                return str(essid) if essid else None
        logger.info("unifi does not know mac=%s (of %d clients)", mac, len(data))
        return None

    def authorize_guest(self, mac: str, minutes: int = DEFAULT_MINUTES,
                        down_kbps: int | None = None,
                        up_kbps: int | None = None) -> bool:
        payload: dict[str, Any] = {"cmd": "authorize-guest", "mac": mac,
                                   "minutes": minutes}
        # Guest codes are bandwidth-capped so a tour group cannot crowd out
        # students; the previous dash_script vouchers used the same 10/5 Mbps.
        if down_kbps:
            payload["down"] = int(down_kbps)
        if up_kbps:
            payload["up"] = int(up_kbps)
        return self._cmd(payload)

    def unauthorize_guest(self, mac: str) -> bool:
        return self._cmd({"cmd": "unauthorize-guest", "mac": mac})

    def _cmd(self, payload: dict[str, Any]) -> bool:
        try:
            resp = self._post_cmd(payload)
        except requests.RequestException as e:
            logger.warning("unifi request failed: %s", e)
            return False
        return _rc_ok(resp)


class ApiKeyUniFiClient(_HttpUniFiClientBase):
    """Preferred client. Stateless - no login, no session, no CSRF token."""

    def __init__(self, host: str, api_key: str, site: str = "default", **kw):
        super().__init__(host, site=site, **kw)
        if not api_key:
            raise ValueError("UNIFI_API_KEY is required when UNIFI_MODE=apikey")
        self._session.headers.update(
            {
                "X-API-KEY": api_key,
                "Accept": "application/json",
                "Content-Type": "application/json",
            }
        )

    def _post_cmd(self, payload: dict[str, Any]) -> requests.Response:
        return self._session.post(self._cmd_url, json=payload, timeout=self.timeout)


class LoginUniFiClient(_HttpUniFiClientBase):
    """Fallback for controllers without API-key support. Requires a *local*
    UniFi admin account - Ubiquiti cloud/SSO accounts cannot use /api/auth/login.
    """

    def __init__(self, host: str, username: str, password: str, site: str = "default", **kw):
        super().__init__(host, site=site, **kw)
        self.username = username
        self.password = password
        self._logged_in = False

    def _login(self) -> None:
        resp = self._session.post(
            f"https://{self.host}/api/auth/login",
            json={"username": self.username, "password": self.password},
            timeout=self.timeout,
        )
        resp.raise_for_status()
        csrf = resp.headers.get("x-csrf-token")
        if csrf:
            # Required on UniFi OS for every subsequent state-changing request.
            self._session.headers["x-csrf-token"] = csrf
        self._logged_in = True

    def _get(self, url: str) -> requests.Response:
        if not self._logged_in:
            self._login()
        resp = self._session.get(url, timeout=self.timeout)
        if resp.status_code in (401, 403):
            self._logged_in = False
            self._login()
            resp = self._session.get(url, timeout=self.timeout)
        return resp

    def _post(self, url: str, payload: dict[str, Any]) -> requests.Response:
        if not self._logged_in:
            self._login()
        resp = self._session.post(url, json=payload, timeout=self.timeout)
        if resp.status_code in (401, 403):
            self._logged_in = False
            self._login()
            resp = self._session.post(url, json=payload, timeout=self.timeout)
        return resp

    def _post_cmd(self, payload: dict[str, Any]) -> requests.Response:
        if not self._logged_in:
            self._login()
        resp = self._session.post(self._cmd_url, json=payload, timeout=self.timeout)
        if resp.status_code in (401, 403):
            # Session expired or CSRF token rotated. Force a fresh login and
            # retry exactly once - the old code latched _logged_in=True here and
            # never recovered.
            logger.info("unifi returned %s, re-logging in and retrying once", resp.status_code)
            self._logged_in = False
            self._login()
            resp = self._session.post(self._cmd_url, json=payload, timeout=self.timeout)
        return resp


class MockUniFiClient(UniFiClient):
    """Records calls for assertions; never touches the network."""

    def __init__(self, fail: bool = False, ssids: dict[str, str] | None = None,
                 ip_ssids: dict[str, str] | None = None,
                 vouchers: list[dict] | None = None):
        self.vouchers = list(vouchers or [])
        self.created: list[dict] = []
        self.calls: list[tuple[str, int]] = []
        self.revoked: list[str] = []
        self.ssid_lookups: list[str] = []
        self.ip_lookups: list[str] = []
        self.ssids = ssids or {}
        self.ip_ssids = ip_ssids or {}
        self.fail = fail

    def authorize_guest(self, mac: str, minutes: int = DEFAULT_MINUTES,
                        down_kbps: int | None = None,
                        up_kbps: int | None = None) -> bool:
        self.calls.append((mac, minutes))
        self.rate_caps = getattr(self, "rate_caps", [])
        self.rate_caps.append((down_kbps, up_kbps))
        return not self.fail

    def list_vouchers(self) -> list[dict]:
        return list(self.vouchers)

    def create_voucher(self, note: str, minutes: int, quota: int = 0,
                       down_kbps: int | None = None,
                       up_kbps: int | None = None) -> list[str]:
        if self.fail:
            return []
        code = f"{9000000000 + len(self.created)}"
        rec = {"code": code, "note": note, "duration": minutes, "quota": quota,
               "used": 0, "status": "VALID_MULTI"}
        self.created.append(rec)
        self.vouchers.append(rec)
        return [code]

    def unauthorize_guest(self, mac: str) -> bool:
        self.revoked.append(mac)
        return not self.fail

    # `fail` deliberately does NOT affect the two lookups: it models a
    # controller that rejects authorize-guest, which can still answer queries.
    def client_ssid(self, mac: str) -> str | None:
        self.ssid_lookups.append(mac)
        return self.ssids.get(mac)

    def ssid_for_client_ip(self, ip: str) -> str | None:
        self.ip_lookups.append(ip)
        return self.ip_ssids.get(ip)


def build_unifi_client(config) -> UniFiClient:
    """Construct the client named by config.UNIFI_MODE."""
    mode = (config.UNIFI_MODE or "").strip().casefold()
    if mode == "mock":
        return MockUniFiClient()
    if mode == "apikey":
        return ApiKeyUniFiClient(config.UNIFI_HOST, config.UNIFI_API_KEY, site=config.UNIFI_SITE)
    if mode == "login":
        return LoginUniFiClient(
            config.UNIFI_HOST, config.UNIFI_USER, config.UNIFI_PASS, site=config.UNIFI_SITE
        )
    raise ValueError(f"UNIFI_MODE must be one of apikey/login/mock, got {config.UNIFI_MODE!r}")


# Backwards-compatible alias: the pre-existing tests and any leftover imports
# refer to RealUniFiClient, which was the login-based implementation.
RealUniFiClient = LoginUniFiClient
