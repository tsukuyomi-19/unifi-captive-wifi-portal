import logging
from urllib.parse import urlparse

import time

from flask import (Blueprint, abort, redirect, render_template, request,
                   session as flask_session, url_for)

import auth
from blocklist import is_blocked
from config import Config
from connection_log import log_connection
from policy import Policy
from session_store import SessionStore
from unifi_client import UniFiClient

logger = logging.getLogger("wifi_portal.routes")


def _safe_next_url(raw: str) -> str | None:
    """The original destination UniFi passes as ?url=. Only http(s) absolute
    URLs are echoed back, so a crafted javascript:/data: value can't be turned
    into a redirect off the success page.
    """
    if not raw:
        return None
    parsed = urlparse(raw)
    if parsed.scheme in ("http", "https") and parsed.netloc:
        return raw
    return None


def _resolve_ssid(unifi: UniFiClient, mac: str, supplied: str, client_ip: str) -> str:
    """The SSID for this client, from the most trustworthy source available.

    Order: the controller's client record, then the client's own source address,
    then nothing. The query string is never trusted - see below.

    Why not the query string. UniFi stopped including &ssid= in the
    external-portal redirect when the student SSID moved to a purpose=guest
    network in the Hotspot zone: the *gateway* generates the redirect now (the
    ?ap= value is the UDM's own MAC) instead of the AP, and it omits the
    parameter. Beyond being absent, it is client-supplied, and the SSID selects
    which role policy applies - so a crafted ?ssid= could pick its own policy.

    Why the source address is needed as well. /stat/sta depends on the APs
    reporting client telemetry to the controller. On 2026-08-24 a client that was
    actively fetching pages from this portal did not appear in it at all: 14 of
    28 APs sit in an "isolated" state and only 60 of 101 wireless clients carried
    an essid. Resolving by client IP needs no cooperation from the APs, and the
    source address of an established TCP connection cannot be forged by the
    client either.

    Returns "" when neither source knows, and callers fail closed.
    """
    found = unifi.client_ssid(mac) if mac else None
    source = "controller"
    if not found:
        found = unifi.ssid_for_client_ip(client_ip)
        source = "client-ip"
    if not found:
        logger.warning(
            "no ssid for mac=%s ip=%s from controller or network mapping "
            "(query string said %r, which is not trusted)", mac, client_ip, supplied
        )
        return ""
    if supplied and supplied != found:
        logger.warning(
            "ssid mismatch for mac=%s: query said %r, %s says %r - using %r",
            mac, supplied, source, found, found,
        )
    else:
        logger.info("ssid %r for mac=%s resolved via %s", found, mac, source)
    return found


def build_routes_blueprint(
    config: Config, store: SessionStore, identity, unifi: UniFiClient, policy: Policy
) -> Blueprint:
    bp = Blueprint("portal", __name__)

    @bp.route("/favicon.ico")
    def favicon():
        """Answer the probe instead of 404ing on every page load.

        base.html declares an inline data: icon, so a compliant browser never
        asks for this. Captive-portal webviews ask anyway. 204 keeps it free -
        no file to deploy, no nginx alias, nothing for www-data to traverse.
        """
        return "", 204

    @bp.route("/health")
    def health():
        """Liveness probe for systemd/monitoring. Deliberately does not touch
        LDAP or UniFi so that it stays cheap and can't be used to probe them.
        """
        return {"status": "ok", "ssids": policy.known_ssids()}, 200

    @bp.route("/")
    @bp.route("/guest/s/<site>/")
    def landing(site: str | None = None):
        # UniFi OS (UDM/Cloud Gateway) External Portal Server redirects here with
        #   ?ap=<AP mac>&id=<client mac>&t=<ts>&url=<original destination>&ssid=<ssid>
        # "id" is the client MAC, not "mac". Classic controllers and manual
        # testing use "mac" - both accepted.
        mac = request.args.get("id") or request.args.get("mac", "")
        ssid = _resolve_ssid(unifi, mac, request.args.get("ssid", ""),
                             request.remote_addr or "")
        return render_template(
            "landing.html",
            mac=mac,
            ip=request.args.get("ip", ""),
            ssid=ssid,
            next_url=_safe_next_url(request.args.get("url", "")) or "",
            known_ssid=ssid in policy.ssid_roles if ssid else True,
            vouchers_enabled=config.VOUCHERS_ENABLED,
        )

    @bp.route("/login")
    def login():
        mac = request.args.get("mac")
        if not mac:
            abort(400, "Missing device address - reconnect to WiFi and try again.")
        ssid = _resolve_ssid(unifi, mac, request.args.get("ssid", ""),
                             request.remote_addr or "")
        if not ssid:
            # No trustworthy source could name the network; _resolve_ssid has
            # already logged the detail. Fail closed - the SSID decides which
            # roles are admitted.
            abort(400, "Could not identify the WiFi network - reconnect and try again.")

        store.cleanup_expired()
        state = store.create_session(
            mac, ssid, config.SESSION_TTL_SECONDS, next_url=_safe_next_url(request.args.get("url", ""))
        )

        flow = auth.build_flow(config, config.OAUTH_REDIRECT_URI)
        return redirect(auth.get_authorization_url(flow, state, config.HOSTED_DOMAIN))

    @bp.route("/callback")
    def callback():
        state = request.args.get("state")
        if not state:
            return render_template("error.html", message="Missing state parameter."), 400

        session_row = store.consume_session(state)
        if session_row is None:
            return render_template(
                "error.html", message="Session expired. Please reconnect and try again."
            ), 403

        # MAC comes from the server-side session bound at /login - never from
        # request.args here, so a tampered ?mac= cannot authorize another device.
        mac = session_row["mac"]
        originating_ssid = session_row["ssid"]
        next_url = session_row["next_url"]

        flow = auth.build_flow(config, config.OAUTH_REDIRECT_URI)
        try:
            id_info = auth.verify_id_token(flow, request.url, config)
        except auth.TokenVerificationError as e:
            # The reason goes to the app log, never to the page - it can contain
            # token-exchange detail. Without it, "Sign-in could not be verified"
            # is unactionable for whoever is on the other end of the ticket.
            logger.warning("token verification failed for mac=%s: %s", mac, e)
            log_connection("<unverified>", mac, originating_ssid, "N/A", "DENIED: token invalid")
            return render_template("error.html", message="Sign-in could not be verified."), 403

        email = id_info["email"]
        if not email.endswith(f"@{config.HOSTED_DOMAIN}"):
            log_connection(email, mac, originating_ssid, "N/A", "DENIED: wrong email domain")
            return render_template(
                "error.html", message="Unauthorized: use your school-issued Google account."
            ), 403

        if is_blocked(email, config.BLOCKLIST_FILE):
            log_connection(email, mac, originating_ssid, "N/A", "DENIED: blocklisted")
            return render_template(
                "error.html", message="This account is not permitted to connect. Contact IT."
            ), 403

        ou_path = identity.lookup_ou_path(email)
        role = policy.classify(ou_path or "")
        if role is None:
            log_connection(
                email, mac, originating_ssid, ou_path or "not-found", "DENIED: unrecognized OU"
            )
            return render_template(
                "error.html", message="Could not determine your account type. Contact IT."
            ), 403

        # A staff sign-in to the voucher page reuses this same callback, and
        # the same registered OAuth redirect URI - adding a second one would
        # mean a change in the Google Cloud console. The purpose column on the
        # state row is what distinguishes them.
        purpose = ("purpose" in session_row.keys() and session_row["purpose"]) \
            or "portal"
        if purpose == "staff":
            if role != "staff":
                log_connection(email, "-", "-", ou_path,
                               "DENIED: not staff, voucher page")
                return render_template(
                    "error.html",
                    message="Only staff can issue guest codes."), 403
            flask_session["staff_email"] = email
            flask_session["staff_expires"] = (
                time.time() + config.STAFF_SESSION_MINUTES * 60)
            log_connection(email, "-", "-", ou_path, "STAFF: voucher page")
            logger.info("staff session opened for %s", email)
            return redirect("/staff/vouchers")

        # Fail closed. Previously this compared against two hardcoded SSID
        # constants and any other SSID matched neither branch, falling through
        # to authorize the device regardless of role.
        if not policy.is_allowed(originating_ssid, role):
            permitted = policy.other_ssids_for(role)
            if not permitted:
                # No SSID admits this role at all - a disabled, suspended or
                # service account. Sending them to "wrong network" invites them
                # to hop SSIDs forever; observed with a real _TEST GROUP account.
                log_connection(email, mac, originating_ssid, ou_path, f"DENIED: {role} barred")
                return render_template(
                    "error.html",
                    message="This account is not permitted to use the WiFi. Contact IT.",
                ), 403
            log_connection(email, mac, originating_ssid, ou_path, f"DENIED: {role} not allowed here")
            return redirect(url_for("portal.wrong_network", network=", ".join(permitted)))

        if not unifi.authorize_guest(mac, config.AUTHORIZE_MINUTES):
            log_connection(email, mac, originating_ssid, ou_path, "ERROR: unifi authorize failed")
            return render_template(
                "error.html", message="Could not authorize this device. Contact IT."
            ), 502

        log_connection(email, mac, originating_ssid, ou_path, "AUTHORIZED")
        return redirect(url_for("portal.success", next=next_url or ""))

    @bp.route("/success")
    def success():
        return render_template("success.html", next_url=_safe_next_url(request.args.get("next", "")))

    @bp.route("/wrong-network")
    def wrong_network():
        return render_template("wrong_network.html", network=request.args.get("network", ""))

    return bp
