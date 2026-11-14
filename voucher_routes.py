"""Guest access-code routes: redemption for guests, issuing for staff.

Why this is a separate blueprint
-------------------------------
Two audiences with different trust levels share one Flask app. Keeping them in
separate modules makes it obvious which handlers are reachable by an
unauthenticated device on an open SSID (`/guest`) and which require a verified
staff identity (`/staff/*`).

Why guest redemption matters beyond guests
-----------------------------------------
A code is validated entirely locally - no Google, no internet, nothing leaves the
building. That is what makes it work for a student whose Covenant Eyes or
NetNanny VPN fails closed during the pre-authorization window and therefore
cannot reach accounts.google.com to sign in. The `FILTER -` class exists for
exactly that case.
"""

from __future__ import annotations

import logging
import time

from flask import (Blueprint, abort, current_app, redirect, render_template,
                   request, session, url_for)

import auth
import vouchers
from connection_log import log_connection

logger = logging.getLogger("wifi_portal.vouchers")

STAFF_SESSION_KEY = "staff_email"
STAFF_SESSION_EXP = "staff_expires"


def build_voucher_blueprint(config, store, voucher_store, identity, unifi, policy):
    bp = Blueprint("vouchers", __name__)

    def _enabled_or_404():
        if not config.VOUCHERS_ENABLED:
            abort(404)

    # ------------------------------------------------------------- guest side

    def _buckets(mac: str) -> list[str]:
        """Rate-limit keys. Both, because either alone is weak: a MAC is
        trivially spoofable, and a source address is shared behind NAT."""
        out = []
        if mac:
            out.append(f"mac:{mac.strip().casefold()}")
        if request.remote_addr:
            out.append(f"ip:{request.remote_addr}")
        return out

    def _locked_out(mac: str) -> bool:
        for b in _buckets(mac):
            n = voucher_store.recent_attempts(b, config.VOUCHER_ATTEMPT_WINDOW)
            if n >= config.VOUCHER_MAX_ATTEMPTS:
                logger.warning("voucher lockout: %s has %d attempts in %ds",
                               b, n, config.VOUCHER_ATTEMPT_WINDOW)
                return True
        return False

    def _fail(token: str, mac: str, reason: str, message: str, status: int = 400,
              count_attempt: bool = True):
        """Re-render the form with the binding token intact.

        The token is deliberately NOT consumed on failure: a guest who mistypes
        must be able to try again, and the MAC binding lives in that row. Rate
        limiting is what bounds retries, not destroying the binding.
        """
        if count_attempt:
            for b in _buckets(mac):
                voucher_store.record_attempt(b)
        logger.warning("voucher rejected mac=%s ip=%s: %s",
                       mac or "<unbound>", request.remote_addr, reason)
        return render_template("guest_code.html", token=token, error=message), status

    @bp.route("/guest", methods=["GET"])
    def guest_form():
        _enabled_or_404()
        # The MAC arrives from the controller's redirect and is bound to a
        # server-side row here. The form carries only an opaque token, so a
        # tampered field cannot authorize somebody else's device - the same
        # protection /login gives the OAuth flow.
        mac = request.args.get("mac") or request.args.get("id", "")
        ssid = request.args.get("ssid", "")
        next_url = request.args.get("url", "")
        store.cleanup_expired()
        voucher_store.purge_attempts()
        token = store.create_session(mac, ssid, config.SESSION_TTL_SECONDS,
                                     next_url=next_url, purpose="guest")
        return render_template("guest_code.html", token=token, error=None)

    @bp.route("/guest", methods=["POST"])
    def guest_redeem():
        _enabled_or_404()
        token = (request.form.get("token") or "").strip()
        row = store.read_session(token) if token else None
        if row is None:
            # Expired or forged. There is no MAC to rate-limit against, and
            # nothing to authorize.
            logger.warning("voucher post with no valid binding token from ip=%s",
                           request.remote_addr)
            return render_template(
                "error.html",
                message="This page expired. Reconnect to the WiFi and try again."
            ), 403

        mac = (row["mac"] or "").strip()
        ssid = row["ssid"] or "-"
        next_url = row["next_url"] or ""
        code = vouchers.normalise_code(request.form.get("code") or "")

        if not mac:
            return _fail(token, mac, "binding has no mac",
                         "Could not identify your device. Reconnect to the WiFi "
                         "and try again.")
        if not code:
            # Fumbling the form is not a guess; counting it would let a guest
            # lock themselves out without ever entering a wrong code.
            return _fail(token, mac, "empty code",
                         "Enter the code from your slip.", count_attempt=False)

        # Checked BEFORE any lookup, so a locked-out client cannot use the
        # response to learn whether a code exists.
        if _locked_out(mac):
            return _fail(token, mac, "rate limited",
                         "Too many incorrect codes. Wait 15 minutes and try again.",
                         429)

        match = next((v for v in unifi.list_vouchers()
                      if str(v.get("code", "")).strip() == code), None)
        if match is None:
            return _fail(token, mac, "unknown code", "That code was not recognised.")

        klass = vouchers.classify(match.get("note"))
        if klass is None:
            # A voucher with no recognised prefix is not redeemable. This is what
            # keeps the ten pre-2026 dash_script vouchers inert.
            return _fail(token, mac,
                         f"voucher {code} has unclassified note {match.get('note')!r}",
                         "That code is not valid for guest access. Ask the "
                         "front office for a new one.")

        spec = vouchers.CLASSES[klass]
        now = int(time.time())
        use = voucher_store.begin_or_get(code, klass,
                                         vouchers.expiry_for(klass, now))
        if now >= use["expires"]:
            return _fail(token, mac, f"voucher {code} expired at {use['expires']}",
                         "That code has expired. Ask the front office for a new one.")

        minutes = vouchers.remaining_minutes(use["expires"], now)
        if not unifi.authorize_guest(mac, minutes, down_kbps=spec.down_kbps,
                                     up_kbps=spec.up_kbps):
            logger.error("authorize_guest failed for mac=%s via voucher %s", mac, code)
            return render_template(
                "error.html",
                message="Could not connect your device. Please tell the front office."
            ), 502

        store.consume_session(token)          # binding spent only on success
        voucher_store.record_device(code, mac)
        for b in _buckets(mac):
            voucher_store.clear_attempts(b)
        log_connection(f"voucher:{code}", mac, ssid,
                       f"{klass}/{match.get('note')}", "AUTHORIZED")
        logger.info("voucher %s (%s) authorized mac=%s for %d minutes",
                    code, klass, mac, minutes)
        return render_template("success.html", email=spec.label,
                               next_url=next_url if next_url.startswith("http") else "")

    # ------------------------------------------------------------- staff side

    def _staff_email() -> str | None:
        if session.get(STAFF_SESSION_EXP, 0) < time.time():
            return None
        return session.get(STAFF_SESSION_KEY)

    @bp.route("/staff/vouchers", methods=["GET"])
    def staff_page():
        _enabled_or_404()
        email = _staff_email()
        if not email:
            state = store.create_session("-", "-", config.SESSION_TTL_SECONDS,
                                         next_url=None, purpose="staff")
            flow = auth.build_flow(config, config.OAUTH_REDIRECT_URI)
            return redirect(auth.get_authorization_url(flow, state,
                                                       config.HOSTED_DOMAIN))
        mine = [v for v in unifi.list_vouchers()
                if vouchers.classify(v.get("note")) is not None]
        for v in mine:
            use = voucher_store.get_use(str(v.get("code")))
            v["_class"] = vouchers.classify(v.get("note"))
            v["_devices"] = voucher_store.device_count(str(v.get("code")))
            v["_expires"] = use["expires"] if use else None
            v["_used"] = bool(use)
        just_made = [c for c in (request.args.get("created") or "").split(",") if c]
        return render_template("staff_vouchers.html", email=email, vouchers=mine,
                               classes=vouchers.CLASSES, error=None,
                               created={"codes": just_made, "class": "", "label": ""}
                               if just_made else None)

    @bp.route("/staff/vouchers", methods=["POST"])
    def staff_create():
        _enabled_or_404()
        email = _staff_email()
        if not email:
            abort(403)
        klass = (request.form.get("class") or "").strip().casefold()
        if klass not in vouchers.CLASSES:
            abort(400, "unknown code type")
        label = (request.form.get("label") or "").strip()[:60]
        spec = vouchers.CLASSES[klass]
        prefix = "GUEST -" if klass == vouchers.GUEST else "FILTER -"
        note = f"{prefix} {label} (by {email})".strip()

        # UniFi's own duration is not what governs access - this app computes
        # expiry at redemption (see vouchers.expiry_for). A generous value is
        # passed so the controller never expires a code out from under us.
        codes = unifi.create_voucher(note=note, minutes=525600, quota=0,
                                     down_kbps=spec.down_kbps,
                                     up_kbps=spec.up_kbps)
        if not codes:
            logger.error("voucher creation failed for %s by %s", klass, email)
            return render_template("staff_vouchers.html", email=email,
                                   vouchers=[], classes=vouchers.CLASSES,
                                   error="Could not create the code. Try again.",
                                   created=None), 502
        logger.info("voucher(s) %s created class=%s by %s", codes, klass, email)
        log_connection(email, "-", "-", f"issued {klass}", f"VOUCHER {codes[0]}")
        # Redirect rather than render: refreshing a rendered POST would mint
        # another code, and the codes are shown in the list anyway.
        return redirect(url_for("vouchers.staff_page", created=",".join(codes)))

    @bp.route("/staff/logout")
    def staff_logout():
        session.pop(STAFF_SESSION_KEY, None)
        session.pop(STAFF_SESSION_EXP, None)
        return redirect(url_for("vouchers.staff_page"))

    return bp
