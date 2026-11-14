import logging
import os

from flask import Flask
from werkzeug.middleware.proxy_fix import ProxyFix

from config import Config
from connection_log import configure_connection_logger
from directory_client import build_identity_lookup
from policy import load_policy
from routes import build_routes_blueprint
from session_store import SessionStore
from unifi_client import build_unifi_client
from voucher_routes import build_voucher_blueprint
from voucher_store import VoucherStore


def create_app(config: Config, unifi_client=None, identity=None, policy=None) -> Flask:
    app = Flask(__name__)

    configure_connection_logger(config.CONNECTION_LOG_PATH)

    store = SessionStore(config.SESSION_DB_PATH)
    store.init_db()

    unifi = unifi_client or build_unifi_client(config)
    identity = identity or build_identity_lookup(config)
    policy = policy or load_policy(config.POLICY_FILE)

    if config.TRUST_PROXY_HOPS:
        # Without this, nginx terminating TLS means Flask sees a plain http://
        # request. request.url then reads "http://wifi.../callback" while the
        # registered redirect URI is https://, and oauthlib rejects the token
        # exchange as a redirect-URI mismatch (or refuses the insecure transport
        # outright). This bites on the very first real deployment behind nginx,
        # and the resulting error points nowhere near the cause.
        app.wsgi_app = ProxyFix(
            app.wsgi_app,
            x_for=config.TRUST_PROXY_HOPS,
            x_proto=config.TRUST_PROXY_HOPS,
            x_host=config.TRUST_PROXY_HOPS,
        )

    app.register_blueprint(build_routes_blueprint(config, store, identity, unifi, policy))

    if config.VOUCHERS_ENABLED:
        if not config.SECRET_KEY:
            # Without this Flask cannot sign the staff session cookie, and the
            # /staff/vouchers page would either 500 or - worse - be reachable
            # with an unsigned cookie. Fail at startup, not at first use.
            raise RuntimeError(
                "VOUCHERS_ENABLED=1 requires SECRET_KEY to be set; generate one "
                "with: python -c \"import secrets;print(secrets.token_urlsafe(48))\""
            )
        app.secret_key = config.SECRET_KEY
        app.config.update(
            SESSION_COOKIE_HTTPONLY=True,
            SESSION_COOKIE_SAMESITE="Lax",
            # The portal is reachable over plain http for captive-portal
            # detection, but the staff page is only ever used over https, so the
            # cookie is marked secure whenever a proxy is terminating TLS.
            SESSION_COOKIE_SECURE=bool(config.TRUST_PROXY_HOPS),
        )
        vstore = VoucherStore(config.VOUCHER_DB_PATH)
        vstore.init_db()
        app.register_blueprint(build_voucher_blueprint(
            config, store, vstore, identity, unifi, policy))

    return app


def create_application() -> Flask:
    """Entry point for a WSGI server:  gunicorn 'app:create_application()'

    Deliberately a function rather than a module-level `application = ...`.
    Building the app at import time meant that merely importing this module -
    which the unit tests do, to get create_app - required every production
    environment variable to be present, and failed with a bare KeyError if not.
    """
    from dotenv import load_dotenv

    load_dotenv()
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    return create_app(Config.from_env())


if __name__ == "__main__":
    app = create_application()
    ssl_cert = os.environ.get("SSL_CERT_FILE")
    ssl_key = os.environ.get("SSL_KEY_FILE")
    # debug is off unless asked for: the previous default of debug=True exposed
    # the Werkzeug interactive debugger, which is remote code execution to
    # anyone who can reach the port.
    app.run(
        host=os.environ.get("BIND_HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", "5000")),
        debug=os.environ.get("FLASK_DEBUG", "") == "1",
        ssl_context=(ssl_cert, ssl_key) if ssl_cert and ssl_key else None,
    )
