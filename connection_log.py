import logging

logger = logging.getLogger("wifi_portal.connections")


def configure_connection_logger(log_path: str) -> None:
    """Safe to call repeatedly (e.g. once per create_app in tests) - replaces
    any prior handler instead of stacking duplicate file handles."""
    for old_handler in logger.handlers[:]:
        logger.removeHandler(old_handler)
        old_handler.close()
    handler = logging.FileHandler(log_path)
    handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


def log_connection(email: str, mac: str, ssid: str, ou: str, result: str) -> None:
    logger.info("email=%s mac=%s ssid=%s ou=%s result=%s", email, mac, ssid, ou, result)
