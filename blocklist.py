import os


def load_blocklist(path: str) -> set[str]:
    """Format: one email per line, '#' comments, blank lines ignored."""
    if not path or not os.path.exists(path):
        return set()
    emails = set()
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            emails.add(line.lower())
    return emails


def is_blocked(email: str, path: str) -> bool:
    return email.lower() in load_blocklist(path)
