"""Guest access-code policy: which codes exist, what class they are, when they die.

Two classes, distinguished by a prefix in the voucher's `note` field on the
controller:

  GUEST -  <text>    a visiting family or tour. Unlimited devices, one day from
                     first use, rate-limited to spare student bandwidth.
  FILTER - <text>    a student whose content filter (Covenant Eyes, NetNanny,
                     Bark) fails closed during the pre-authorization window and
                     therefore cannot complete Google sign-in. Unlimited
                     devices, expires at the end of the school year, uncapped.

Why a prefix rather than a separate store
-----------------------------------------
The controller is the registry - staff create vouchers there and the `note`
already records who issued it. A prefix keeps class alongside the code without a
second system to keep in sync.

It also fails safe against history: older vouchers left on a controller (for
example ones with `quota=0` and notes that are bare email addresses) carry no
recognised prefix, so `classify()` returns None and they cannot be redeemed.
Enabling code login does not silently turn forgotten codes into live keys.

Why this module computes expiry rather than trusting UniFi's `duration`
----------------------------------------------------------------------
UniFi's voucher `duration` is ambiguous - every existing voucher reads 259200,
which is either 3 days (seconds) or 180 days (minutes), and the unit has not been
confirmed on this controller. Under `auth=custom` UniFi does not enforce it
anyway. Duration policy therefore lives here, in version control, where a
mis-set field in the console cannot accidentally grant six months.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, time as dtime, timezone


GUEST = "guest"
FILTER = "filter"

PREFIXES = {
    "GUEST -": GUEST,
    "GUEST-": GUEST,
    "FILTER -": FILTER,
    "FILTER-": FILTER,
}


@dataclass(frozen=True)
class VoucherClass:
    name: str
    # Rolling window from first use, in minutes. None means "use school_year_end".
    minutes: int | None
    # Bandwidth ceiling handed to authorize-guest, in kbps. None means uncapped.
    down_kbps: int | None
    up_kbps: int | None
    label: str


CLASSES = {
    GUEST: VoucherClass(
        name=GUEST,
        minutes=1440,                 # one day from first use
        # Mirrors the caps the previous dash_script vouchers carried, so a tour
        # group cannot crowd out students.
        down_kbps=10000,
        up_kbps=5000,
        label="Guest",
    ),
    FILTER: VoucherClass(
        name=FILTER,
        minutes=None,                 # absolute: end of the school year
        down_kbps=None,
        up_kbps=None,
        label="Filtered device",
    ),
}


def classify(note: str | None) -> str | None:
    """Map a voucher note to a class, or None if it carries no known prefix.

    Deliberately strict: an unrecognised note is not redeemable. That is what
    keeps the pre-existing 2025 vouchers inert.
    """
    if not note:
        return None
    n = note.strip()
    for prefix, klass in PREFIXES.items():
        if n.upper().startswith(prefix):
            return klass
    return None


def school_year_end(now: datetime | None = None) -> int:
    """Epoch seconds for the next 30 June, 23:59:59 UTC.

    A rolling ten months would drift: a code issued in January would run to
    November, straight through the summer. Anchoring to 30 June means a code
    issued in September lasts the school year and one issued in May lasts weeks,
    and the whole set clears itself out annually without anyone remembering to.
    """
    now = now or datetime.now(timezone.utc)
    year = now.year if (now.month, now.day) < (6, 30) else now.year + 1
    return int(datetime.combine(date(year, 6, 30), dtime(23, 59, 59),
                                tzinfo=timezone.utc).timestamp())


def expiry_for(klass: str, first_used: int, now: datetime | None = None) -> int:
    """Absolute epoch expiry for a class, given when the code was first used."""
    spec = CLASSES[klass]
    if spec.minutes is not None:
        return int(first_used) + spec.minutes * 60
    return school_year_end(now)


def remaining_minutes(expires_at: int, now_epoch: int | None = None) -> int:
    """Minutes to hand to authorize-guest.

    Must be the time REMAINING, not the full window. A device joining a guest
    code eighteen hours after it was first used should get six hours, not another
    twenty-four - otherwise each new device silently extends the code.
    """
    import time as _time

    now = int(now_epoch if now_epoch is not None else _time.time())
    return max(1, (int(expires_at) - now + 59) // 60)


def normalise_code(raw: str) -> str:
    """Strip the formatting people naturally type: spaces and dashes.

    UniFi shows codes as e.g. 04885-65485; guests read them off a slip and type
    them with or without the separator.
    """
    return "".join(ch for ch in (raw or "") if ch.isalnum())
