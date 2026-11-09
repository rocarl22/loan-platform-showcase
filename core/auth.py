"""Password hashing, password policy and lockout - pure functions, no UI, no DB.

Hash format (new):  pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>
It is self-describing, so the iteration count can be raised later and old
hashes are upgraded at next login. Legacy hashes from the old apps (separate
salt column, 200k-round PBKDF2 or single-round SHA256) still verify and are
flagged for upgrade.
"""
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta

ITERATIONS = 600_000            # OWASP 2023 guidance for PBKDF2-HMAC-SHA256
LEGACY_ITERATIONS = 200_000
MIN_PASSWORD_LEN = 8
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_MINUTES = 15
_SCHEME = "pbkdf2_sha256"
_COMMON = {"admin123", "password", "password123", "12345678", "123456789",
           "qwerty123", "11111111", "iloveyou", "letmein1", "welcome1",
           "changeme", "rojam123"}
_TS = "%Y-%m-%d %H:%M:%S"


def hash_password(password: str, iterations: int = ITERATIONS) -> str:
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", (password or "").encode(), salt.encode(),
                             iterations).hex()
    return f"{_SCHEME}${iterations}${salt}${dk}"


def verify_password(password: str, stored: str, legacy_salt: str = "",
                    iterations: int = ITERATIONS) -> tuple[bool, bool]:
    """-> (ok, needs_upgrade). Timing-safe. `legacy_salt` is the old users.salt
    column, only needed to check hashes made by the previous apps."""
    password = password or ""
    stored = stored or ""
    if stored.startswith("legacy$"):            # written by legacy_import
        try:
            _, legacy_salt, stored = stored.split("$", 2)
        except ValueError:
            return False, False
    if stored.startswith(_SCHEME + "$"):
        try:
            _, it, salt, want = stored.split("$", 3)
            it = int(it)
        except ValueError:
            return False, False
        got = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), it).hex()
        return hmac.compare_digest(got, want), (it < iterations)
    # legacy 1: PBKDF2 200k with separate salt
    got = hashlib.pbkdf2_hmac("sha256", password.encode(), legacy_salt.encode(),
                              LEGACY_ITERATIONS).hex()
    if hmac.compare_digest(got, stored):
        return True, True
    # legacy 2: single-round SHA256(salt + password)
    old = hashlib.sha256((legacy_salt + password).encode()).hexdigest()
    if hmac.compare_digest(old, stored):
        return True, True
    return False, False


def password_ok(pw: str) -> tuple[bool, str]:
    pw = pw or ""
    if len(pw) < MIN_PASSWORD_LEN:
        return False, f"Password must be at least {MIN_PASSWORD_LEN} characters."
    if pw.strip().lower() in _COMMON:
        return False, "That password is too common - choose a less guessable one."
    if len(set(pw)) < 4:
        return False, "Password is too repetitive."
    return True, ""


def is_locked(locked_until: str, now: datetime) -> tuple[bool, str]:
    lu = (locked_until or "").strip()
    if not lu:
        return False, ""
    try:
        until = datetime.strptime(lu, _TS)
    except ValueError:
        return False, ""
    if now < until:
        left = int((until - now).total_seconds() // 60) + 1
        return True, f"Too many failed attempts - try again in ~{left} min."
    return False, ""


def register_failure(failed_attempts: int, now: datetime) -> tuple[int, str]:
    """-> (new_attempt_count, locked_until or ''). Lock when the limit is hit."""
    n = (failed_attempts or 0) + 1
    if n >= MAX_LOGIN_ATTEMPTS:
        return n, (now + timedelta(minutes=LOCKOUT_MINUTES)).strftime(_TS)
    return n, ""


def new_session_token() -> str:
    return secrets.token_urlsafe(32)
