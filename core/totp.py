"""Two-step sign-in with an authenticator app (RFC 6238 time codes, the kind Google Authenticator, Microsoft
Authenticator and Authy all read). Standard library only. Recovery codes are one-time and stored only as hashes."""
import base64
import hashlib
import hmac
import secrets
import struct
from urllib.parse import quote

STEP, DIGITS, WINDOW = 30, 6, 1                       # a code is accepted for the previous, current and next 30 seconds


def new_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _key(secret: str) -> bytes:
    s = "".join((secret or "").split()).upper()
    return base64.b32decode(s + "=" * (-len(s) % 8))


def code_at(secret: str, counter: int) -> str:
    h = hmac.new(_key(secret), struct.pack(">Q", counter), hashlib.sha1).digest()
    o = h[-1] & 15
    return str((struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % 10 ** DIGITS).zfill(DIGITS)


def verify(secret: str, code: str, now_ts: float, last_used: int = 0):
    """-> the time-step that matched (store it so the same code cannot be used twice), or None."""
    code = "".join((code or "").split())
    if not (len(code) == DIGITS and code.isdigit()) or not secret:
        return None
    base = int(now_ts // STEP)
    for step in range(base - WINDOW, base + WINDOW + 1):
        if step > last_used and hmac.compare_digest(code_at(secret, step), code):
            return step
    return None


def uri(secret: str, account: str, issuer: str) -> str:
    return f"otpauth://totp/{quote(issuer)}:{quote(account)}?secret={secret}&issuer={quote(issuer)}&digits={DIGITS}&period={STEP}"


def spaced(secret: str) -> str:
    return " ".join(secret[i:i + 4] for i in range(0, len(secret), 4))


def new_recovery_codes(n: int = 8) -> list[str]:
    return [f"{secrets.token_hex(2)}-{secrets.token_hex(2)}-{secrets.token_hex(2)}" for _ in range(n)]


def hash_code(code: str) -> str:
    return hashlib.sha256(("".join((code or "").split()).lower()).encode()).hexdigest()
