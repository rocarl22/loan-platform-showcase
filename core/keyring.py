"""Key management: one random master key, wrapped (encrypted) twice.

  master key (32 random bytes, never written to disk in the clear)
     |- wrapped by a key derived from the admin's PASSPHRASE     (day-to-day unlock)
     '- wrapped by a key derived from a RECOVERY KEY             (printed once, kept offline)

Why this shape:
  * changing the passphrase re-wraps the master key; the database is NOT re-encrypted
  * a forgotten passphrase is recoverable with the recovery key; lose BOTH and the data is gone
    for good - that is the price of the data genuinely being unreadable to everyone else
  * the master key is never used directly: purpose-specific subkeys come from HKDF
    (database encryption, backup encryption), so one leaking does not expose the others

The keyring file holds only wrapped keys and derivation settings - useless without a secret.
"""
import base64
import json
import os
import secrets
import tempfile

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .vault import DEFAULT_SCRYPT, derive_key

VERSION = 1
MIN_PASSPHRASE_LEN = 10
_COMMON = {"password12", "1234567890", "qwertyuiop", "password123", "admin12345", "iloveyou12"}
PURPOSES = ("database", "backup")


class KeyringError(Exception):
    pass


class WrongSecret(KeyringError):
    """Wrong passphrase / recovery key, or the keyring file was altered."""


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _unb64(s: str) -> bytes:
    return base64.b64decode(s.encode())


def check_passphrase(p: str) -> None:
    if len(p or "") < MIN_PASSPHRASE_LEN:
        raise KeyringError(f"Use a passphrase of at least {MIN_PASSPHRASE_LEN} characters (a few random words works well).")
    if p.strip().lower() in _COMMON or len(set(p)) < 5:
        raise KeyringError("That passphrase is too easy to guess.")


def new_recovery_key() -> str:
    """160 random bits as 8 groups of 4 base32 characters: ABCD-EFGH-... (easy to write down)."""
    raw = base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")
    return "-".join(raw[i:i + 4] for i in range(0, len(raw), 4))


def _norm_recovery(rk: str) -> str:
    return "".join(ch for ch in (rk or "").upper() if ch.isalnum())


def _wrap(master: bytes, secret: str, label: str, scrypt) -> dict:
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
    kek = derive_key(secret, salt, *scrypt)
    ct = AESGCM(kek).encrypt(nonce, master, f"keyring-v{VERSION}|{label}".encode())
    return {"salt": _b64(salt), "nonce": _b64(nonce), "wrapped": _b64(ct), "scrypt": list(scrypt)}


def _unwrap(entry: dict, secret: str, label: str) -> bytes:
    if not secret:
        raise WrongSecret("Wrong passphrase or recovery key.")      # not "damaged": the file is fine
    try:
        n, r, p = entry["scrypt"]
        if not (10 <= n <= 22 and 1 <= r <= 16 and 1 <= p <= 4):
            raise KeyringError("unsupported keyring settings")
        kek = derive_key(secret, _unb64(entry["salt"]), n, r, p)
        return AESGCM(kek).decrypt(_unb64(entry["nonce"]), _unb64(entry["wrapped"]),
                                   f"keyring-v{VERSION}|{label}".encode())
    except InvalidTag:
        raise WrongSecret("Wrong passphrase or recovery key.") from None
    except (KeyError, ValueError, TypeError):
        raise KeyringError("The keyring file is damaged.") from None


def _save(path: str, data: dict) -> None:
    d = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(prefix=".keyring-", suffix=".tmp", dir=d)
    try:
        os.chmod(tmp, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=1)
            f.flush(); os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try: os.unlink(tmp)
        except OSError: pass
        raise


def _load(path: str) -> dict:
    try:
        with open(path) as f:
            data = json.load(f)
    except FileNotFoundError:
        raise KeyringError("No keyring found. Create one first.") from None
    except (ValueError, OSError):
        raise KeyringError("The keyring file is damaged.") from None
    if not isinstance(data, dict) or data.get("version") != VERSION or "passphrase" not in data or "recovery" not in data:
        raise KeyringError("The keyring file is damaged or from a newer version.")
    return data


def create(path: str, passphrase: str, scrypt=DEFAULT_SCRYPT) -> tuple[bytes, str]:
    """Make a new keyring. Returns (master_key, recovery_key) - show the recovery key ONCE."""
    if os.path.exists(path):
        raise KeyringError("A keyring already exists here; refusing to overwrite it.")
    check_passphrase(passphrase)
    master, recovery = secrets.token_bytes(32), new_recovery_key()
    _save(path, {"version": VERSION,
                 "passphrase": _wrap(master, passphrase, "passphrase", scrypt),
                 "recovery": _wrap(master, _norm_recovery(recovery), "recovery", scrypt)})
    return master, recovery


def unlock(path: str, passphrase: str) -> bytes:
    return _unwrap(_load(path)["passphrase"], passphrase or "", "passphrase")


def unlock_with_recovery(path: str, recovery_key: str) -> bytes:
    return _unwrap(_load(path)["recovery"], _norm_recovery(recovery_key), "recovery")


def change_passphrase(path: str, old_passphrase: str, new_passphrase: str, scrypt=DEFAULT_SCRYPT) -> None:
    """Re-wraps the SAME master key: nothing already encrypted needs touching."""
    master = unlock(path, old_passphrase)
    check_passphrase(new_passphrase)
    data = _load(path)
    data["passphrase"] = _wrap(master, new_passphrase, "passphrase", scrypt)
    _save(path, data)


def reset_passphrase_with_recovery(path: str, recovery_key: str, new_passphrase: str, scrypt=DEFAULT_SCRYPT) -> None:
    master = unlock_with_recovery(path, recovery_key)
    check_passphrase(new_passphrase)
    data = _load(path)
    data["passphrase"] = _wrap(master, new_passphrase, "passphrase", scrypt)
    _save(path, data)


def new_recovery(path: str, passphrase: str, scrypt=DEFAULT_SCRYPT) -> str:
    """Issue a fresh recovery key (the old one stops working). Returns the new one."""
    master = unlock(path, passphrase)
    recovery = new_recovery_key()
    data = _load(path)
    data["recovery"] = _wrap(master, _norm_recovery(recovery), "recovery", scrypt)
    _save(path, data)
    return recovery


def subkey(master: bytes, purpose: str) -> bytes:
    """32-byte key for one purpose only ('database', 'backup')."""
    if purpose not in PURPOSES:
        raise ValueError(f"unknown key purpose {purpose!r}")
    if len(master) != 32:
        raise ValueError("master key must be 32 bytes")
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=f"workspace-{purpose}-v1".encode()).derive(master)
