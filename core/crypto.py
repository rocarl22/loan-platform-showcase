"""Write-only encrypted backups.

Idea: the app can CREATE encrypted backups at any time, but cannot READ them back. Only
someone holding the RECOVERY KEY can. So a stolen laptop, a copied backup or a hacked server
reveals nothing, and the app never has to store a secret that decrypts history.

  recovery key  --scrypt(salt)-->  X25519 private key  -->  public key (stored in the database)
  each backup:  fresh ephemeral X25519 key; shared secret with the public key -> HKDF -> AES-256 key
  data:         split in chunks, each sealed with AES-GCM; the header and a 'last chunk' flag are
                authenticated, so tampering, reordering and truncation are all detected.

Only standard, reviewed primitives from the `cryptography` package are used; nothing is invented.
"""
import os
import secrets
import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"WSB1"
VERSION = 1
CHUNK = 1 << 20                       # 1 MiB
DEFAULT_LOG2N = 15                    # scrypt cost (about 32 MiB, ~0.1 s); tests use a lower value
_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"      # no 0/O/1/I - nothing to misread
_HEADER = struct.Struct(">4sB32s4sI")  # magic, version, ephemeral public key, nonce prefix, chunk size


class CryptoError(Exception):
    pass


class WrongKeyOrDamaged(CryptoError):
    """Wrong recovery key, or the file was damaged or altered."""


class BadRecoveryKey(CryptoError):
    """The typed recovery key has a typo (checksum does not match)."""


# ------------------------------------------------------------------ recovery key
def _check_char(body: str) -> str:
    """Weighted sum mod 32 with odd (so invertible) weights: ANY single mistyped character is always
    caught, and so are nearly all swapped neighbours. (A hash byte would miss 1 typo in 32.)"""
    total = sum((2 * i + 1) * _ALPHABET.index(ch) for i, ch in enumerate(body))
    return _ALPHABET[(-total) % 32]


def generate_recovery_key() -> str:
    """24 random characters (120 bits) + 1 check character, shown as XXXXX-XXXXX-XXXXX-XXXXX-XXXXX."""
    body = "".join(secrets.choice(_ALPHABET) for _ in range(24))
    raw = body + _check_char(body)
    return "-".join(raw[i:i + 5] for i in range(0, 25, 5))


def normalize_recovery_key(text: str) -> str:
    """Accept lower case, spaces and dashes. Raises BadRecoveryKey on a typo."""
    raw = "".join(ch for ch in (text or "").upper() if ch.isalnum())
    if len(raw) != 25 or any(ch not in _ALPHABET for ch in raw) or _check_char(raw[:24]) != raw[24]:
        raise BadRecoveryKey("That recovery key does not look right. Check each group of five characters.")
    return raw


def _private_from_recovery(recovery_key: str, salt: bytes, log2n: int) -> X25519PrivateKey:
    seed = Scrypt(salt=salt, length=32, n=2 ** log2n, r=8, p=1).derive(normalize_recovery_key(recovery_key).encode())
    return X25519PrivateKey.from_private_bytes(seed)


def public_bytes(priv: X25519PrivateKey) -> bytes:
    return priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def new_kdf_params(log2n: int = DEFAULT_LOG2N) -> str:
    """Stored next to the public key so the same recovery key re-derives the same private key."""
    return f"{log2n}:{secrets.token_hex(16)}"


def derive_public(recovery_key: str, kdf: str) -> bytes:
    log2n, salt = kdf.split(":")
    return public_bytes(_private_from_recovery(recovery_key, bytes.fromhex(salt), int(log2n)))


def derive_private(recovery_key: str, kdf: str) -> X25519PrivateKey:
    log2n, salt = kdf.split(":")
    return _private_from_recovery(recovery_key, bytes.fromhex(salt), int(log2n))


# ------------------------------------------------------------------ file encryption
def _aes_key(shared: bytes, eph_pub: bytes, recipient_pub: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=eph_pub + recipient_pub,
                info=b"wsbackup-v1").derive(shared)


def _nonce(prefix: bytes, index: int) -> bytes:
    return prefix + index.to_bytes(8, "big")


def _read_header(src):
    """-> (header_bytes, eph_pub, nonce_prefix, chunk_size, kdf). The key-derivation parameters (a public
    salt) travel inside every backup, so a backup plus the recovery key is enough to restore even if
    the database that created it is gone."""
    head = src.read(_HEADER.size)
    if len(head) != _HEADER.size:
        raise WrongKeyOrDamaged("Not a backup file, or it is cut short.")
    magic, ver, eph_pub, prefix, chunk_size = _HEADER.unpack(head)
    if magic != MAGIC or ver != VERSION or not (1 <= chunk_size <= 64 * CHUNK):
        raise WrongKeyOrDamaged("Not a backup file, or it is cut short.")
    ln = src.read(2)
    kdf = src.read(struct.unpack(">H", ln)[0]) if len(ln) == 2 else b""
    if len(ln) != 2 or len(kdf) != struct.unpack(">H", ln)[0]:
        raise WrongKeyOrDamaged("Not a backup file, or it is cut short.")
    return head + ln + kdf, eph_pub, prefix, chunk_size, kdf.decode("ascii", "replace")


def read_kdf(path: str) -> str:
    with open(path, "rb") as f:
        return _read_header(f)[4]


def encrypt_stream(src, dst, recipient_pub: bytes, chunk_size: int = CHUNK, kdf: str = "") -> None:
    """Needs only the PUBLIC key. Reads `src` to the end, writes the sealed stream to `dst`."""
    eph = X25519PrivateKey.generate()
    eph_pub = public_bytes(eph)
    key = AESGCM(_aes_key(eph.exchange(X25519PublicKey.from_public_bytes(recipient_pub)), eph_pub, recipient_pub))
    prefix = secrets.token_bytes(4)
    kb = kdf.encode("ascii")
    header = _HEADER.pack(MAGIC, VERSION, eph_pub, prefix, chunk_size) + struct.pack(">H", len(kb)) + kb
    dst.write(header)
    cur = src.read(chunk_size)
    i = 0
    while True:
        nxt = src.read(chunk_size)
        last = not nxt
        dst.write(key.encrypt(_nonce(prefix, i), cur, header + (b"\x01" if last else b"\x00")))
        if last:
            return
        cur, i = nxt, i + 1


def decrypt_stream(src, dst, private: X25519PrivateKey) -> None:
    head, eph_pub, prefix, chunk_size, _kdf = _read_header(src)
    key = AESGCM(_aes_key(private.exchange(X25519PublicKey.from_public_bytes(eph_pub)), eph_pub, public_bytes(private)))
    sealed = chunk_size + 16
    cur = src.read(sealed)
    i = 0
    while True:
        nxt = src.read(sealed)
        last = not nxt
        try:
            dst.write(key.decrypt(_nonce(prefix, i), cur, head + (b"\x01" if last else b"\x00")))
        except InvalidTag:
            raise WrongKeyOrDamaged("Wrong recovery key, or the backup file is damaged or has been altered.") from None
        if last:
            return
        cur, i = nxt, i + 1


def encrypt_file(src_path: str, dst_path: str, recipient_pub: bytes, chunk_size: int = CHUNK, kdf: str = "") -> None:
    fd = os.open(dst_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with open(src_path, "rb") as s, os.fdopen(fd, "wb") as d:
        encrypt_stream(s, d, recipient_pub, chunk_size, kdf)
        d.flush(); os.fsync(d.fileno())


def decrypt_file(src_path: str, dst_path: str, private: X25519PrivateKey) -> None:
    fd = os.open(dst_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with open(src_path, "rb") as s, os.fdopen(fd, "wb") as d:
            decrypt_stream(s, d, private)
    except Exception:
        try:
            os.remove(dst_path)          # never leave half-decrypted data behind
        except OSError:
            pass
        raise


def decrypt_file_with_recovery_key(src_path: str, dst_path: str, recovery_key: str) -> None:
    """The disaster-recovery path: needs only the backup file and the recovery key."""
    normalize_recovery_key(recovery_key)                      # typo check first, with a clear message
    kdf = read_kdf(src_path)
    if ":" not in kdf:
        raise WrongKeyOrDamaged("This backup does not carry key information. Use the original database's settings.")
    try:
        priv = derive_private(recovery_key, kdf)
    except (ValueError, TypeError):                           # damaged/altered header text
        raise WrongKeyOrDamaged("The backup's key information is damaged.") from None
    decrypt_file(src_path, dst_path, priv)
