"""Authenticated file encryption for backups (and any other file that must stay private).

Format (all integers big-endian):

  magic "VLT1" | mode(1) | log2N(1) r(1) p(1) | salt(16) | chunk_log2(1) | nonce_prefix(8)    = header
  then one or more chunks, each  AES-256-GCM( plaintext_chunk )  =  ciphertext || 16-byte tag

  * mode 0 = the caller supplies a raw 32-byte key; mode 1 = key derived from a passphrase with scrypt
  * every chunk's nonce is  nonce_prefix || chunk_counter(4)  - never reused with a key
  * every chunk is authenticated with the WHOLE header + its counter + a "last chunk" flag as
    additional data, so any of these is detected, not silently accepted:
      - a flipped bit anywhere (header or data)
      - chunks removed, duplicated or reordered
      - the file cut short (the final chunk must carry the "last" flag)
      - changed key-derivation settings
  * a wrong passphrase and a damaged file look the same on purpose (DecryptionError)

Output is written to a temporary file and renamed into place only after it is complete, with
owner-only permissions, so a crash never leaves a half-written file under the real name.
"""
import hashlib
import os
import secrets
import struct
import tempfile

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"VLT1"
MODE_RAW, MODE_PASSPHRASE = 0, 1
_HEADER = struct.Struct(">4sBBBB16sB8s")            # magic, mode, log2N, r, p, salt(16), chunk_log2, nonce_prefix(8)
HEADER_LEN = _HEADER.size
TAG = 16
DEFAULT_SCRYPT = (17, 8, 1)                          # N=2^17 (128 MiB), r=8, p=1  (about 0.6 s)
DEFAULT_CHUNK_LOG2 = 16                              # 64 KiB chunks


class DecryptionError(Exception):
    """Wrong passphrase/key, or the file was damaged or tampered with."""


class NotAVaultFile(DecryptionError):
    pass


def derive_key(passphrase: str, salt: bytes, log2n: int, r: int, p: int) -> bytes:
    if not passphrase:
        raise ValueError("passphrase must not be empty")
    n = 1 << log2n
    return hashlib.scrypt(passphrase.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=32,
                          maxmem=128 * n * r + 16 * 1024 * 1024)


def _nonce(prefix: bytes, counter: int) -> bytes:
    return prefix + struct.pack(">I", counter)


def _aad(header: bytes, counter: int, last: bool) -> bytes:
    return header + struct.pack(">QB", counter, 1 if last else 0)


def _key_for(secret, mode, salt, log2n, r, p) -> bytes:
    if mode == MODE_RAW:
        if not isinstance(secret, (bytes, bytearray)) or len(secret) != 32:
            raise DecryptionError("this file needs a 32-byte key, not a passphrase")
        return bytes(secret)
    if mode == MODE_PASSPHRASE:
        if not isinstance(secret, str):
            raise DecryptionError("this file needs a passphrase, not a raw key")
        return derive_key(secret, salt, log2n, r, p)
    raise DecryptionError("unknown encryption mode")


def _atomic_writer(dst: str):
    d = os.path.dirname(os.path.abspath(dst))
    fd, tmp = tempfile.mkstemp(prefix=".vault-", suffix=".tmp", dir=d)
    os.chmod(tmp, 0o600)
    return os.fdopen(fd, "wb"), tmp


def encrypt_file(src: str, dst: str, secret, *, scrypt=DEFAULT_SCRYPT, chunk_log2: int = DEFAULT_CHUNK_LOG2) -> None:
    """secret: 32-byte key (raw mode) or a passphrase string (scrypt mode)."""
    if isinstance(secret, str):
        mode, (log2n, r, p), salt = MODE_PASSPHRASE, scrypt, secrets.token_bytes(16)
    else:
        mode, (log2n, r, p), salt = MODE_RAW, (0, 0, 0), bytes(16)
    key = _key_for(secret, mode, salt, log2n, r, p)
    prefix = secrets.token_bytes(8)
    header = _HEADER.pack(MAGIC, mode, log2n, r, p, salt, chunk_log2, prefix)
    size, aes = 1 << chunk_log2, AESGCM(key)
    out, tmp = _atomic_writer(dst)
    try:
        with open(src, "rb") as f, out:
            out.write(header)
            counter, block = 0, f.read(size)
            while True:
                nxt = f.read(size) if len(block) == size else b""
                last = not nxt
                out.write(aes.encrypt(_nonce(prefix, counter), block, _aad(header, counter, last)))
                if last:
                    break
                counter, block = counter + 1, nxt
            out.flush(); os.fsync(out.fileno())
        os.replace(tmp, dst)
    except BaseException:
        try: os.unlink(tmp)
        except OSError: pass
        raise


def decrypt_file(src: str, dst: str, secret) -> None:
    out, tmp = _atomic_writer(dst)
    try:
        with open(src, "rb") as f, out:
            header = f.read(HEADER_LEN)
            if len(header) < HEADER_LEN:
                raise NotAVaultFile("not an encrypted file")
            magic, mode, log2n, r, p, salt, chunk_log2, prefix = _HEADER.unpack(header)
            if magic != MAGIC:
                raise NotAVaultFile("not an encrypted file")
            if not (10 <= chunk_log2 <= 24) or (mode == MODE_PASSPHRASE and not (10 <= log2n <= 22 and 1 <= r <= 16 and 1 <= p <= 4)):
                raise DecryptionError("unsupported or damaged file")       # also stops absurd-cost headers
            key = _key_for(secret, mode, salt, log2n, r, p)
            aes, ct_size = AESGCM(key), (1 << chunk_log2) + TAG
            counter, block, seen_last = 0, f.read(ct_size), False
            if not block:
                raise DecryptionError("wrong passphrase/key, or the file is damaged")
            while True:
                nxt = f.read(ct_size) if len(block) == ct_size else b""
                last = not nxt
                try:
                    out.write(aes.decrypt(_nonce(prefix, counter), block, _aad(header, counter, last)))
                except InvalidTag:
                    raise DecryptionError("wrong passphrase/key, or the file is damaged") from None
                if last:
                    break
                counter, block = counter + 1, nxt
            out.flush(); os.fsync(out.fileno())
        os.replace(tmp, dst)
    except BaseException:
        try: os.unlink(tmp)
        except OSError: pass
        raise


def is_vault_file(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(4) == MAGIC
    except OSError:
        return False
