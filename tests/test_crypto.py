import io
import os
import re
import tempfile
import unittest

from core import crypto as X

LOG2N = 10      # cheap scrypt for tests


def kit():
    rk = X.generate_recovery_key(); kdf = X.new_kdf_params(LOG2N)
    return rk, kdf, X.derive_public(rk, kdf), X.derive_private(rk, kdf)


def seal(data, pub, chunk=1 << 20):
    out = io.BytesIO(); X.encrypt_stream(io.BytesIO(data), out, pub, chunk); return out.getvalue()


def unseal(blob, priv):
    out = io.BytesIO(); X.decrypt_stream(io.BytesIO(blob), out, priv); return out.getvalue()


class RecoveryKeyTests(unittest.TestCase):
    def test_format_and_uniqueness(self):
        k = X.generate_recovery_key()
        self.assertRegex(k, r"^([A-Z2-9]{5}-){4}[A-Z2-9]{5}$")
        self.assertNotRegex(k, r"[01OI]")
        self.assertEqual(len({X.generate_recovery_key() for _ in range(200)}), 200)

    def test_forgiving_input_but_catches_typos(self):
        k = X.generate_recovery_key()
        raw = k.replace("-", "")
        self.assertEqual(X.normalize_recovery_key(k.lower()), raw)
        self.assertEqual(X.normalize_recovery_key("  " + " ".join(raw[i:i+5] for i in range(0, 25, 5)) + " "), raw)
        for bad in ("", "short", raw[:-1], raw + "A", "0" * 25):
            with self.assertRaises(X.BadRecoveryKey): X.normalize_recovery_key(bad)
        # change any one character -> ALWAYS rejected (guaranteed by the checksum design, not luck)
        for i in range(25):
            other = next(c for c in X._ALPHABET if c != raw[i])
            with self.assertRaises(X.BadRecoveryKey, msg=i): X.normalize_recovery_key(raw[:i] + other + raw[i+1:])

    def test_swapped_neighbours_are_caught(self):
        import random
        rng = random.Random(3); missed = 0; total = 0
        for _ in range(300):
            raw = X.normalize_recovery_key(X.generate_recovery_key())
            i = rng.randrange(24)                                 # swap positions i, i+1 (body + check char)
            if raw[i] == raw[i + 1]:
                continue
            total += 1
            swapped = raw[:i] + raw[i + 1] + raw[i] + raw[i + 2:]
            try: X.normalize_recovery_key(swapped); missed += 1
            except X.BadRecoveryKey: pass
        self.assertLess(missed / total, 0.10)                     # only value-differs-by-16 pairs can slip through

    def test_same_key_and_salt_give_same_keys_and_different_salt_does_not(self):
        rk = X.generate_recovery_key(); kdf = X.new_kdf_params(LOG2N)
        self.assertEqual(X.derive_public(rk, kdf), X.derive_public(rk.lower(), kdf))
        self.assertNotEqual(X.derive_public(rk, kdf), X.derive_public(rk, X.new_kdf_params(LOG2N)))
        self.assertNotEqual(X.derive_public(rk, kdf), X.derive_public(X.generate_recovery_key(), kdf))


class RoundTripTests(unittest.TestCase):
    def test_round_trip_sizes_and_chunk_boundaries(self):
        rk, kdf, pub, priv = kit()
        for n in (0, 1, 15, 16, 4095, 4096, 4097, 8192, 20000):
            data = os.urandom(n)
            self.assertEqual(unseal(seal(data, pub, 4096), priv), data, n)

    def test_ciphertext_hides_content_and_differs_every_time(self):
        rk, kdf, pub, priv = kit()
        data = b"CLIENT: Jane Doe KSh 12,000 " * 200
        a, b = seal(data, pub), seal(data, pub)
        self.assertNotEqual(a, b)
        self.assertNotIn(b"Jane", a); self.assertNotIn(b"12,000", a)
        self.assertGreater(len(a), len(data))

    def test_wrong_key_is_refused(self):
        _, _, pub, priv = kit(); _, _, _, other = kit()
        blob = seal(b"secret", pub)
        with self.assertRaises(X.WrongKeyOrDamaged): unseal(blob, other)

    def test_any_flipped_byte_is_detected(self):
        _, _, pub, priv = kit()
        blob = seal(os.urandom(10_000), pub, 4096)
        for pos in (0, 5, 10, 40, 45, 60, 4100, len(blob) - 1):
            bad = bytearray(blob); bad[pos] ^= 1
            with self.assertRaises(X.WrongKeyOrDamaged, msg=pos): unseal(bytes(bad), priv)

    def test_truncation_reordering_and_duplication_are_detected(self):
        _, _, pub, priv = kit()
        data = os.urandom(3 * 4096 + 100)
        blob = seal(data, pub, 4096); hs = X._HEADER.size + 2; sl = 4096 + 16
        chunks = [blob[hs + i * sl: hs + (i + 1) * sl] for i in range((len(blob) - hs + sl - 1) // sl)]
        self.assertEqual(len(chunks), 4)
        head = blob[:hs]
        for name, parts in (("drop last", chunks[:-1]), ("drop first", chunks[1:]), ("swap", [chunks[1], chunks[0]] + chunks[2:]),
                            ("duplicate", chunks + [chunks[-1]]), ("repeat middle", chunks[:2] + [chunks[1]] + chunks[2:])):
            with self.assertRaises(X.WrongKeyOrDamaged, msg=name): unseal(head + b"".join(parts), priv)
        with self.assertRaises(X.WrongKeyOrDamaged): unseal(blob[:-1], priv)
        with self.assertRaises(X.WrongKeyOrDamaged): unseal(blob[:X._HEADER.size - 1], priv)
        with self.assertRaises(X.WrongKeyOrDamaged): unseal(b"", priv)
        with self.assertRaises(X.WrongKeyOrDamaged): unseal(b"not a backup file at all, really", priv)

    def test_header_tampering_is_detected(self):
        _, _, pub, priv = kit()
        blob = bytearray(seal(b"x" * 5000, pub, 4096))
        blob[38] ^= 0xFF            # nonce prefix
        with self.assertRaises(X.WrongKeyOrDamaged): unseal(bytes(blob), priv)

    def test_the_public_key_alone_cannot_decrypt(self):
        rk, kdf, pub, priv = kit()
        blob = seal(b"secret", pub)
        # an attacker who has the app, the database and the public key still has no private key
        fake = X.X25519PrivateKey.from_private_bytes(pub)      # the public bytes are not the private key
        with self.assertRaises(X.WrongKeyOrDamaged): unseal(blob, fake)

    def test_backup_carries_its_own_key_parameters(self):
        rk, kdf, pub, priv = kit()
        with tempfile.TemporaryDirectory() as d:
            src, enc, out = (os.path.join(d, n) for n in ("a.bin", "a.enc", "a.out"))
            open(src, "wb").write(b"payload" * 1000)
            X.encrypt_file(src, enc, pub, 4096, kdf=kdf)
            self.assertEqual(X.read_kdf(enc), kdf)
            X.decrypt_file_with_recovery_key(enc, out, rk.lower())              # key + file is all you need
            self.assertEqual(open(out, "rb").read(), b"payload" * 1000)
            with self.assertRaises(X.BadRecoveryKey): X.decrypt_file_with_recovery_key(enc, out, rk[:-1])
            with self.assertRaises(X.WrongKeyOrDamaged): X.decrypt_file_with_recovery_key(enc, out, X.generate_recovery_key())
            # the key parameters are authenticated: swapping them breaks decryption
            blob = bytearray(open(enc, "rb").read()); blob[X._HEADER.size + 2 + 3] ^= 1
            open(enc, "wb").write(bytes(blob))
            with self.assertRaises(X.WrongKeyOrDamaged): X.decrypt_file_with_recovery_key(enc, out, rk)

    def test_damaged_key_text_in_header_is_always_a_clean_error(self):
        rk, kdf, pub, priv = kit()
        with tempfile.TemporaryDirectory() as d:
            src, enc, out = (os.path.join(d, n) for n in ("a.bin", "a.enc", "a.out"))
            open(src, "wb").write(b"x" * 100); X.encrypt_file(src, enc, pub, 4096, kdf=kdf)
            good = open(enc, "rb").read(); at = X._HEADER.size + 2 + 3
            for ch in (b"g", b"Z", b"-", b" "):                       # characters that are not hex digits
                blob = bytearray(good); blob[at] = ch[0]; open(enc, "wb").write(bytes(blob))
                with self.assertRaises(X.WrongKeyOrDamaged): X.decrypt_file_with_recovery_key(enc, out, rk)

    def test_file_helpers_and_permissions(self):
        _, _, pub, priv = kit()
        with tempfile.TemporaryDirectory() as d:
            src, enc, out = (os.path.join(d, n) for n in ("a.bin", "a.enc", "a.out"))
            data = os.urandom(50_000); open(src, "wb").write(data)
            X.encrypt_file(src, enc, pub, 4096); X.decrypt_file(enc, out, priv)
            self.assertEqual(open(out, "rb").read(), data)
            if os.name == "posix":
                self.assertEqual(oct(os.stat(enc).st_mode & 0o777), "0o600")
            bad = os.path.join(d, "b.enc"); open(bad, "wb").write(open(enc, "rb").read()[:-3])
            with self.assertRaises(X.WrongKeyOrDamaged): X.decrypt_file(bad, os.path.join(d, "b.out"), priv)
            self.assertFalse(os.path.exists(os.path.join(d, "b.out")))       # no half-decrypted leftovers


if __name__ == "__main__":
    unittest.main()
