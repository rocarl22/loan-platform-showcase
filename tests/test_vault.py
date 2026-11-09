import os
import struct
import tempfile
import unittest

from core import vault

FAST = (10, 1, 1)          # cheap scrypt for tests
KEY = bytes(range(32))


class VaultTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory(); self.addCleanup(self.d.cleanup)

    def p(self, n): return os.path.join(self.d.name, n)

    def write(self, name, data):
        open(self.p(name), "wb").write(data); return self.p(name)

    def roundtrip(self, data, secret, **kw):
        src = self.write("in", data)
        vault.encrypt_file(src, self.p("enc"), secret, **kw)
        vault.decrypt_file(self.p("enc"), self.p("out"), secret)
        return open(self.p("out"), "rb").read()

    def test_roundtrip_sizes_including_chunk_boundaries(self):
        size = 1 << 10
        for n in (0, 1, size - 1, size, size + 1, 2 * size, 2 * size + 5, 40 * size + 17):
            data = os.urandom(n)
            self.assertEqual(self.roundtrip(data, KEY, chunk_log2=10), data, n)

    def test_passphrase_mode(self):
        data = os.urandom(5000)
        self.assertEqual(self.roundtrip(data, "correct horse battery", scrypt=FAST, chunk_log2=10), data)

    def test_output_hides_plaintext_and_is_randomised(self):
        marker = b"CLIENT-ID-12345678 JANE DOE 0700000000"
        src = self.write("in", marker * 500)
        vault.encrypt_file(src, self.p("a"), KEY); vault.encrypt_file(src, self.p("b"), KEY)
        a, b = open(self.p("a"), "rb").read(), open(self.p("b"), "rb").read()
        self.assertNotIn(b"JANE", a); self.assertNotIn(b"12345678", a)
        self.assertNotEqual(a, b)                                    # fresh nonce prefix every time
        self.assertTrue(a.startswith(b"VLT1")); self.assertTrue(vault.is_vault_file(self.p("a")))

    def test_wrong_secret_and_wrong_mode_fail_without_leaving_output(self):
        src = self.write("in", b"secret data" * 100)
        vault.encrypt_file(src, self.p("enc"), "right passphrase", scrypt=FAST)
        with self.assertRaises(vault.DecryptionError):
            vault.decrypt_file(self.p("enc"), self.p("out"), "wrong passphrase")
        with self.assertRaises(vault.DecryptionError):
            vault.decrypt_file(self.p("enc"), self.p("out"), KEY)             # raw key for a passphrase file
        self.assertFalse(os.path.exists(self.p("out")))
        self.assertEqual([f for f in os.listdir(self.d.name) if f.endswith(".tmp")], [])   # no stray temp files
        vault.encrypt_file(src, self.p("enc2"), KEY)
        with self.assertRaises(vault.DecryptionError):
            vault.decrypt_file(self.p("enc2"), self.p("out"), "a passphrase")
        with self.assertRaises(vault.DecryptionError):
            vault.decrypt_file(self.p("enc2"), self.p("out"), bytes(32))

    def test_every_single_byte_change_is_detected(self):
        src = self.write("in", os.urandom(3000))
        vault.encrypt_file(src, self.p("enc"), KEY, chunk_log2=10)
        good = open(self.p("enc"), "rb").read()
        for i in range(len(good)):
            bad = bytearray(good); bad[i] ^= 0x01
            open(self.p("bad"), "wb").write(bad)
            with self.assertRaises(vault.DecryptionError, msg=f"byte {i}"):
                vault.decrypt_file(self.p("bad"), self.p("out"), KEY)
        self.assertFalse(os.path.exists(self.p("out")))

    def test_truncation_reordering_and_duplication_are_detected(self):
        size = 1 << 10; ct = size + 16
        src = self.write("in", os.urandom(size * 4 + 100))
        vault.encrypt_file(src, self.p("enc"), KEY, chunk_log2=10)
        raw = open(self.p("enc"), "rb").read()
        head, body = raw[:vault.HEADER_LEN], raw[vault.HEADER_LEN:]
        chunks = [body[i:i + ct] for i in range(0, len(body), ct)]
        self.assertEqual(len(chunks), 5)
        cases = {
            "drop last chunk": head + b"".join(chunks[:-1]),
            "drop first chunk": head + b"".join(chunks[1:]),
            "drop a middle chunk": head + b"".join(chunks[:2] + chunks[3:]),
            "swap two chunks": head + b"".join([chunks[1], chunks[0]] + chunks[2:]),
            "duplicate a chunk": head + b"".join(chunks[:2] + [chunks[1]] + chunks[2:]),
            "cut mid-chunk": raw[:-20],
            "append garbage": raw + b"x" * 40,
            "header only": head,
        }
        for name, blob in cases.items():
            open(self.p("bad"), "wb").write(blob)
            with self.assertRaises(vault.DecryptionError, msg=name):
                vault.decrypt_file(self.p("bad"), self.p("out"), KEY)

    def test_not_a_vault_file(self):
        for blob in (b"", b"short", b"SQLite format 3\x00" + b"\0" * 100):
            with self.assertRaises(vault.NotAVaultFile):
                vault.decrypt_file(self.write("x", blob), self.p("out"), KEY)
        self.assertFalse(vault.is_vault_file(self.p("missing")))

    def test_absurd_cost_header_is_refused_before_any_work(self):
        src = self.write("in", b"x" * 10)
        vault.encrypt_file(src, self.p("enc"), "pw", scrypt=FAST)
        raw = bytearray(open(self.p("enc"), "rb").read()); raw[5] = 31              # log2N = 31 (a memory bomb)
        open(self.p("bad"), "wb").write(raw)
        with self.assertRaises(vault.DecryptionError):
            vault.decrypt_file(self.p("bad"), self.p("out"), "pw")

    def test_permissions_and_overwrite_safety(self):
        src = self.write("in", b"data")
        vault.encrypt_file(src, self.p("enc"), KEY)
        self.assertEqual(os.stat(self.p("enc")).st_mode & 0o777, 0o600)
        vault.decrypt_file(self.p("enc"), self.p("out"), KEY)
        self.assertEqual(os.stat(self.p("out")).st_mode & 0o777, 0o600)
        # a failed re-encrypt (missing source) must not destroy the existing good file
        before = open(self.p("enc"), "rb").read()
        with self.assertRaises(OSError):
            vault.encrypt_file(self.p("nope"), self.p("enc"), KEY)
        self.assertEqual(open(self.p("enc"), "rb").read(), before)
        self.assertEqual([f for f in os.listdir(self.d.name) if f.endswith(".tmp")], [])

    def test_bad_inputs(self):
        src = self.write("in", b"x")
        with self.assertRaises(vault.DecryptionError):
            vault.encrypt_file(src, self.p("e"), b"too short")
        with self.assertRaises(ValueError):
            vault.encrypt_file(src, self.p("e"), "")


if __name__ == "__main__":
    unittest.main()
