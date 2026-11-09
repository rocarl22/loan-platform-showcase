import unittest
from datetime import datetime, timedelta
import hashlib
from core import auth

FAST = 1000   # iterations kept low so the suite is quick


class AuthTests(unittest.TestCase):
    def test_roundtrip_and_format(self):
        h = auth.hash_password("S3cret-pass!", iterations=FAST)
        self.assertTrue(h.startswith("pbkdf2_sha256$1000$"))
        self.assertEqual(auth.verify_password("S3cret-pass!", h, iterations=FAST), (True, False))
        self.assertEqual(auth.verify_password("wrong", h, iterations=FAST), (False, False))

    def test_salts_differ(self):
        self.assertNotEqual(auth.hash_password("same", FAST), auth.hash_password("same", FAST))

    def test_upgrade_flag_when_iterations_raised(self):
        h = auth.hash_password("pw-12345", iterations=FAST)
        ok, up = auth.verify_password("pw-12345", h, iterations=FAST * 2)
        self.assertTrue(ok); self.assertTrue(up)

    def test_legacy_pbkdf2_and_sha256_verify_and_flag_upgrade(self):
        salt = "abc123"
        pb = hashlib.pbkdf2_hmac("sha256", b"old-pass", salt.encode(), 200_000).hex()
        self.assertEqual(auth.verify_password("old-pass", pb, legacy_salt=salt), (True, True))
        sh = hashlib.sha256((salt + "older").encode()).hexdigest()
        self.assertEqual(auth.verify_password("older", sh, legacy_salt=salt), (True, True))
        self.assertEqual(auth.verify_password("nope", sh, legacy_salt=salt), (False, False))

    def test_imported_legacy_format(self):
        salt = "s1"
        sh = hashlib.sha256((salt + "pw").encode()).hexdigest()
        self.assertEqual(auth.verify_password("pw", f"legacy${salt}${sh}"), (True, True))

    def test_garbage_hash_is_rejected_not_crashed(self):
        self.assertEqual(auth.verify_password("x", "pbkdf2_sha256$notanint$s$h"), (False, False))
        self.assertEqual(auth.verify_password("x", ""), (False, False))
        self.assertEqual(auth.verify_password("", "legacy$onlytwo"), (False, False))

    def test_policy(self):
        self.assertFalse(auth.password_ok("short")[0])
        self.assertFalse(auth.password_ok("admin123")[0])
        self.assertFalse(auth.password_ok("aaaaaaaa")[0])
        self.assertTrue(auth.password_ok("correct horse 9")[0])

    def test_lockout_cycle(self):
        now = datetime(2026, 10, 19, 12, 0, 0)
        n, until = 0, ""
        for i in range(auth.MAX_LOGIN_ATTEMPTS - 1):
            n, until = auth.register_failure(n, now)
            self.assertEqual(until, "")
        n, until = auth.register_failure(n, now)
        self.assertEqual(until, (now + timedelta(minutes=15)).strftime("%Y-%m-%d %H:%M:%S"))
        locked, msg = auth.is_locked(until, now + timedelta(minutes=5))
        self.assertTrue(locked); self.assertIn("min", msg)
        self.assertFalse(auth.is_locked(until, now + timedelta(minutes=16))[0])
        self.assertFalse(auth.is_locked("", now)[0])
        self.assertFalse(auth.is_locked("garbage", now)[0])

    def test_tokens_unique_and_long(self):
        a, b = auth.new_session_token(), auth.new_session_token()
        self.assertNotEqual(a, b); self.assertGreaterEqual(len(a), 40)


if __name__ == "__main__":
    unittest.main()
