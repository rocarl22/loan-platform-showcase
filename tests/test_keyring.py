import json
import os
import tempfile
import unittest

from core import keyring as K

FAST = (10, 1, 1)
PW = "purple tractor nine"


class KeyringTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory(); self.addCleanup(self.d.cleanup)
        self.path = os.path.join(self.d.name, "keyring.json")

    def make(self):
        return K.create(self.path, PW, scrypt=FAST)

    def test_create_then_unlock_both_ways(self):
        master, rec = self.make()
        self.assertEqual(len(master), 32)
        self.assertEqual(K.unlock(self.path, PW), master)
        self.assertEqual(K.unlock_with_recovery(self.path, rec), master)
        self.assertEqual(K.unlock_with_recovery(self.path, rec.lower().replace("-", " ")), master)   # forgiving format
        self.assertRegex(rec, r"^([A-Z2-7]{4}-){7}[A-Z2-7]{4}$")

    def test_wrong_secrets_rejected(self):
        self.make()
        for bad in ("", "wrong passphrase!", PW + "x", PW.upper()):
            with self.assertRaises(K.WrongSecret): K.unlock(self.path, bad)
        with self.assertRaises(K.WrongSecret): K.unlock_with_recovery(self.path, "AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG-HHHH")
        with self.assertRaises(K.WrongSecret): K.unlock(self.path, None)

    def test_file_has_no_secrets_and_owner_only_permissions(self):
        master, rec = self.make()
        raw = open(self.path).read()
        self.assertNotIn(master.hex(), raw); self.assertNotIn(PW, raw)
        self.assertNotIn(rec.replace("-", ""), raw)
        self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o600)

    def test_never_overwrites_an_existing_keyring(self):
        self.make()
        before = open(self.path).read()
        with self.assertRaises(K.KeyringError): K.create(self.path, "another long passphrase", scrypt=FAST)
        self.assertEqual(open(self.path).read(), before)

    def test_change_passphrase_keeps_the_same_master_key(self):
        master, rec = self.make()
        K.change_passphrase(self.path, PW, "a brand new passphrase", scrypt=FAST)
        self.assertEqual(K.unlock(self.path, "a brand new passphrase"), master)       # data stays readable
        with self.assertRaises(K.WrongSecret): K.unlock(self.path, PW)                # old one is dead
        self.assertEqual(K.unlock_with_recovery(self.path, rec), master)              # recovery key unaffected
        with self.assertRaises(K.WrongSecret): K.change_passphrase(self.path, "not it at all", "whatever passphrase", scrypt=FAST)

    def test_recovery_resets_a_forgotten_passphrase(self):
        master, rec = self.make()
        K.reset_passphrase_with_recovery(self.path, rec, "second life passphrase", scrypt=FAST)
        self.assertEqual(K.unlock(self.path, "second life passphrase"), master)
        with self.assertRaises(K.WrongSecret): K.unlock(self.path, PW)

    def test_new_recovery_key_replaces_the_old_one(self):
        master, rec = self.make()
        rec2 = K.new_recovery(self.path, PW, scrypt=FAST)
        self.assertNotEqual(rec, rec2)
        self.assertEqual(K.unlock_with_recovery(self.path, rec2), master)
        with self.assertRaises(K.WrongSecret): K.unlock_with_recovery(self.path, rec)

    def test_passphrase_policy(self):
        for bad in ("short", "", "aaaaaaaaaaaa", "password123"):
            with self.assertRaises(K.KeyringError): K.create(self.path, bad, scrypt=FAST)
        self.assertFalse(os.path.exists(self.path))

    def test_tampering_and_damage_detected(self):
        self.make()
        data = json.load(open(self.path))
        data["passphrase"]["wrapped"] = data["passphrase"]["wrapped"][:-4] + "AAAA"
        json.dump(data, open(self.path, "w"))
        with self.assertRaises(K.WrongSecret): K.unlock(self.path, PW)
        data = json.load(open(self.path)); data["passphrase"]["scrypt"] = [31, 8, 1]       # cost bomb
        json.dump(data, open(self.path, "w"))
        with self.assertRaises(K.KeyringError): K.unlock(self.path, PW)
        open(self.path, "w").write("{not json")
        with self.assertRaises(K.KeyringError): K.unlock(self.path, PW)
        with self.assertRaises(K.KeyringError): K.unlock(os.path.join(self.d.name, "none.json"), PW)

    def test_a_wrapped_key_cannot_be_moved_between_slots(self):
        """The passphrase blob is bound to its slot: pasting it into the recovery slot must fail."""
        master, rec = self.make()
        data = json.load(open(self.path)); data["recovery"] = data["passphrase"]
        json.dump(data, open(self.path, "w"))
        with self.assertRaises(K.WrongSecret): K.unlock_with_recovery(self.path, PW)

    def test_subkeys_are_distinct_stable_and_purpose_bound(self):
        master, _ = self.make()
        db, bk = K.subkey(master, "database"), K.subkey(master, "backup")
        self.assertEqual(len(db), 32); self.assertNotEqual(db, bk); self.assertNotEqual(db, master)
        self.assertEqual(db, K.subkey(master, "database"))
        with self.assertRaises(ValueError): K.subkey(master, "other")
        with self.assertRaises(ValueError): K.subkey(b"short", "backup")


if __name__ == "__main__":
    unittest.main()
