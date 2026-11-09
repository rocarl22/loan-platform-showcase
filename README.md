# Loan Platform: Security & Encryption Showcase

This repository is a **selected portion** of a larger commercial loan and group-savings
management system I built in Python (SQLite, Starlette web app, desktop installer).
The full system is not public. The modules here are the self-contained security
components, published with their tests so the code can be read and run.

## What is included

| Module | What it does |
|---|---|
| `core/auth.py` | Salted PBKDF2-HMAC-SHA256 password hashing, upgrade of older hash formats on login, password policy, secure session token generation |
| `core/totp.py` | Time-based one-time passwords (two-step sign-in) with replay protection |
| `core/crypto.py` | Public-key sealed backups using X25519 key agreement, HKDF and AES-GCM |
| `core/vault.py` | Password-based file encryption using scrypt and AES-GCM |
| `core/keyring.py` | Master-key storage: the key is wrapped by passphrase and recovery code, never stored in the clear |

`tests/` holds the unit tests for each module (44 tests).

## Run the tests

```
python -m venv venv
venv\Scripts\activate        # Windows
pip install -r requirements.txt
python -m unittest discover -s tests -t .
```

Tested on Python 3.13.

## Not included

The web application, loan and payment logic, reporting, licensing and installer are part of
the private commercial product and are not published here.
