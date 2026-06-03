# Secure Password Manager

A command-line password manager that encrypts and stores your passwords locally using modern authenticated encryption.

## Security model

| Concern | Solution |
|---|---|
| Key derivation | Argon2id (time=3, mem=64 MiB, p=4) |
| Encryption | AES-256-GCM (authenticated — tamper-evident) |
| Salt storage | `data/salt.bin` (same directory as the database) |
| Wrong password detection | Canary value in `data/canary.bin` — wrong password detected at startup, not silently at decrypt time |
| Nonces | 12-byte random nonce per encryption, prepended to ciphertext |

**The master password is never stored.** If you forget it, your data cannot be recovered — keep a backup in a safe place.

## Requirements

Python 3.11+

```bash
pip install -r requirements.txt
```

## Usage

```bash
python src/main.py
```

### Menu options

| # | Action |
|---|---|
| 1 | Add a new password entry |
| 2 | Retrieve a password by exact website name |
| 3 | Search passwords (partial / case-insensitive) |
| 4 | Update an existing password |
| 5 | Delete an entry |
| 6 | Generate a secure password or memorable passphrase |
| 7 | List all stored entries |
| 8 | Create an encrypted backup |
| 9 | Restore from a backup |
| 10 | Export to USB / external drive |
| 11 | Import from USB / external drive |
| 12 | List available backups |
| 13 | Clear the database (irreversible) |
| 14 | Reset master password (requires current password) |
| 15 | Change security question (requires master password) |
| 16 | Exit |

## Project structure

```
passwdmngr/
├── src/
│   ├── main.py               # CLI entry point
│   ├── crypto/
│   │   └── encryption.py     # AES-256-GCM + Argon2id
│   ├── core/
│   │   ├── generator.py      # Password / passphrase generation
│   │   └── storage.py        # Backup, restore, export, import
│   └── database/
│       └── models.py         # SQLite CRUD layer
├── tests/
│   ├── test_encryption.py
│   ├── test_generator.py
│   ├── test_database.py
│   └── test_storage.py
├── requirements.txt
└── README.md
```

## Running tests

```bash
pip install pytest
pytest tests/ -v
```

## Data files

All runtime data lives in `data/` (created automatically):

| File | Contents |
|---|---|
| `passwords.db` | Encrypted password entries (SQLite) |
| `salt.bin` | Argon2 salt — back this up with the database |
| `canary.bin` | Encrypted sentinel for master password verification |
| `backups/` | Timestamped backup archives |

Backups are self-contained zip files that include all three files above.
