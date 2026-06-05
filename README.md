# Secure Password Manager

A command-line password manager that encrypts and stores passwords locally using authenticated encryption.

## Security model

| Concern | Solution |
|---|---|
| Key derivation | Argon2id (time=3, mem=64 MiB, p=4) |
| Entry encryption | AES-256-GCM with a random 256-bit vault key |
| Master password | Derives a wrapping key for `data/vault_key.bin`; the master password is never stored |
| Recovery | Email OTP verifies identity, then local recovery key material re-wraps the same vault key |
| Wrong password detection | `data/canary.bin` detects wrong passwords at startup |
| Nonces | 12-byte random nonce per encryption |

After the first successful login on this version, existing vaults are migrated to wrapped-key encryption. Changing or recovering the master password then preserves stored password entries because the entries remain encrypted with the same vault key.

## First Run On Windows

Use the PowerShell launcher:

```powershell
.\run.ps1
```

The launcher checks for Python, installs Python 3.12 with `winget` when possible, creates `.venv`, checks required libraries, installs `requirements.txt` with a progress display, and then starts the app.

If `winget` is not available, install Python 3.11+ from the official Python website, then rerun `.\run.ps1`.

## Manual Setup

```bash
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe main.py
```

On macOS/Linux-style shells:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python main.py
```

Email recovery uses Gmail API OAuth. Place your OAuth client file at `credentials.json` in the project folder. On the first email recovery attempt, the app opens a Google approval page and stores the resulting token at `data/gmail_token.json`.

Important for existing vaults: log in once with the current master password after installing this version. That creates `vault_key.bin`, `recovery_secret.bin`, and `recovery_vault_key.bin`, which are required for password-preserving email recovery.

## Usage

On Windows PowerShell:

```powershell
.\run.ps1
```

### Menu options

| # | Action |
|---|---|
| 1 | Add a new password entry |
| 2 | Retrieve a password by exact website name |
| 3 | Search passwords |
| 4 | Update an existing password |
| 5 | Delete an entry |
| 6 | Generate a secure password or memorable passphrase |
| 7 | List all stored entries |
| 8 | Create backup |
| 9 | Restore from backup |
| 10 | Export to USB / external drive |
| 11 | Import from USB / external drive |
| 12 | List backups |
| 13 | Clear database |
| 14 | Reset master password |
| 15 | Change security question |
| 16 | Exit |
| 17 | Recovery setup |

## Data files

All runtime data lives in `data/`:

| File | Contents |
|---|---|
| `passwords.db` | Encrypted password entries |
| `salt.bin` | Argon2 salt for the master wrapping key |
| `vault_key.bin` | Vault key encrypted by the master password-derived key |
| `recovery_secret.bin` | Local recovery secret used after email OTP verification |
| `recovery_vault_key.bin` | Vault key encrypted by the local recovery secret |
| `canary.bin` | Encrypted sentinel for password verification |
| `recovery_config.json` | Registered recovery email and temporary OTP hash |
| `gmail_token.json` | Google OAuth token cache |
| `backups/` | Timestamped backup archives |

Backups include the database, salt, canary, vault key wrap, and recovery files when present.
