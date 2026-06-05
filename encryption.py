"""
AES-256-GCM encryption with Argon2id key derivation and key wrapping.

Passwords are encrypted with a random data encryption key, called the vault
key. The master password derives a separate key that only wraps/unwraps that
vault key. This lets the app change or recover the master password without
re-encrypting every stored password.
"""

import base64
import json
import os
from pathlib import Path
from typing import Optional

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


_SALT_SIZE = 32
_KEY_SIZE = 32
_NONCE_SIZE = 12
_VAULT_KEY_SIZE = 32
_RECOVERY_SECRET_SIZE = 32
_CANARY_PLAINTEXT = b"passwd-manager-canary-v1"

_ARGON2_TIME_COST = 3
_ARGON2_MEMORY_COST = 65536
_ARGON2_PARALLELISM = 4


class WrongMasterPasswordError(Exception):
    """Raised when the supplied master password cannot unlock the vault key."""


class Encryption:
    """Handles AES-256-GCM encryption/decryption of password entries."""

    def __init__(self, master_password: str, data_dir: Path):
        self._data_dir = Path(data_dir)
        self._data_dir.mkdir(parents=True, exist_ok=True)

        self._salt = self._load_or_create_salt()
        self._master_key = self._derive_key(master_password.encode())
        self._legacy_mode = False
        self._vault_key = self._load_or_create_vault_key()
        self._aesgcm = AESGCM(self._vault_key)
        self._verify_or_store_canary()

    def encrypt(self, plaintext: str) -> str:
        """Encrypt plaintext using the vault key."""
        nonce = os.urandom(_NONCE_SIZE)
        ciphertext = self._aesgcm.encrypt(nonce, plaintext.encode(), None)
        payload = (
            base64.urlsafe_b64encode(nonce)
            + b":"
            + base64.urlsafe_b64encode(ciphertext)
        )
        return payload.decode()

    def decrypt(self, token: str) -> str:
        """Decrypt a token produced by encrypt."""
        try:
            nonce_b64, ct_b64 = token.encode().split(b":", 1)
            nonce = base64.urlsafe_b64decode(nonce_b64)
            ciphertext = base64.urlsafe_b64decode(ct_b64)
        except Exception as exc:
            raise ValueError(f"Malformed ciphertext token: {exc}") from exc

        plaintext = self._aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode()

    @property
    def needs_legacy_migration(self) -> bool:
        """True when this vault still uses the old master-derived entry key."""
        return self._legacy_mode

    def promote_legacy_vault_key(self) -> None:
        """
        Replace the legacy entry key with a random wrapped vault key.

        Callers should decrypt old entries before calling this method, then
        re-encrypt those plaintexts with this same Encryption instance.
        """
        if not self._legacy_mode:
            self.ensure_recovery_key_wrap()
            return

        self._vault_key = os.urandom(_VAULT_KEY_SIZE)
        self._aesgcm = AESGCM(self._vault_key)
        self._write_wrapped_vault_key(self._vault_key, self._master_key)
        self._write_canary()
        self._legacy_mode = False
        self.ensure_recovery_key_wrap()

    def rotate_master_password(self, new_password: str) -> None:
        """
        Change the master password by re-wrapping the same vault key.

        Password entries do not need to be decrypted or re-encrypted.
        """
        if self._legacy_mode:
            self.promote_legacy_vault_key()

        self._salt = os.urandom(_SALT_SIZE)
        self._write_salt(self._salt)
        self._master_key = self._derive_key(new_password.encode())
        self._write_wrapped_vault_key(self._vault_key, self._master_key)
        self._write_canary()
        self.ensure_recovery_key_wrap()

    def ensure_recovery_key_wrap(self) -> None:
        """
        Create/update the local recovery wrap for the vault key.

        Email OTP authorizes the recovery flow, and this local secret unwraps
        the vault key after OTP verification.
        """
        secret_path = self._recovery_secret_path()
        if secret_path.exists():
            recovery_secret = secret_path.read_bytes()
        else:
            recovery_secret = os.urandom(_RECOVERY_SECRET_SIZE)
            secret_path.write_bytes(recovery_secret)

        self._recovery_vault_key_path().write_text(
            self._encrypt_bytes(recovery_secret, self._vault_key),
            encoding="utf-8",
        )

    @classmethod
    def reset_master_password_without_old_key(
        cls,
        new_password: str,
        data_dir: Path,
    ) -> "Encryption":
        """
        Reset the master password using the recovery-wrapped vault key.

        This preserves existing vault entries. It requires recovery key
        material created during setup or after a successful login migration.
        """
        data_dir = Path(data_dir)
        secret_path = data_dir / "recovery_secret.bin"
        recovery_wrap_path = data_dir / "recovery_vault_key.bin"

        if not secret_path.exists() or not recovery_wrap_path.exists():
            raise RuntimeError(
                "Recovery key material is missing. Log in once with the current "
                "master password to migrate this vault before using email recovery."
            )

        recovery_secret = secret_path.read_bytes()
        recovery_token = recovery_wrap_path.read_text(encoding="utf-8")
        vault_key = cls._decrypt_bytes(recovery_secret, recovery_token)

        salt = os.urandom(_SALT_SIZE)
        (data_dir / "salt.bin").write_bytes(salt)
        master_key = cls._derive_key_with_salt(new_password.encode(), salt)
        (data_dir / "vault_key.bin").write_text(
            cls._encrypt_bytes(master_key, vault_key),
            encoding="utf-8",
        )

        canary_path = data_dir / "canary.bin"
        if canary_path.exists():
            canary_path.unlink()

        enc = cls(new_password, data_dir)
        enc.ensure_recovery_key_wrap()
        return enc

    def _salt_path(self) -> Path:
        return self._data_dir / "salt.bin"

    def _canary_path(self) -> Path:
        return self._data_dir / "canary.bin"

    def _vault_key_path(self) -> Path:
        return self._data_dir / "vault_key.bin"

    def _recovery_secret_path(self) -> Path:
        return self._data_dir / "recovery_secret.bin"

    def _recovery_vault_key_path(self) -> Path:
        return self._data_dir / "recovery_vault_key.bin"

    def _load_or_create_salt(self) -> bytes:
        path = self._salt_path()
        if path.exists():
            return path.read_bytes()
        salt = os.urandom(_SALT_SIZE)
        path.write_bytes(salt)
        return salt

    def _write_salt(self, salt: bytes) -> None:
        self._salt_path().write_bytes(salt)

    def _derive_key(self, password: bytes) -> bytes:
        return self._derive_key_with_salt(password, self._salt)

    @staticmethod
    def _derive_key_with_salt(password: bytes, salt: bytes) -> bytes:
        return hash_secret_raw(
            secret=password,
            salt=salt,
            time_cost=_ARGON2_TIME_COST,
            memory_cost=_ARGON2_MEMORY_COST,
            parallelism=_ARGON2_PARALLELISM,
            hash_len=_KEY_SIZE,
            type=Type.ID,
        )

    @staticmethod
    def _encrypt_bytes(key: bytes, plaintext: bytes) -> str:
        nonce = os.urandom(_NONCE_SIZE)
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
        return (
            base64.urlsafe_b64encode(nonce)
            + b":"
            + base64.urlsafe_b64encode(ciphertext)
        ).decode()

    @staticmethod
    def _decrypt_bytes(key: bytes, token: str) -> bytes:
        nonce_b64, ct_b64 = token.encode().split(b":", 1)
        nonce = base64.urlsafe_b64decode(nonce_b64)
        ciphertext = base64.urlsafe_b64decode(ct_b64)
        return AESGCM(key).decrypt(nonce, ciphertext, None)

    def _load_or_create_vault_key(self) -> bytes:
        vault_key_path = self._vault_key_path()
        if vault_key_path.exists():
            try:
                return self._decrypt_bytes(
                    self._master_key,
                    vault_key_path.read_text(encoding="utf-8"),
                )
            except Exception as exc:
                raise WrongMasterPasswordError("Master password is incorrect.") from exc

        if self._canary_path().exists():
            self._legacy_mode = True
            return self._master_key

        vault_key = os.urandom(_VAULT_KEY_SIZE)
        self._write_wrapped_vault_key(vault_key, self._master_key)
        return vault_key

    def _write_wrapped_vault_key(self, vault_key: bytes, master_key: bytes) -> None:
        self._vault_key_path().write_text(
            self._encrypt_bytes(master_key, vault_key),
            encoding="utf-8",
        )

    def _verify_or_store_canary(self) -> None:
        path = self._canary_path()
        if not path.exists():
            self._write_canary()
            if not self._legacy_mode:
                self.ensure_recovery_key_wrap()
            return

        try:
            decrypted = self.decrypt(path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise WrongMasterPasswordError("Master password is incorrect.") from exc

        if decrypted.encode() != _CANARY_PLAINTEXT:
            raise WrongMasterPasswordError("Master password is incorrect.")

        if not self._legacy_mode:
            self.ensure_recovery_key_wrap()

    def _write_canary(self) -> None:
        self._canary_path().write_text(
            self.encrypt(_CANARY_PLAINTEXT.decode()),
            encoding="utf-8",
        )

    def _security_config_path(self) -> Path:
        return self._data_dir / "security_config.json"

    @staticmethod
    def _hash_security_answer(answer: str) -> str:
        """Hash a security question answer using PBKDF2."""
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = kdf.derive(answer.encode())
        return base64.b64encode(salt + key).decode()

    @staticmethod
    def _verify_security_answer(answer: str, stored_hash: str) -> bool:
        """Verify a security question answer against its hash."""
        try:
            answer_hash = base64.b64decode(stored_hash.encode())
            salt = answer_hash[:16]
            stored_key = answer_hash[16:]
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            computed_key = kdf.derive(answer.encode())
            return computed_key == stored_key
        except Exception:
            return False

    def set_security_question(self, question: str, answer: str) -> None:
        """Store a security question and hashed answer."""
        config = {
            "security_question": question,
            "security_answer_hash": self._hash_security_answer(answer),
        }
        self._security_config_path().write_text(
            json.dumps(config, indent=2),
            encoding="utf-8",
        )

    def get_security_question(self) -> Optional[str]:
        """Retrieve the stored security question."""
        path = self._security_config_path()
        if not path.exists():
            return None
        try:
            config = json.loads(path.read_text(encoding="utf-8"))
            return config.get("security_question")
        except Exception:
            return None

    def verify_security_answer(self, answer: str) -> bool:
        """Verify a security answer without raising exceptions."""
        path = self._security_config_path()
        if not path.exists():
            return False
        try:
            config = json.loads(path.read_text(encoding="utf-8"))
            stored_hash = config.get("security_answer_hash")
            return bool(stored_hash and self._verify_security_answer(answer, stored_hash))
        except Exception:
            return False

    def has_security_question(self) -> bool:
        """Check if a security question is configured."""
        return self._security_config_path().exists()
