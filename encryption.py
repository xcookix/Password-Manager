"""
AES-256-GCM encryption with Argon2id key derivation.

Design notes:
- Salt is stored at a caller-supplied path so storage and crypto stay in sync.
- A canary value (a known plaintext encrypted with the derived key) is stored
  alongside the salt so wrong master passwords are detected at startup rather
  than at decrypt time.
- AES-256-GCM provides authenticated encryption; tampered ciphertexts raise
  an exception instead of returning garbage.
- Nonces are randomly generated per encryption and prepended to the ciphertext.
"""

import os
import base64
import json
from pathlib import Path
from typing import Optional

from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
_SALT_SIZE = 32          # bytes
_KEY_SIZE = 32           # bytes  → AES-256
_NONCE_SIZE = 12         # bytes  → GCM standard
_CANARY_PLAINTEXT = b"passwd-manager-canary-v1"

# Argon2id parameters (OWASP 2023 recommended minimum)
_ARGON2_TIME_COST = 3
_ARGON2_MEMORY_COST = 65536   # 64 MiB
_ARGON2_PARALLELISM = 4


class WrongMasterPasswordError(Exception):
    """Raised when the supplied master password does not match the stored canary."""


class Encryption:
    """Handles AES-256-GCM encryption/decryption of password entries."""

    def __init__(self, master_password: str, data_dir: Path):
        """
        Args:
            master_password: The user's master password (UTF-8 string).
            data_dir:        Directory that holds salt.bin and canary.bin.
                             Must already exist.
        """
        self._data_dir = Path(data_dir)
        self._salt = self._load_or_create_salt()
        self._key = self._derive_key(master_password.encode())
        self._aesgcm = AESGCM(self._key)
        self._verify_or_store_canary(master_password)

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt *plaintext* and return a base64-encoded string that embeds
        the random nonce: ``<nonce_b64>:<ciphertext_b64>``.
        """
        nonce = os.urandom(_NONCE_SIZE)
        ciphertext = self._aesgcm.encrypt(nonce, plaintext.encode(), None)
        payload = base64.urlsafe_b64encode(nonce) + b":" + base64.urlsafe_b64encode(ciphertext)
        return payload.decode()

    def decrypt(self, token: str) -> str:
        """
        Decrypt a token produced by :meth:`encrypt`.

        Raises:
            ValueError:  If the token is malformed.
            cryptography.exceptions.InvalidTag: If the ciphertext was tampered with.
        """
        try:
            nonce_b64, ct_b64 = token.encode().split(b":", 1)
            nonce = base64.urlsafe_b64decode(nonce_b64)
            ciphertext = base64.urlsafe_b64decode(ct_b64)
        except Exception as exc:
            raise ValueError(f"Malformed ciphertext token: {exc}") from exc

        plaintext = self._aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _salt_path(self) -> Path:
        return self._data_dir / "salt.bin"

    def _canary_path(self) -> Path:
        return self._data_dir / "canary.bin"

    def _load_or_create_salt(self) -> bytes:
        path = self._salt_path()
        if path.exists():
            return path.read_bytes()
        salt = os.urandom(_SALT_SIZE)
        path.write_bytes(salt)
        return salt

    def _derive_key(self, password: bytes) -> bytes:
        return hash_secret_raw(
            secret=password,
            salt=self._salt,
            time_cost=_ARGON2_TIME_COST,
            memory_cost=_ARGON2_MEMORY_COST,
            parallelism=_ARGON2_PARALLELISM,
            hash_len=_KEY_SIZE,
            type=Type.ID,
        )

    def _verify_or_store_canary(self, master_password: str) -> None:
        """
        On first run: encrypt the canary plaintext and store it.
        On subsequent runs: decrypt the stored canary and compare.

        Raises:
            WrongMasterPasswordError: If the decrypted canary does not match.
        """
        path = self._canary_path()
        if not path.exists():
            token = self.encrypt(_CANARY_PLAINTEXT.decode())
            path.write_text(token, encoding="utf-8")
            return

        token = path.read_text(encoding="utf-8")
        try:
            decrypted = self.decrypt(token)
        except Exception as exc:
            raise WrongMasterPasswordError("Master password is incorrect.") from exc

        if decrypted.encode() != _CANARY_PLAINTEXT:
            raise WrongMasterPasswordError("Master password is incorrect.")

    def _write_salt(self, salt: bytes) -> None:
        self._salt_path().write_bytes(salt)

    def rotate_master_password(self, new_password: str) -> None:
        """
        Rotate the stored key material so the new master password is required.

        This rewrites salt.bin and canary.bin and updates the in-memory AES key.
        """
        new_salt = os.urandom(_SALT_SIZE)
        self._salt = new_salt
        self._write_salt(new_salt)

        self._key = self._derive_key(new_password.encode())
        self._aesgcm = AESGCM(self._key)

        if self._canary_path().exists():
            self._canary_path().unlink()
        token = self.encrypt(_CANARY_PLAINTEXT.decode())
        self._canary_path().write_text(token, encoding="utf-8")

    # ------------------------------------------------------------------
    # Security Question Management
    # ------------------------------------------------------------------

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
        answer_hash = base64.b64encode(salt + key).decode()
        return answer_hash

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
        path = self._security_config_path()
        path.write_text(json.dumps(config, indent=2), encoding="utf-8")

    def get_security_question(self) -> Optional[str]:
        """Retrieve the stored security question (plaintext)."""
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
            if not stored_hash:
                return False
            return self._verify_security_answer(answer, stored_hash)
        except Exception:
            return False

    def has_security_question(self) -> bool:
        """Check if a security question is configured."""
        return self._security_config_path().exists()

