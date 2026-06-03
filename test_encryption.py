"""Tests for crypto/encryption.py"""

import pytest
import tempfile
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from crypto.encryption import Encryption, WrongMasterPasswordError


@pytest.fixture
def tmp_data(tmp_path):
    return tmp_path


def test_roundtrip(tmp_data):
    enc = Encryption("correct-horse", tmp_data)
    token = enc.encrypt("my-secret-password")
    assert enc.decrypt(token) == "my-secret-password"


def test_different_plaintexts_produce_different_tokens(tmp_data):
    enc = Encryption("pass", tmp_data)
    assert enc.encrypt("abc") != enc.encrypt("abc")  # random nonce → different each time


def test_wrong_master_password_raises(tmp_data):
    Encryption("rightpass", tmp_data)   # creates salt + canary
    with pytest.raises(WrongMasterPasswordError):
        Encryption("wrongpass", tmp_data)


def test_correct_password_after_creation(tmp_data):
    Encryption("mypass", tmp_data)
    enc2 = Encryption("mypass", tmp_data)   # should not raise
    token = enc2.encrypt("hello")
    assert enc2.decrypt(token) == "hello"


def test_tampered_ciphertext_raises(tmp_data):
    from cryptography.exceptions import InvalidTag
    enc = Encryption("pass", tmp_data)
    token = enc.encrypt("secret")
    # Corrupt the ciphertext portion
    nonce_b64, ct_b64 = token.split(":")
    bad_token = nonce_b64 + ":" + ct_b64[:-4] + "AAAA"
    with pytest.raises(Exception):   # InvalidTag or ValueError
        enc.decrypt(bad_token)


def test_salt_file_created(tmp_data):
    Encryption("pass", tmp_data)
    assert (tmp_data / "salt.bin").exists()
    assert (tmp_data / "canary.bin").exists()


def test_same_salt_reused_across_instances(tmp_data):
    enc1 = Encryption("pass", tmp_data)
    salt1 = enc1._salt
    enc2 = Encryption("pass", tmp_data)
    assert enc1._salt == enc2._salt


def test_rotate_master_password(tmp_data):
    enc = Encryption("oldpass", tmp_data)
    token = enc.encrypt("secret")
    assert enc.decrypt(token) == "secret"

    enc.rotate_master_password("newpass")
    new_enc = Encryption("newpass", tmp_data)
    assert new_enc.decrypt(new_enc.encrypt("secret")) == "secret"

    with pytest.raises(WrongMasterPasswordError):
        Encryption("oldpass", tmp_data)
