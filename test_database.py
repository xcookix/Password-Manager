"""Tests for database/models.py"""

import sys
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from database.models import Database, PasswordManager


@pytest.fixture
def db(tmp_path):
    database = Database(tmp_path / "test.db")
    database.connect()
    database.init_tables()
    yield database
    database.close()


@pytest.fixture
def pm(db):
    return PasswordManager(db)


def test_add_and_get(pm):
    assert pm.add_password("example.com", "user@x.com", "enc_pass")
    entry = pm.get_password("example.com")
    assert entry is not None
    assert entry.website == "example.com"
    assert entry.username == "user@x.com"
    assert entry.encrypted_password == "enc_pass"


def test_get_case_insensitive(pm):
    pm.add_password("GitHub.com", "dev", "enc")
    assert pm.get_password("github.com") is not None
    assert pm.get_password("GITHUB.COM") is not None


def test_search_partial(pm):
    pm.add_password("github.com", "u1", "e1")
    pm.add_password("gitlab.com", "u2", "e2")
    pm.add_password("google.com", "u3", "e3")
    results = pm.search_passwords("git")
    assert len(results) == 2
    websites = {r.website for r in results}
    assert "github.com" in websites
    assert "gitlab.com" in websites


def test_update_password(pm):
    pm.add_password("site.com", "u", "old_enc")
    pm.update_password("site.com", "new_enc")
    entry = pm.get_password("site.com")
    assert entry.encrypted_password == "new_enc"


def test_delete_password(pm):
    pm.add_password("todelete.com", "u", "e")
    assert pm.delete_password("todelete.com")
    assert pm.get_password("todelete.com") is None


def test_get_nonexistent_returns_none(pm):
    assert pm.get_password("nothere.com") is None


def test_category_auto_created_and_resolved(pm):
    pm.add_password("bank.com", "u", "e", category="Finance")
    entry = pm.get_password("bank.com")
    assert entry.category == "Finance"


def test_get_all_passwords_ordered(pm):
    pm.add_password("z-site.com", "u", "e")
    pm.add_password("a-site.com", "u", "e")
    all_entries = pm.get_all_passwords()
    names = [e.website for e in all_entries]
    assert names == sorted(names, key=str.lower)


def test_get_all_categories(pm):
    pm.add_password("s1.com", "u", "e", category="Work")
    pm.add_password("s2.com", "u", "e", category="Personal")
    cats = pm.get_all_categories()
    assert "Work" in cats
    assert "Personal" in cats
