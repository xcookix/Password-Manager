"""Tests for core/storage.py"""

import sys
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from core.storage import StorageManager


@pytest.fixture
def storage(tmp_path):
    mgr = StorageManager(tmp_path / "data")
    # Create dummy data files so backups have content
    mgr.db_path.write_bytes(b"fake-db-content")
    mgr.salt_path.write_bytes(b"fake-salt-content")
    mgr.canary_path.write_bytes(b"fake-canary-content")
    return mgr


def test_creates_directories(storage):
    assert storage.base_dir.exists()
    assert (storage.base_dir / "backups").exists()


def test_create_and_verify_backup(storage):
    location = storage.create_backup()
    assert location is not None
    assert storage.verify_backup(location)


def test_backup_contains_required_files(storage):
    import zipfile
    location = storage.create_backup()
    zip_path = Path(location) / "backup.zip"
    with zipfile.ZipFile(zip_path) as zf:
        names = set(zf.namelist())
    assert "passwords.db" in names
    assert "salt.bin" in names
    assert "canary.bin" in names
    assert "metadata.json" in names


def test_restore_backup(storage, tmp_path):
    location = storage.create_backup()
    # Corrupt the live db
    storage.db_path.write_bytes(b"corrupted")
    assert storage.restore_backup(location)
    assert storage.db_path.read_bytes() == b"fake-db-content"


def test_verify_rejects_missing_zip(tmp_path):
    mgr = StorageManager(tmp_path / "data2")
    assert not mgr.verify_backup(str(tmp_path / "nonexistent"))


def test_export_and_import_device(storage, tmp_path):
    dest = tmp_path / "usb"
    assert storage.export_to_device(str(dest))
    assert (dest / "passwords_backup.zip").exists()

    # Now import into a fresh storage
    mgr2 = StorageManager(tmp_path / "data2")
    assert mgr2.import_from_device(str(dest))
    assert mgr2.db_path.read_bytes() == b"fake-db-content"


def test_list_backups_sorted_descending(storage):
    storage.create_backup()
    import time; time.sleep(1.1)
    storage.create_backup()
    backups = storage.get_backup_list()
    assert len(backups) == 2
    assert backups[0].name > backups[1].name   # newest first


def test_cleanup_old_backups(storage):
    for _ in range(4):
        storage.create_backup()
        import time; time.sleep(1.05)
    storage.cleanup_old_backups(keep_last=2)
    assert len(storage.get_backup_list()) == 2
