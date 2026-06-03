"""
Backup, restore, and device export/import for the password database.

Design notes:
- All paths are resolved relative to a caller-supplied base_dir so this
  module has no opinion about where data lives; main.py owns that.
- Temporary directories are created before the try block so the finally
  clause can always reference them safely.
- Atomic restore: files are extracted to a temp directory and only moved
  into place after all validation passes.
- Backup archives contain passwords.db, salt.bin, and canary.bin so a
  restore is always self-contained.
"""

import json
import shutil
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Optional


_REQUIRED_FILES = {"passwords.db", "salt.bin", "canary.bin"}
_OPTIONAL_FILES = {"security_config.json"}
_BACKUP_VERSION = "2"


class StorageManager:
    def __init__(self, base_dir: str | Path = "data"):
        self.base_dir = Path(base_dir)
        self.db_path = self.base_dir / "passwords.db"
        self.salt_path = self.base_dir / "salt.bin"
        self.canary_path = self.base_dir / "canary.bin"
        self.security_config_path = self.base_dir / "security_config.json"
        self._ensure_dirs()

    # ------------------------------------------------------------------
    # Directory setup
    # ------------------------------------------------------------------

    def _ensure_dirs(self):
        self.base_dir.mkdir(parents=True, exist_ok=True)
        (self.base_dir / "backups").mkdir(exist_ok=True)

    # ------------------------------------------------------------------
    # Backup
    # ------------------------------------------------------------------

    def create_backup(self, backup_path: Optional[str] = None) -> Optional[str]:
        """
        Create a compressed backup zip.

        Returns the backup directory path on success, None on failure.
        """
        if backup_path:
            backup_dir = Path(backup_path)
        else:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_dir = self.base_dir / "backups" / ts

        backup_dir.mkdir(parents=True, exist_ok=True)
        zip_path = backup_dir / "backup.zip"

        try:
            with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
                for src_path, arc_name in [
                    (self.db_path, "passwords.db"),
                    (self.salt_path, "salt.bin"),
                    (self.canary_path, "canary.bin"),
                ]:
                    if src_path.exists():
                        zf.write(src_path, arc_name)
                
                # Include security question if it exists (optional)
                if self.security_config_path.exists():
                    zf.write(self.security_config_path, "security_config.json")

                metadata = {
                    "created": datetime.now().isoformat(),
                    "version": _BACKUP_VERSION,
                    "files": list(_REQUIRED_FILES),
                }
                zf.writestr("metadata.json", json.dumps(metadata, indent=2))
            return str(backup_dir)
        except Exception as exc:
            print(f"Backup failed: {exc}")
            if backup_dir.exists():
                shutil.rmtree(backup_dir, ignore_errors=True)
            return None

    def restore_backup(self, backup_dir: str) -> bool:
        """
        Restore from a backup directory.  Validates before overwriting live data.
        """
        zip_path = Path(backup_dir) / "backup.zip"
        if not zip_path.exists():
            print(f"Backup file not found: {zip_path}")
            return False

        temp_dir = self.base_dir / "_restore_tmp"
        temp_dir.mkdir(exist_ok=True)   # created BEFORE try so finally is safe

        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                zf.extractall(temp_dir)

            # Validate metadata
            meta_path = temp_dir / "metadata.json"
            if not meta_path.exists():
                print("Invalid backup: missing metadata.json")
                return False
            metadata = json.loads(meta_path.read_text())
            if "version" not in metadata:
                print("Invalid backup: metadata missing version field")
                return False

            # Copy validated files into place
            for arc_name, dest in [
                ("passwords.db", self.db_path),
                ("salt.bin", self.salt_path),
                ("canary.bin", self.canary_path),
                ("security_config.json", self.security_config_path),
            ]:
                src = temp_dir / arc_name
                if src.exists():
                    shutil.copy2(src, dest)

            return True
        except Exception as exc:
            print(f"Restore failed: {exc}")
            return False
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def verify_backup(self, backup_dir: str) -> bool:
        """Return True only if the backup zip is intact and complete."""
        zip_path = Path(backup_dir) / "backup.zip"
        if not zip_path.exists():
            return False
        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                if zf.testzip() is not None:
                    return False
                names = set(zf.namelist())
                if not _REQUIRED_FILES.issubset(names):
                    return False
                metadata = json.loads(zf.read("metadata.json"))
                if "version" not in metadata or "files" not in metadata:
                    return False
            return True
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Device export / import
    # ------------------------------------------------------------------

    def export_to_device(self, destination: str) -> bool:
        """Export a self-contained backup zip to an external path."""
        if not destination:
            print("No destination path provided.")
            return False

        dest_path = Path(destination)
        dest_path.mkdir(parents=True, exist_ok=True)
        zip_path = dest_path / "passwords_backup.zip"

        try:
            with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
                for src_path, arc_name in [
                    (self.db_path, "passwords.db"),
                    (self.salt_path, "salt.bin"),
                    (self.canary_path, "canary.bin"),
                ]:
                    if src_path.exists():
                        zf.write(src_path, arc_name)

                metadata = {
                    "created": datetime.now().isoformat(),
                    "version": _BACKUP_VERSION,
                    "files": list(_REQUIRED_FILES),
                }
                zf.writestr("metadata.json", json.dumps(metadata, indent=2))
            return True
        except Exception as exc:
            print(f"Export failed: {exc}")
            zip_path.unlink(missing_ok=True)
            return False

    def import_from_device(self, source: str) -> bool:
        """Import a backup zip from an external path."""
        if not source:
            print("No source path provided.")
            return False

        zip_path = Path(source) / "passwords_backup.zip"
        if not zip_path.exists():
            print(f"Backup file not found: {zip_path}")
            return False

        temp_dir = self.base_dir / "_import_tmp"
        temp_dir.mkdir(exist_ok=True)   # created BEFORE try so finally is safe

        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                zf.extractall(temp_dir)

            meta_path = temp_dir / "metadata.json"
            if not meta_path.exists():
                print("Invalid backup: missing metadata.json")
                return False
            metadata = json.loads(meta_path.read_text())
            if "version" not in metadata:
                print("Invalid backup: metadata missing version field")
                return False

            for arc_name, dest in [
                ("passwords.db", self.db_path),
                ("salt.bin", self.salt_path),
                ("canary.bin", self.canary_path),
            ]:
                src = temp_dir / arc_name
                if src.exists():
                    shutil.copy2(src, dest)

            return True
        except Exception as exc:
            print(f"Import failed: {exc}")
            return False
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    # ------------------------------------------------------------------
    # Backup catalogue
    # ------------------------------------------------------------------

    def get_backup_list(self, backup_path: Optional[str] = None) -> list[Path]:
        search = Path(backup_path) if backup_path else self.base_dir / "backups"
        if not search.exists():
            return []
        return sorted(
            [d for d in search.iterdir() if d.is_dir() and (d / "backup.zip").exists()],
            key=lambda x: x.name,
            reverse=True,
        )

    def cleanup_old_backups(
        self, backup_path: Optional[str] = None, keep_last: int = 5
    ) -> None:
        for old in self.get_backup_list(backup_path)[keep_last:]:
            shutil.rmtree(old, ignore_errors=True)
