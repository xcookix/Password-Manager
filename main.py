"""
Password Manager — command-line entry point.

Changes from original:
- Encryption is initialised with data_dir so salt/canary live in data/.
- generate_password() signature now matches PasswordGen.generate().
- Wrong master password is detected at startup via the canary (WrongMasterPasswordError).
- Search command added (partial, case-insensitive).
- Update and delete commands added.
- Clipboard copy offered after password retrieval (requires pyperclip).
- clear_database() closes the DB before deletion.
- All menu paths handle exceptions individually so one bad input
  doesn't crash the session.
"""

import os
import shutil
import sys
from pathlib import Path
from typing import Optional

# Resolve current directory imports when running as `python main.py`
sys.path.insert(0, str(Path(__file__).parent))

from encryption import Encryption, WrongMasterPasswordError
from generator import PasswordGen
from storage import StorageManager
from models import Database, PasswordManager


try:
    import pyperclip
    _CLIPBOARD_AVAILABLE = True
except ImportError:
    _CLIPBOARD_AVAILABLE = False


# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------

class PasswordManagerApp:
    def __init__(self, data_dir: str = "data"):
        self.storage = StorageManager(data_dir)
        self.db = Database(str(self.storage.db_path))
        self.db.connect()
        self.db.init_tables()
        self.password_manager = PasswordManager(self.db)
        self.generator = PasswordGen()
        self.encryption: Optional[Encryption] = None

    # ------------------------------------------------------------------
    # Encryption setup
    # ------------------------------------------------------------------

    def initialize_encryption(self, master_password: str) -> None:
        """
        Initialise encryption.  Raises WrongMasterPasswordError on wrong password.
        """
        self.encryption = Encryption(master_password, self.storage.base_dir)

    def verify_master_password(self, master_password: str) -> bool:
        """Verify a master password without changing the current session."""
        try:
            Encryption(master_password, self.storage.base_dir)
            return True
        except WrongMasterPasswordError:
            return False
        except Exception:
            return False

    def reset_master_password(self, current_password: str, new_password: str) -> bool:
        """Rotate encryption keys and re-encrypt all stored entries."""
        if not self.verify_master_password(current_password):
            print("Current master password is incorrect.")
            return False

        if self.encryption is None:
            raise RuntimeError("Encryption not initialised.")

        entries = self.password_manager.get_all_passwords()
        decrypted_entries = []
        for entry in entries:
            try:
                decrypted_entries.append((entry.id, self.encryption.decrypt(entry.encrypted_password)))
            except Exception as exc:
                print(f"Error decrypting '{entry.website}': {exc}")
                return False

        self.encryption.rotate_master_password(new_password)

        for entry_id, plaintext in decrypted_entries:
            encrypted_password = self.encryption.encrypt(plaintext)
            if not self.password_manager.update_password_by_id(entry_id, encrypted_password):
                print(f"Error re-encrypting entry id {entry_id}")
                return False

        # Debug checks: old password must no longer work, new password must.
        try:
            Encryption(current_password, self.storage.base_dir)
            print("Debug: old password still accepted after reset.")
            return False
        except WrongMasterPasswordError:
            pass

        try:
            Encryption(new_password, self.storage.base_dir)
        except WrongMasterPasswordError:
            print("Debug: new password did not work after reset.")
            return False

        return True

    def set_security_question(self, question: str, answer: str) -> bool:
        """Store a security question."""
        enc = self._require_encryption()
        try:
            enc.set_security_question(question, answer)
            return True
        except Exception as exc:
            print(f"Error setting security question: {exc}")
            return False

    def get_security_question(self) -> Optional[str]:
        """Get the stored security question."""
        enc = self._require_encryption()
        return enc.get_security_question()

    def verify_security_answer(self, answer: str) -> bool:
        """Verify a security question answer."""
        enc = self._require_encryption()
        return enc.verify_security_answer(answer)

    def has_security_question(self) -> bool:
        """Check if a security question is set."""
        if self.encryption is None:
            return False
        return self.encryption.has_security_question()

    def recover_password_via_question(self, answer: str, new_password: str) -> bool:
        """Recover access and reset master password via security question."""
        if self.encryption is None:
            raise RuntimeError("Encryption not initialised.")
        
        enc = self.encryption
        if not enc.verify_security_answer(answer):
            return False
        
        entries = self.password_manager.get_all_passwords()
        decrypted_entries = []
        for entry in entries:
            try:
                decrypted_entries.append((entry.id, enc.decrypt(entry.encrypted_password)))
            except Exception:
                decrypted_entries.append((entry.id, None))
        
        enc.rotate_master_password(new_password)
        
        for entry_id, plaintext in decrypted_entries:
            if plaintext is not None:
                encrypted_password = enc.encrypt(plaintext)
                self.password_manager.update_password_by_id(entry_id, encrypted_password)
        
        return True

    # ------------------------------------------------------------------
    # Password operations
    # ------------------------------------------------------------------

    def _require_encryption(self) -> Encryption:
        if not self.encryption:
            raise RuntimeError("Encryption not initialised.")
        return self.encryption

    def add_password(
        self,
        website: str,
        username: str,
        password: str,
        notes: str = "",
        category: str = "",
    ) -> bool:
        enc = self._require_encryption()
        encrypted = enc.encrypt(password)
        return self.password_manager.add_password(
            website, username, encrypted,
            notes or None,
            category or None,
        )

    def get_password(self, website: str) -> Optional[dict]:
        enc = self._require_encryption()
        entry = self.password_manager.get_password(website)
        if entry is None:
            return None
        return {
            "website":  entry.website,
            "username": entry.username,
            "password": enc.decrypt(entry.encrypted_password),
            "notes":    entry.notes,
            "created":  entry.created_at,
            "updated":  entry.updated_at,
            "category": entry.category,
        }

    def search_passwords(self, query: str) -> list[dict]:
        """Return all entries whose website contains *query* (case-insensitive)."""
        enc = self._require_encryption()
        entries = self.password_manager.search_passwords(query)
        results = []
        for e in entries:
            try:
                results.append({
                    "website":  e.website,
                    "username": e.username,
                    "password": enc.decrypt(e.encrypted_password),
                    "notes":    e.notes,
                    "created":  e.created_at,
                    "updated":  e.updated_at,
                    "category": e.category,
                })
            except Exception:
                pass   # skip entries that can't be decrypted
        return results

    def update_password(self, website: str, new_password: str) -> bool:
        enc = self._require_encryption()
        encrypted = enc.encrypt(new_password)
        return self.password_manager.update_password(website, encrypted)

    def delete_password(self, website: str) -> bool:
        return self.password_manager.delete_password(website)

    # ------------------------------------------------------------------
    # Password generation
    # ------------------------------------------------------------------

    def generate_password(
        self,
        length: int = 16,
        use_lowercase: bool = True,
        use_uppercase: bool = True,
        use_digits: bool = True,
        use_symbols: bool = True,
    ) -> Optional[str]:
        try:
            return self.generator.generate(
                length,
                use_lowercase=use_lowercase,
                use_uppercase=use_uppercase,
                use_digits=use_digits,
                use_symbols=use_symbols,
            )
        except ValueError as exc:
            print(f"Password generation error: {exc}")
            return None

    # ------------------------------------------------------------------
    # Backup / restore
    # ------------------------------------------------------------------

    def backup_data(self, backup_path: Optional[str] = None) -> Optional[str]:
        location = self.storage.create_backup(backup_path)
        if location and self.storage.verify_backup(location):
            return location
        print("Backup verification failed.")
        return None

    def restore_data(self, backup_path: str) -> bool:
        if not self.storage.verify_backup(backup_path):
            print("Invalid or corrupted backup.")
            return False
        return self.storage.restore_backup(backup_path)

    def export_to_usb(self, usb_path: str) -> bool:
        return self.storage.export_to_device(usb_path)

    def import_from_usb(self, usb_path: str) -> bool:
        return self.storage.import_from_device(usb_path)

    def list_backups(self, backup_path: Optional[str] = None) -> list:
        return self.storage.get_backup_list(backup_path)

    # ------------------------------------------------------------------
    # Database management
    # ------------------------------------------------------------------

    def clear_database(self) -> bool:
        try:
            self.db.close()
            data_dir = str(self.storage.base_dir)
            if os.path.exists(data_dir):
                shutil.rmtree(data_dir)
            return True
        except Exception as exc:
            print(f"Error clearing database: {exc}")
            return False

    def close(self):
        try:
            self.db.close()
        except Exception as exc:
            print(f"Error closing database: {exc}")


# ---------------------------------------------------------------------------
# CLI helpers
# ---------------------------------------------------------------------------

def _copy_to_clipboard(text: str) -> None:
    if not _CLIPBOARD_AVAILABLE:
        return
    try:
        pyperclip.copy(text)
        print("(Copied to clipboard.)")
    except Exception:
        pass


def _print_entry(entry: dict) -> None:
    print(f"\n  Website:  {entry['website']}")
    print(f"  Username: {entry['username']}")
    print(f"  Password: {entry['password']}")
    if entry["notes"]:
        print(f"  Notes:    {entry['notes']}")
    if entry["category"]:
        print(f"  Category: {entry['category']}")
    print(f"  Created:  {entry['created']}")
    print(f"  Updated:  {entry['updated']}")


def _print_menu() -> str:
    print("\n╔══════════════════════════════╗")
    print("║     Password Manager CLI     ║")
    print("╠══════════════════════════════╣")
    print("║  1. Add password             ║")
    print("║  2. Get password             ║")
    print("║  3. Search passwords         ║")
    print("║  4. Update password          ║")
    print("║  5. Delete password          ║")
    print("║  6. Generate password        ║")
    print("║  7. List all passwords       ║")
    print("║  8. Create backup            ║")
    print("║  9. Restore from backup      ║")
    print("║ 10. Export to USB            ║")
    print("║ 11. Import from USB          ║")
    print("║ 12. List backups             ║")
    print("║ 13. Clear database           ║")
    print("║ 14. Reset master password    ║")
    print("║ 15. Change security question ║")
    print("║ 16. Exit                     ║")
    print("╚══════════════════════════════╝")
    return input("Choose an option (1-16): ").strip()


def _prompt_generation(app: PasswordManagerApp) -> Optional[str]:
    """Interactive password generation sub-flow. Returns password or None."""
    try:
        raw = input("Password length [16]: ").strip()
        length = int(raw) if raw else 16
    except ValueError:
        print("Invalid length; using 16.")
        length = 16

    memorable = input("Generate memorable passphrase instead? (y/n) [n]: ").strip().lower() == "y"
    if memorable:
        pwd = app.generator.generate_memorable()
    else:
        symbols = input("Include symbols? (y/n) [y]: ").strip().lower()
        use_symbols = symbols != "n"
        pwd = app.generate_password(length=length, use_symbols=use_symbols)

    if pwd:
        report = app.generator.check_strength(pwd)
        print(f"\nGenerated: {pwd}")
        print(f"Strength:  {report.label} (score {report.score}/100, ~{report.entropy_bits} bits)")
        if _CLIPBOARD_AVAILABLE:
            if input("Copy to clipboard? (y/n) [y]: ").strip().lower() != "n":
                _copy_to_clipboard(pwd)
    return pwd


def _prompt_reset_master_password(app: PasswordManagerApp) -> None:
    import getpass

    current = getpass.getpass("Current master password: ")
    if not app.verify_master_password(current):
        print("Incorrect current master password.")
        return

    new_password = getpass.getpass("New master password: ")
    confirm = getpass.getpass("Confirm new master password: ")
    if not new_password:
        print("New password cannot be empty.")
        return
    if new_password != confirm:
        print("Passwords do not match.")
        return

    if app.reset_master_password(current, new_password):
        print("✓ Master password successfully updated.")
    else:
        print("✗ Master password reset failed.")


def _prompt_set_security_question(app: PasswordManagerApp) -> None:
    """Prompt user to set a security question."""
    if app.has_security_question():
        change = input("A security question is already set. Change it? (y/n) [n]: ").strip().lower()
        if change != "y":
            return
        print("You will need to verify your current master password to change the question.")
        current = input("Current master password (for verification): ").strip()
        if not app.verify_master_password(current):
            print("Incorrect master password.")
            return
    
    question = input("Enter a security question: ").strip()
    if not question:
        print("Question cannot be empty.")
        return
    
    answer = input("Enter the answer (will be hashed): ").strip()
    if not answer:
        print("Answer cannot be empty.")
        return
    
    if app.set_security_question(question, answer):
        print("✓ Security question set successfully.")
    else:
        print("✗ Failed to set security question.")


def _prompt_recover_password(app: PasswordManagerApp) -> bool:
    """Recover access via security question. Returns True if successful."""
    import getpass
    
    # We need to check if a security question is set without requiring the master password
    # This is tricky - we'll try to create a temporary Encryption instance to check
    try:
        temp_enc = Encryption("_dummy_", app.storage.base_dir)
    except WrongMasterPasswordError:
        # This is expected if the vault exists; we just want to check if security question exists
        pass
    except Exception as exc:
        print(f"Error checking vault: {exc}")
        return False
    
    # Try to get security question
    question = None
    try:
        temp_enc = Encryption("_dummy_", app.storage.base_dir)
        question = temp_enc.get_security_question()
    except WrongMasterPasswordError:
        # Vault exists but password is wrong; try to get question from file directly
        import json
        config_path = app.storage.base_dir / "security_config.json"
        if config_path.exists():
            try:
                config = json.loads(config_path.read_text(encoding="utf-8"))
                question = config.get("security_question")
            except Exception:
                pass
    except Exception:
        pass
    
    if not question:
        print("No security question is configured for this vault.")
        return False
    
    print(f"\nSecurity Question: {question}")
    answer = input("Answer: ").strip()
    
    # Verify answer directly without needing to initialize encryption
    import json
    config_path = app.storage.base_dir / "security_config.json"
    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
        stored_hash = config.get("security_answer_hash")
        if not stored_hash or not Encryption._verify_security_answer(answer, stored_hash):
            print("Incorrect answer. Recovery failed.")
            return False
    except Exception as exc:
        print(f"Error verifying answer: {exc}")
        return False
    
    print("Identity verified.")
    new_password = getpass.getpass("New master password: ")
    confirm = getpass.getpass("Confirm new master password: ")
    
    if not new_password or new_password != confirm:
        print("Passwords do not match or empty.")
        return False
    
    try:
        # Initialize with dummy password to access the database
        app.initialize_encryption("_dummy_")
    except WrongMasterPasswordError:
        # Try with a real password from the vault
        pass
    except Exception:
        pass
    
    # Now reset using the recovery method
    try:
        if app.recover_password_via_question(answer, new_password):
            print("✓ Master password reset successfully. Please login with your new password.")
            app.close()
            return True
        else:
            print("✗ Password recovery failed.")
            return False
    except Exception as exc:
        print(f"Error during recovery: {exc}")
        return False


def _prompt_change_security_question(app: PasswordManagerApp) -> None:
    """Change the security question after login."""
    import getpass
    
    if not app.has_security_question():
        print("No security question is currently set.")
        setup = input("Set one now? (y/n) [y]: ").strip().lower()
        if setup != "n":
            _prompt_set_security_question(app)
        return
    
    current = getpass.getpass("Current master password (for verification): ")
    if not app.verify_master_password(current):
        print("Incorrect master password.")
        return
    
    _prompt_set_security_question(app)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    app = PasswordManagerApp()

    print("\n⚠  IMPORTANT: Your master password cannot be recovered if forgotten.")
    print("   All passwords are encrypted with it and it is never stored.\n")

    # Master password entry with canary verification
    while True:
        import getpass
        print("\nOptions: [Enter] Login  [r] Recover via security question")
        choice = input("Master password (or 'r' to recover): ").strip()
        
        if choice.lower() == "r":
            if _prompt_recover_password(app):
                return
            else:
                print("Recovery failed. Try again.\n")
                continue
        
        master_password = getpass.getpass("Master password: ") if not choice else choice
        try:
            app.initialize_encryption(master_password)
            break
        except WrongMasterPasswordError:
            print("Incorrect master password. Please try again.\n")
        except Exception as exc:
            print(f"Unexpected error during initialisation: {exc}")
            app.close()
            return
    
    # Ask to set security question on first login
    if not app.has_security_question():
        print("\n✓ Welcome! Your vault is now accessible.")
        setup_q = input("Set up a security question for password recovery? (y/n) [y]: ").strip().lower()
        if setup_q != "n":
            _prompt_set_security_question(app)

    try:
        while True:
            choice = _print_menu()

            # ---- 1. Add password -----------------------------------------
            if choice == "1":
                try:
                    website = input("Website: ").strip()
                    username = input("Username: ").strip()
                    use_gen = input("Generate password? (y/n) [y]: ").strip().lower() != "n"
                    if use_gen:
                        password = _prompt_generation(app)
                        if not password:
                            continue
                    else:
                        import getpass as gp
                        password = gp.getpass("Password: ")
                    notes = input("Notes (optional): ").strip()
                    category = input("Category (optional): ").strip()

                    if app.add_password(website, username, password, notes, category):
                        print("✓ Password saved.")
                    else:
                        print("✗ Failed to save password.")
                except Exception as exc:
                    print(f"Error: {exc}")

            # ---- 2. Get password -----------------------------------------
            elif choice == "2":
                try:
                    website = input("Website: ").strip()
                    entry = app.get_password(website)
                    if entry:
                        _print_entry(entry)
                        if _CLIPBOARD_AVAILABLE:
                            if input("\nCopy password to clipboard? (y/n) [y]: ").strip().lower() != "n":
                                _copy_to_clipboard(entry["password"])
                    else:
                        print("No entry found. Try 'Search' for partial matches.")
                except Exception as exc:
                    print(f"Error: {exc}")

            # ---- 3. Search -----------------------------------------------
            elif choice == "3":
                try:
                    query = input("Search query: ").strip()
                    results = app.search_passwords(query)
                    if results:
                        print(f"\nFound {len(results)} result(s):")
                        for entry in results:
                            _print_entry(entry)
                    else:
                        print("No matching entries.")
                except Exception as exc:
                    print(f"Error: {exc}")

            # ---- 4. Update password --------------------------------------
            elif choice == "4":
                try:
                    website = input("Website to update: ").strip()
                    existing = app.get_password(website)
                    if not existing:
                        print("Entry not found.")
                        continue
                    use_gen = input("Generate new password? (y/n) [y]: ").strip().lower() != "n"
                    if use_gen:
                        new_pwd = _prompt_generation(app)
                        if not new_pwd:
                            continue
                    else:
                        import getpass as gp
                        new_pwd = gp.getpass("New password: ")
                    if app.update_password(website, new_pwd):
                        print("✓ Password updated.")
                    else:
                        print("✗ Update failed.")
                except Exception as exc:
                    print(f"Error: {exc}")

            # ---- 5. Delete password --------------------------------------
            elif choice == "5":
                try:
                    website = input("Website to delete: ").strip()
                    confirm = input(f"Delete entry for '{website}'? (yes/no): ").strip().lower()
                    if confirm == "yes":
                        if app.delete_password(website):
                            print("✓ Entry deleted.")
                        else:
                            print("✗ Deletion failed.")
                    else:
                        print("Cancelled.")
                except Exception as exc:
                    print(f"Error: {exc}")

            # ---- 6. Generate password ------------------------------------
            elif choice == "6":
                try:
                    _prompt_generation(app)
                except Exception as exc:
                    print(f"Error: {exc}")

            # ---- 7. List all passwords -----------------------------------
            elif choice == "7":
                try:
                    entries = app.password_manager.get_all_passwords()
                    if entries:
                        print(f"\nStored passwords ({len(entries)} total):")
                        for e in entries:
                            print(f"\n  Website:  {e.website}  |  Username: {e.username}", end="")
                            if e.category:
                                print(f"  |  Category: {e.category}", end="")
                            print()
                    else:
                        print("No passwords stored yet.")
                except Exception as exc:
                    print(f"Error: {exc}")

            # ---- 8. Create backup ----------------------------------------
            elif choice == "8":
                try:
                    path = input("Backup path [default]: ").strip() or None
                    location = app.backup_data(path)
                    if location:
                        print(f"✓ Backup created and verified: {location}")
                    else:
                        print("✗ Backup failed.")
                except Exception as exc:
                    print(f"Error: {exc}")

            # ---- 9. Restore from backup ----------------------------------
            elif choice == "9":
                try:
                    path = input("Backup path to restore from: ").strip()
                    if app.restore_data(path):
                        print("✓ Restored. Please restart to use the restored data.")
                        break
                    else:
                        print("✗ Restore failed.")
                except Exception as exc:
                    print(f"Error: {exc}")

            # ---- 10. Export to USB ---------------------------------------
            elif choice == "10":
                try:
                    path = input("Export destination path: ").strip()
                    if app.export_to_usb(path):
                        print(f"✓ Exported to: {path}")
                    else:
                        print("✗ Export failed.")
                except Exception as exc:
                    print(f"Error: {exc}")

            # ---- 11. Import from USB -------------------------------------
            elif choice == "11":
                try:
                    path = input("Import source path: ").strip()
                    if app.import_from_usb(path):
                        print("✓ Imported. Please restart to use the imported data.")
                        break
                    else:
                        print("✗ Import failed.")
                except Exception as exc:
                    print(f"Error: {exc}")

            # ---- 12. List backups ----------------------------------------
            elif choice == "12":
                try:
                    path = input("Backup directory [default]: ").strip() or None
                    backups = app.list_backups(path)
                    if backups:
                        print(f"\nAvailable backups ({len(backups)}):")
                        for b in backups:
                            print(f"  {b}")
                    else:
                        print("No backups found.")
                except Exception as exc:
                    print(f"Error: {exc}")

            # ---- 13. Clear database --------------------------------------
            elif choice == "13":
                print("\n⚠  WARNING: This will permanently delete ALL stored passwords!")
                confirm = input("Type 'YES' to confirm: ").strip()
                if confirm == "YES":
                    if app.clear_database():
                        print("✓ Database cleared. Please restart the application.")
                        break
                    else:
                        print("✗ Failed to clear database.")
                else:
                    print("Cancelled.")

            # ---- 14. Reset master password -------------------------------
            elif choice == "14":
                try:
                    _prompt_reset_master_password(app)
                except Exception as exc:
                    print(f"Error resetting master password: {exc}")

            # ---- 15. Change security question ---------------------------
            elif choice == "15":
                try:
                    _prompt_change_security_question(app)
                except Exception as exc:
                    print(f"Error changing security question: {exc}")

            # ---- 16. Exit ------------------------------------------------
            elif choice == "16":
                break
            else:
                print("Invalid option. Please enter 1-16.")

    except KeyboardInterrupt:
        print("\n\nInterrupted — exiting.")
    finally:
        app.close()


if __name__ == "__main__":
    main()
