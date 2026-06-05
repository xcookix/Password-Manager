"""
Password Manager — command-line entry point.
"""

import os
import shutil
import sys
import builtins
import importlib
import importlib.util
import getpass
import subprocess
import signal
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple

# Resolve current directory imports
sys.path.insert(0, str(Path(__file__).parent))


_REQUIRED_RUNTIME_PACKAGES = {
    "argon2": "argon2-cffi>=23.1.0",
    "cryptography": "cryptography>=42.0.0",
    "pyperclip": "pyperclip>=1.8.2",
    "googleapiclient": "google-api-python-client>=2.0.0",
    "google.auth": "google-auth>=2.0.0",
    "google_auth_oauthlib": "google-auth-oauthlib>=1.0.0",
    "rich": "rich>=13.7.0",
    "tqdm": "tqdm>=4.66.0",
}


def _module_available(import_name: str) -> bool:
    try:
        return importlib.util.find_spec(import_name) is not None
    except ModuleNotFoundError:
        return False


def _missing_runtime_packages() -> List[str]:
    return [
        package
        for import_name, package in _REQUIRED_RUNTIME_PACKAGES.items()
        if not _module_available(import_name)
    ]


def _install_runtime_packages(packages: List[str]) -> None:
    if not packages:
        return

    print("Installing missing Python libraries for Password Manager...")
    pip_args = [
        sys.executable,
        "-m",
        "pip",
        "install",
        "--disable-pip-version-check",
        "--no-warn-script-location",
    ]
    if not _module_available("tqdm") and any(pkg.startswith("tqdm") for pkg in packages):
        subprocess.check_call([*pip_args, "tqdm>=4.66.0"])
        packages = [pkg for pkg in packages if not pkg.startswith("tqdm")]

    try:
        from tqdm import tqdm
    except ImportError:
        tqdm = None

    iterator = tqdm(packages, desc="Installing libraries", unit="pkg", dynamic_ncols=True) if tqdm else packages
    for package in iterator:
        subprocess.check_call([*pip_args, package])


_install_runtime_packages(_missing_runtime_packages())

try:
    if importlib.util.find_spec("rich") is None:
        raise ImportError
    Console = importlib.import_module("rich.console").Console
    Panel = importlib.import_module("rich.panel").Panel
    Table = importlib.import_module("rich.table").Table
    Text = importlib.import_module("rich.text").Text
except ImportError:  # pragma: no cover - plain terminal fallback
    Console = None
    Panel = None
    Table = None
    Text = None

console = Console() if Console else None
_RAW_GETPASS = getpass.getpass


def _ui_print(message: object = "", style: Optional[str] = None) -> None:
    if console:
        console.print(message, style=style)
    else:
        print(message)


def _success(message: str) -> None:
    _ui_print(f"OK {message}", "bold green")


def _error(message: str) -> None:
    _ui_print(f"ERR {message}", "bold red")


def _warning(message: str) -> None:
    _ui_print(f"WARN {message}", "bold yellow")


def _info(message: str) -> None:
    _ui_print(message, "cyan")


class PromptInterrupted(Exception):
    """Raised when the terminal interrupts the current prompt/action."""


def input(prompt: str = "") -> str:
    try:
        return builtins.input(prompt)
    except (EOFError, KeyboardInterrupt):
        raise PromptInterrupted("Input was interrupted.")


def _safe_getpass(prompt: str = "Password: ") -> str:
    try:
        return _RAW_GETPASS(prompt)
    except (EOFError, KeyboardInterrupt):
        raise PromptInterrupted("Password entry was interrupted.")


def _handle_sigint(signum, frame) -> None:
    _warning("Interrupt ignored. Use menu option 16 to exit safely.")


def _install_interrupt_guard() -> None:
    try:
        signal.signal(signal.SIGINT, _handle_sigint)
    except Exception:
        pass
    getpass.getpass = _safe_getpass


def _prompt_yes_no(prompt: str, default: str = "n") -> bool:
    default = default.lower()
    while True:
        answer = input(prompt).strip().lower()
        if not answer:
            return default == "y"
        if answer in {"y", "yes"}:
            return True
        if answer in {"n", "no"}:
            return False
        _warning("Please answer y or n.")

from encryption import Encryption, WrongMasterPasswordError
from generator import PasswordGen
from storage import StorageManager
from models import Database, PasswordManager
from recovery import RecoveryManager


pyperclip = None
_CLIPBOARD_AVAILABLE = False
if importlib.util.find_spec("pyperclip") is not None:
    try:
        pyperclip = importlib.import_module("pyperclip")
        _CLIPBOARD_AVAILABLE = True
    except ImportError:
        pyperclip = None
        _CLIPBOARD_AVAILABLE = False


class PasswordManagerApp:
    def __init__(self, data_dir: str = "data"):
        # Force resolution to an absolute path string to normalize all sub-modules
        self.base_data_path = str(Path(data_dir).resolve())
        
        self.storage = StorageManager(self.base_data_path)
        self.db = Database(str(self.storage.db_path))
        self.db.connect()   
        self.db.init_tables()
        self.password_manager = PasswordManager(self.db)
        self.generator = PasswordGen()
        self.encryption: Optional[Encryption] = None
        self.recovery = RecoveryManager(self.base_data_path)

    def initialize_encryption(self, master_password: str) -> None:
        """Initialise encryption session. Raises WrongMasterPasswordError on mismatch."""
        self.encryption = Encryption(master_password, Path(self.base_data_path))
        self._migrate_legacy_vault_if_needed()

    def verify_master_password(self, master_password: str) -> bool:
        """Verify a master password cleanly against the configuration."""
        try:
            Encryption(master_password, Path(self.base_data_path))
            return True
        except WrongMasterPasswordError:
            return False
        except Exception:
            return False

    def reset_master_password(self, current_password: str, new_password: str) -> bool:
        """Rotate the master password wrapper while preserving stored entries."""
        if not self.verify_master_password(current_password):
            print("Current master password is incorrect.")
            return False

        enc = self._require_encryption()
        try:
            enc.rotate_master_password(new_password)
            return True
        except Exception as exc:
            print(f"Error rotating master password: {exc}")
            return False

    def set_security_question(self, question: str, answer: str) -> bool:
        """Store a security question configured safely under active encryption."""
        enc = self._require_encryption()
        try:
            enc.set_security_question(question, answer)
            return True
        except Exception as exc:
            print(f"Error setting security question: {exc}")
            return False

    def get_security_question(self) -> Optional[str]:
        """Get the stored security question plaintext string."""
        enc = self._require_encryption()
        return enc.get_security_question()

    def verify_security_answer(self, answer: str) -> bool:
        """Verify a security question answer string."""
        enc = self._require_encryption()
        return enc.verify_security_answer(answer)

    def has_security_question(self) -> bool:
        """Check if a security question has been configured in the storage space."""
        return (Path(self.base_data_path) / "security_config.json").exists()

    def recover_password_via_question(self, answer: str, new_password: str) -> bool:
        """Recover access and reset master password via verified security question answer."""
        if not self.verify_security_answer_for_recovery(answer):
            print("Identity verification failed matching security signature answers.")
            return False

        return self.reset_master_password_after_recovery(new_password)

    def get_security_question_for_recovery(self) -> Optional[str]:
        """Read the recovery security question without requiring the master key."""
        path = Path(self.base_data_path) / "security_config.json"
        if not path.exists():
            return None
        try:
            import json
            config = json.loads(path.read_text(encoding="utf-8"))
            return config.get("security_question")
        except Exception:
            return None

    def verify_security_answer_for_recovery(self, answer: str) -> bool:
        """Verify the security answer without requiring the master key."""
        path = Path(self.base_data_path) / "security_config.json"
        if not path.exists():
            return False
        try:
            import json
            config = json.loads(path.read_text(encoding="utf-8"))
            stored_hash = config.get("security_answer_hash")
            return bool(stored_hash and Encryption._verify_security_answer(answer, stored_hash))
        except Exception:
            return False

    def reset_master_password_after_recovery(self, new_password: str) -> bool:
        """
        Reset the master password after independent identity verification.

        Recovery unwraps the existing vault key using recovery material, then
        re-wraps that same vault key with the new master password.
        """
        try:
            self.encryption = Encryption.reset_master_password_without_old_key(
                new_password,
                Path(self.base_data_path),
            )
            return True
        except Exception as exc:
            print(f"Error writing recovered master password: {exc}")
            return False

    def _require_encryption(self) -> Encryption:
        if not self.encryption:
            raise RuntimeError("Encryption session has not been initialised yet.")
        return self.encryption

    def _migrate_legacy_vault_if_needed(self) -> None:
        enc = self._require_encryption()
        if not enc.needs_legacy_migration:
            return

        entries = self.password_manager.get_all_passwords()
        decrypted_entries: List[Tuple[int, str]] = []

        for entry in entries:
            try:
                decrypted_entries.append((entry.id, enc.decrypt(entry.encrypted_password)))
            except Exception as exc:
                raise RuntimeError(
                    f"Could not migrate encrypted entry for '{entry.website}': {exc}"
                ) from exc

        enc.promote_legacy_vault_key()

        for entry_id, plaintext in decrypted_entries:
            encrypted_password = enc.encrypt(plaintext)
            if not self.password_manager.update_password_by_id(entry_id, encrypted_password):
                raise RuntimeError(f"Could not migrate encrypted entry ID {entry_id}")

        print("Vault encryption upgraded to wrapped-key format.")

    def add_password(self, website: str, username: str, password: str, notes: str = "", category: str = "") -> bool:
        enc = self._require_encryption()
        encrypted = enc.encrypt(password)
        return self.password_manager.add_password(
            website, username, encrypted, notes or None, category or None
        )

    def get_password(self, website: str) -> Optional[Dict[str, Any]]:
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

    def search_passwords(self, query: str) -> List[Dict[str, Any]]:
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
                pass
        return results

    def update_password(self, website: str, new_password: str) -> bool:
        enc = self._require_encryption()
        encrypted = enc.encrypt(new_password)
        return self.password_manager.update_password(website, encrypted)

    def delete_password(self, website: str) -> bool:
        return self.password_manager.delete_password(website)

    def generate_password(self, length: int = 16, use_lowercase: bool = True, use_uppercase: bool = True, use_digits: bool = True, use_symbols: bool = True) -> Optional[str]:
        try:
            return self.generator.generate(
                length, use_lowercase=use_lowercase, use_uppercase=use_uppercase,
                use_digits=use_digits, use_symbols=use_symbols
            )
        except ValueError as exc:
            print(f"Password generation criteria issue: {exc}")
            return None

    def backup_data(self, backup_path: Optional[str] = None) -> Optional[str]:
        location = self.storage.create_backup(backup_path)
        if location and self.storage.verify_backup(location):
            return location
        print("Backup verification sequence failed.")
        return None

    def restore_data(self, backup_path: str) -> bool:
        if not self.storage.verify_backup(backup_path):
            print("Invalid or corrupted storage backup package found.")
            return False
        self.db.close()
        if not self.storage.restore_backup(backup_path):
            self.db.connect()
            self.db.init_tables()
            self.password_manager = PasswordManager(self.db)
            return False

        self.db.connect()
        self.db.init_tables()
        self.password_manager = PasswordManager(self.db)
        return True

    def export_to_usb(self, usb_path: str) -> bool:
        return self.storage.export_to_device(usb_path)

    def import_from_usb(self, usb_path: str) -> bool:
        self.db.close()
        if not self.storage.import_from_device(usb_path):
            self.db.connect()
            self.db.init_tables()
            self.password_manager = PasswordManager(self.db)
            return False

        self.db.connect()
        self.db.init_tables()
        self.password_manager = PasswordManager(self.db)
        return True

    def list_backups(self, backup_path: Optional[str] = None) -> List[Any]:
        return self.storage.get_backup_list(backup_path)

    def clear_database(self) -> bool:
        try:
            self.db.close()
            data_dir = str(self.base_data_path)
            if os.path.exists(data_dir):
                shutil.rmtree(data_dir)
            return True
        except Exception as exc:
            print(f"Error clearing filesystem database workspace: {exc}")
            return False

    def close(self) -> None:
        try:
            self.db.close()
        except Exception as exc:
            print(f"Error terminating database connections cleanly: {exc}")


# ---------------------------------------------------------------------------
# CLI Helper Implementations
# ---------------------------------------------------------------------------

def _copy_to_clipboard(text: str) -> None:
    if not _CLIPBOARD_AVAILABLE:
        return
    try:
        # pyperclip may be None in some environments (type checkers); guard explicitly
        if pyperclip is None:
            return
        pyperclip.copy(text)
        print("(Copied password safely to device clipboard.)")
    except Exception:
        pass


_BANNERS = [
    r"""
 ______                                      _    _______
(_____ \                                    | |  (_______)
 _____) )____  ___  ___ _ _ _  ___   ____ __| |   _  _  _ _____ ____  _____  ____ _____  ____
|  ____(____ |/___)/___) | | |/ _ \ / ___) _  |  | ||_|| (____ |  _ \(____ |/ _  | ___ |/ ___)
| |    / ___ |___ |___ | | | | |_| | |  ( (_| |  | |   | / ___ | | | / ___ ( (_| | ____| |
|_|    \_____(___/(___/ \___/ \___/|_|   \____|  |_|   |_\_____|_| |_\_____|\___ |_____)_|
                                                                           (_____|
                              by cookix
""",
    r"""
  _
 |_) _.  _  _       _  ._ _|   |\/|  _. ._   _.  _   _  ._
 |  (_| _> _> \/\/ (_) | (_|   |  | (_| | | (_| (_| (/_ |
                                                 _|
                            by cookix
""",
    r"""
╔═╗┌─┐┌─┐┌─┐┬ ┬┌─┐┬─┐┌┬┐  ╔╦╗┌─┐┌┐┌┌─┐┌─┐┌─┐┬─┐
╠═╝├─┤└─┐└─┐││││ │├┬┘ ││  ║║║├─┤│││├─┤│ ┬├┤ ├┬┘
╩  ┴ ┴└─┘└─┘└┴┘└─┘┴└──┴┘  ╩ ╩┴ ┴┘└┘┴ ┴└─┘└─┘┴└─
                            by cookix
""",
    r"""
+==============================================================+
|                     PASSWORD MANAGER                         |
|   encrypted vaults . backups . recovery . portable exports   |
|                         by cookix                            |
e
+==============================================================+
""",
]
_BANNERS = [_BANNERS[0], _BANNERS[1], _BANNERS[3]]


def _next_banner_index() -> int:
    state_path = Path("data") / ".banner_state"
    try:
        state_path.parent.mkdir(parents=True, exist_ok=True)
        current = int(state_path.read_text(encoding="utf-8").strip() or "0")
    except Exception:
        current = 0
    try:
        state_path.write_text(str((current + 1) % len(_BANNERS)), encoding="utf-8")
    except Exception:
        pass
    return current % len(_BANNERS)


def _print_banner() -> None:
    banner = _BANNERS[_next_banner_index()]
    if console and Panel:
        console.print(
            Panel.fit(
                Text(banner, style="bold cyan") if Text else banner,
                border_style="bright_blue",
                subtitle="[green]secure local vault[/green]",
            )
        )
    else:
        print(banner)


def _print_entry(entry: Dict[str, Any]) -> None:
    if console and Table and Panel:
        table = Table.grid(padding=(0, 2))
        table.add_column(style="bold cyan")
        table.add_column()
        table.add_row("Website", str(entry["website"]))
        table.add_row("Username", str(entry["username"]))
        table.add_row("Password", str(entry["password"]))
        if entry.get("notes"):
            table.add_row("Notes", str(entry["notes"]))
        if entry.get("category"):
            table.add_row("Category", str(entry["category"]))
        table.add_row("Created", str(entry["created"]))
        table.add_row("Updated", str(entry["updated"]))
        console.print(Panel(table, border_style="green", title=str(entry["website"])))
        return

    print(f"\n  Website:  {entry['website']}")
    print(f"  Username: {entry['username']}")
    print(f"  Password: {entry['password']}")
    if entry.get("notes"):
        print(f"  Notes:    {entry['notes']}")
    if entry.get("category"):
        print(f"  Category: {entry['category']}")
    print(f"  Created:  {entry['created']}")
    print(f"  Updated:  {entry['updated']}")


def _print_menu() -> str:
    if console and Table and Panel:
        table = Table(show_header=False, box=None, pad_edge=False)
        table.add_column("No.", style="bold cyan", justify="right")
        table.add_column("Action", style="bold")
        table.add_column("Description", style="dim")
        rows = [
            ("1", "Add password", "Save a new encrypted login entry."),
            ("2", "Get password", "Retrieve one entry by exact website name."),
            ("3", "Search passwords", "Find entries by partial website text."),
            ("4", "Update password", "Replace the saved password for an entry."),
            ("5", "Delete password", "Remove an entry from the vault."),
            ("6", "Generate password", "Create a strong password or passphrase."),
            ("7", "List all passwords", "Show every stored vault entry."),
            ("8", "Create backup", "Package vault data into a backup archive."),
            ("9", "Restore from backup", "Restore vault data from a backup archive."),
            ("10", "Export to USB", "Copy a backup package to an external device."),
            ("11", "Import from USB", "Import a backup package from an external device."),
            ("12", "List backups", "Show backup archives available locally."),
            ("13", "Clear database", "Delete local vault data after confirmation."),
            ("14", "Reset master password", "Change the master password while logged in."),
            ("15", "Change security question", "Update the recovery challenge question."),
            ("16", "Exit", "Close the password manager safely."),
            ("17", "Recovery setup", "Configure email and security-question recovery."),
        ]
        for row in rows:
            table.add_row(*row)
        console.print(Panel(table, title="Password Manager Menu", border_style="bright_blue"))
        return input("Choose an option (1-17): ").strip()

    print("\nPassword Manager Menu")
    print("  1. Add password             - Save a new encrypted login entry.")
    print("  2. Get password             - Retrieve one entry by exact website name.")
    print("  3. Search passwords         - Find entries by partial website text.")
    print("  4. Update password          - Replace the saved password for an entry.")
    print("  5. Delete password          - Remove an entry from the vault.")
    print("  6. Generate password        - Create a strong password or passphrase.")
    print("  7. List all passwords       - Show every stored vault entry.")
    print("  8. Create backup            - Package vault data into a backup archive.")
    print("  9. Restore from backup      - Restore vault data from a backup archive.")
    print(" 10. Export to USB            - Copy a backup package to an external device.")
    print(" 11. Import from USB          - Import a backup package from an external device.")
    print(" 12. List backups             - Show backup archives available locally.")
    print(" 13. Clear database           - Delete local vault data after confirmation.")
    print(" 14. Reset master password    - Change the master password while logged in.")
    print(" 15. Change security question - Update the recovery challenge question.")
    print(" 16. Exit                     - Close the password manager safely.")
    print(" 17. Recovery setup           - Configure email and security-question recovery.")
    return input("Choose an option (1-17): ").strip()


def _prompt_generation(app: PasswordManagerApp) -> Optional[str]:
    try:
        raw = input("Password length [16]: ").strip()
        length = int(raw) if raw else 16
    except ValueError:
        print("Invalid length integer parsed; defaulting to 16.")
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
        print(f"\nGenerated Password Result: {pwd}")
        print(f"Strength Metrics: {report.label} (Score {report.score}/100, ~{report.entropy_bits} entropy bits)")
        if _CLIPBOARD_AVAILABLE:
            if input("Copy to clipboard? (y/n) [y]: ").strip().lower() != "n":
                _copy_to_clipboard(pwd)
    return pwd


def _prompt_reset_master_password(app: PasswordManagerApp) -> None:
    current = getpass.getpass("Current master password: ")
    if not app.verify_master_password(current):
        print("Incorrect current master password verified.")
        return
    new_password = getpass.getpass("New master password: ")
    confirm = getpass.getpass("Confirm new master password: ")
    if not new_password:
        print("New credentials cannot be structural blanks.")
        return
    if new_password != confirm:
        print("Passwords input mismatch detected.")
        return
    if app.reset_master_password(current, new_password):
        print("✓ Master password successfully updated.")
    else:
        print("✗ Master password reset operation failed.")


def _prompt_set_security_question(app: PasswordManagerApp, require_master_password: bool = True) -> None:
    if app.has_security_question():
        change = input("A security question is already configured. Overwrite? (y/n) [n]: ").strip().lower()
        if change != "y":
            return
        
    if require_master_password:
        print("Verification of current master keys required to confirm update modifications.")
        current = getpass.getpass("Current master password: ")
        if not app.verify_master_password(current):
            print("Incorrect verification authorization password.")
            return
        
    question = input("Enter verification challenge question: ").strip()
    if not question:
        print("Question parameters cannot be left blank.")
        return
    answer = input("Enter specific plaintext secret response: ").strip()
    if not answer:
        print("Answer credentials field required.")
        return
        
    if app.set_security_question(question, answer):
        print("✓ Security question registered and saved successfully.")
    else:
        print("✗ Failed updating security configuration profiles.")


def _prompt_recover_password(app: PasswordManagerApp) -> bool:
    """Prompt user for recovery details via configured security question."""
    question = app.get_security_question_for_recovery()

    if not question:
        print("No fallback verification questions found configured on this local database instance.")
        return False

    print(f"\nVerification Prompt Challenge: {question}")
    answer = input("Answer: ").strip()

    if not app.verify_security_answer_for_recovery(answer):
        print("Incorrect answer mismatch verified. Recovery terminated safely.")
        return False

    print("Identity validated successfully via recovery records.")
    new_password = getpass.getpass("New master password: ")
    confirm = getpass.getpass("Confirm new master password: ")
    if not new_password or new_password != confirm:
        print("Master passwords cannot remain empty and must match properly.")
        return False

    try:
        if app.recover_password_via_question(answer, new_password):
            print("✓ Master password reset completed. Please authenticate with your new password.")
            return True
        else:
            print("✗ Security layer failed writing updated master recovery signatures.")
            return False
    except Exception as exc:
        print(f"Error during recovery action handling operations: {exc}")
        return False


def _prompt_change_security_question(app: PasswordManagerApp) -> None:
    if not app.has_security_question():
        print("No active validation questions exist on this profile.")
        if input("Configure entry profile now? (y/n) [y]: ").strip().lower() != "n":
            _prompt_set_security_question(app)
        return
    _prompt_set_security_question(app)


def _prompt_recovery_setup(app: PasswordManagerApp, only_missing: bool = False) -> None:
    """Guide the user through missing recovery setup after login."""
    missing_question = not app.has_security_question()
    missing_email = not app.recovery.has_recovery_email()

    if only_missing and not missing_question and not missing_email:
        return

    if missing_question or missing_email:
        print("\nRecovery setup is incomplete.")
        if missing_question:
            print("- Security question is not configured.")
        if missing_email:
            print("- Recovery email is not configured.")

        if not _prompt_yes_no("Set up missing recovery options now? (y/n) [y]: ", default="y"):
            print("You can set them up later from menu option 17.")
            return
    else:
        print("\nRecovery setup is already complete.")
        if not _prompt_yes_no("Update recovery settings? (y/n) [n]: ", default="n"):
            return

    if not app.has_security_question() or not only_missing:
        if _prompt_yes_no("Configure security question? (y/n) [y]: ", default="y"):
            _prompt_set_security_question(app, require_master_password=False)

    if not app.recovery.has_recovery_email() or not only_missing:
        if _prompt_yes_no("Configure recovery email? (y/n) [y]: ", default="y"):
            _prompt_register_recovery_email(app)


def main():
    _install_interrupt_guard()
    app = PasswordManagerApp()
    _print_banner()
    print("\n⚠ IMPORTANT: Email recovery can reset your master password only after")
    print(" this vault has been upgraded to wrapped-key encryption by a successful login.\n")

    try:
        while True:
            print("\nOptions: [Enter] Login  |  [r] Recover via Security Question  |  [e] Recover via Email OTP")
            try:
                choice = input("Entry action selection: ").strip().lower()
            except PromptInterrupted as exc:
                _warning(f"{exc} Please choose an option again.")
                continue

            if choice == "e":
                if app.recovery.has_recovery_email():
                    if _prompt_recover_via_email(app):
                        break
                else:
                    print("No recovery email configured. Log in and use menu option 17 to set up recovery.")
                continue

            if choice == "r":
                if _prompt_recover_password(app):
                    break
                continue

            try:
                passwd = getpass.getpass("Enter master database access password: ")
            except PromptInterrupted as exc:
                _warning(f"{exc} Login cancelled.")
                continue
            if not passwd:
                _warning("Master password cannot be empty. Login cancelled.")
                continue
            try:
                app.initialize_encryption(passwd)
                print("✓ Identity verified successfully. Access granted.")
                try:
                    _prompt_recovery_setup(app, only_missing=True)
                except PromptInterrupted as exc:
                    _warning(f"{exc} Recovery setup skipped for now.")
                break
            except WrongMasterPasswordError:
                print("✗ Access credentials failed. Please verify records or use option [r].")
            except Exception as exc:
                print(f"Critical execution initializer error encountered: {exc}")
                sys.exit(1)

        while True:
            try:
                choice = _print_menu()
            except PromptInterrupted as exc:
                _warning(f"{exc} Returning to menu.")
                continue
            if choice == "16":
                break
            elif choice == "1":
                website = input("Website domain: ").strip()
                username = input("Account user tag/email: ").strip()
                use_gen = input("Generate automated credentials securely? (y/n) [n]: ").strip().lower() == "y"
                
                password = ""
                if use_gen:
                    gen_pwd = _prompt_generation(app)
                    if gen_pwd:
                        password = gen_pwd
                else:
                    password = getpass.getpass("Plaintext validation password: ")
                
                notes = input("Optional descriptive notes: ").strip()
                category = input("Optional storage organizational category name: ").strip()
                
                if password and app.add_password(website, username, password, notes, category):
                    print("✓ Entry updated into persistent workspace layout structures.")
                else:
                    print("✗ Operations manager aborted writing item parameters.")
            elif choice == "2":
                website = input("Target domain website: ").strip()
                entry = app.get_password(website)
                if entry:
                    _print_entry(entry)
                    if _CLIPBOARD_AVAILABLE and input("\nCopy password payload to device clipboard? (y/n) [y]: ").strip().lower() != "n":
                        _copy_to_clipboard(entry["password"])
                else:
                    print("Exact domain record match not located. Try partial keyword searching option 3.")
            elif choice == "3":
                query = input("Keyword parameter: ").strip()
                results = app.search_passwords(query)
                if results:
                    print(f"\nDiscovered {len(results)} match profile indicators:")
                    for match in results:
                        _print_entry(match)
                else:
                    print("No indexed profiles corresponded to that filter string.")
            elif choice == "4":
                website = input("Domain profile target key: ").strip()
                if not app.password_manager.get_password(website):
                    print("No active registry handles that website key domain.")
                    continue
                new_p = getpass.getpass("New string value: ")
                if app.update_password(website, new_p):
                    print("✓ Configuration mutations committed safely.")
                else:
                    print("✗ Operation database layer fault dropped.")
            elif choice == "5":
                website = input("Website item deletion target key: ").strip()
                if app.delete_password(website):
                    print("✓ Record purged from active database maps.")
                else:
                    print("✗ System dropped target removal request.")
            elif choice == "6":
                _prompt_generation(app)
            elif choice == "7":
                results = app.search_passwords("")
                print(f"\nDisplaying full profile manifest listing ({len(results)} items):")
                for entry in results:
                    _print_entry(entry)
            elif choice == "8":
                backup_path = input("Backup folder path [default: data/backups/timestamp]: ").strip() or None
                location = app.backup_data(backup_path)
                if location:
                    print(f"✓ Backup created at: {location}")
                else:
                    print("✗ Backup failed.")
            elif choice == "9":
                backup_path = input("Backup folder path containing backup.zip: ").strip()
                if backup_path and app.restore_data(backup_path):
                    print("✓ Backup restored. Please verify your vault entries.")
                else:
                    print("✗ Restore failed.")
            elif choice == "10":
                usb_path = input("Destination folder or USB path: ").strip()
                if usb_path and app.export_to_usb(usb_path):
                    print("✓ Export completed.")
                else:
                    print("✗ Export failed.")
            elif choice == "11":
                usb_path = input("Source folder or USB path containing passwords_backup.zip: ").strip()
                if usb_path and app.import_from_usb(usb_path):
                    print("✓ Import completed. Please verify your vault entries.")
                else:
                    print("✗ Import failed.")
            elif choice == "12":
                backup_path = input("Backup search folder [default: data/backups]: ").strip() or None
                backups = app.list_backups(backup_path)
                if backups:
                    print("\nAvailable backups:")
                    for backup in backups:
                        print(f"  - {backup}")
                else:
                    print("No backups found.")
            elif choice == "13":
                print("This deletes the local vault database and key files.")
                if input("Type DELETE to continue: ").strip() == "DELETE":
                    if app.clear_database():
                        print("✓ Database cleared. Restart the app to create a fresh vault.")
                        break
                    print("✗ Clear database failed.")
            elif choice == "14":
                _prompt_reset_master_password(app)
            elif choice == "15":
                _prompt_change_security_question(app)
            elif choice == "17":
                _prompt_recovery_setup(app)
            else:
                print("Feature choice code execution profile not mapped yet or command unhandled.")

    except KeyboardInterrupt:
        print("\n\nSession interrupted. Closing safely.")
    finally:
        app.close()


def _prompt_recover_via_email(app: "PasswordManagerApp") -> bool:
    """OTP-based master password recovery via registered email."""
    email = app.recovery.get_recovery_email()
    print(f"\nSending a 6-digit recovery code to {email} ...")

    if not app.recovery.generate_and_send_otp():
        print("Failed to send recovery code.")
        return False

    for attempt in range(3):
        code = input(f"Enter the 6-digit code (attempt {attempt + 1}/3): ").strip()
        if app.recovery.verify_otp(code):
            print("\u2713 Code verified.")
            break
        remaining = 2 - attempt
        if remaining > 0:
            print(f"Incorrect code. {remaining} attempt(s) remaining.")
        else:
            print("Too many incorrect attempts. Recovery cancelled.")
            return False
    else:
        return False

    new_password = getpass.getpass("New master password: ")
    confirm = getpass.getpass("Confirm new master password: ")
    if not new_password or new_password != confirm:
        print("Passwords do not match or are empty.")
        return False

    try:
        if not app.reset_master_password_after_recovery(new_password):
            print("Recovery failed while writing the new master password.")
            return False
        print("\u2713 Master password reset successfully. You are now logged in.")
        return True
    except Exception as exc:
        print(f"Recovery failed: {exc}")
        return False


def _prompt_register_recovery_email(app: "PasswordManagerApp") -> None:
    """Register or update the recovery email address."""
    current = app.recovery.get_recovery_email()
    if current:
        print(f"Current recovery email: {current}")
        if input("Update it? (y/n) [n]: ").strip().lower() != "y":
            return
    email = input("Enter recovery email address: ").strip()
    if not email or "@" not in email:
        print("Invalid email address.")
        return
    app.recovery.register_email(email)
    print(f"✓ Recovery email set to: {email}")
    print("  Gmail API is configured with credentials.json.")
    print("  The first recovery email will open a Google OAuth approval page.")

if __name__ == "__main__":
    main()
