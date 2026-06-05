"""
SQLite database layer.

Design notes:
- Database acts as a context manager so connections are always closed cleanly.
- PasswordManager.search() supports partial/case-insensitive website matching
  so users don't need exact names.
- Category FK is resolved to a name on every password read to avoid a
  second query at the call site.
- All mutations are wrapped in explicit transactions so partial writes roll
  back automatically.
"""

import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Typed record returned from queries
# ---------------------------------------------------------------------------

class PasswordEntry:
    __slots__ = ("id", "website", "username", "encrypted_password",
                 "notes", "created_at", "updated_at", "category")

    def __init__(self, row: tuple):
        (
            self.id,
            self.website,
            self.username,
            self.encrypted_password,
            self.notes,
            self.created_at,
            self.updated_at,
            self.category,   # already resolved to name or None
        ) = row


# ---------------------------------------------------------------------------
# Database connection wrapper
# ---------------------------------------------------------------------------

class Database:
    def __init__(self, db_path: str | Path):
        self.db_path = str(db_path)
        self._conn: Optional[sqlite3.Connection] = None

    # Context-manager support
    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *_):
        self.close()

    def connect(self):
        """Open the SQLite connection with WAL journal mode for reliability."""
        self._conn = sqlite3.connect(self.db_path)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")

    def close(self):
        if self._conn:
            self._conn.close()
            self._conn = None

    @property
    def conn(self) -> sqlite3.Connection:
        if self._conn is None:
            raise RuntimeError("Database is not connected. Call connect() first.")
        return self._conn

    def init_tables(self):
        with self.conn:
            self.conn.executescript("""
                CREATE TABLE IF NOT EXISTS categories (
                    id   INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT    NOT NULL UNIQUE
                );

                CREATE TABLE IF NOT EXISTS passwords (
                    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
                    website            TEXT    NOT NULL,
                    username           TEXT    NOT NULL,
                    encrypted_password TEXT    NOT NULL,
                    notes              TEXT,
                    created_at         DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at         DATETIME DEFAULT CURRENT_TIMESTAMP,
                    category_id        INTEGER REFERENCES categories(id) ON DELETE SET NULL
                );

                CREATE INDEX IF NOT EXISTS idx_passwords_website
                    ON passwords(website COLLATE NOCASE);
            """)


# ---------------------------------------------------------------------------
# Password CRUD
# ---------------------------------------------------------------------------

class PasswordManager:
    def __init__(self, database: Database):
        self.db = database

    # -- helpers -----------------------------------------------------------

    def _resolve_row(self, row) -> Optional[PasswordEntry]:
        """Convert a sqlite3.Row to a PasswordEntry with category name resolved."""
        if row is None:
            return None
        category_name = None
        if row["category_id"] is not None:
            cur = self.db.conn.execute(
                "SELECT name FROM categories WHERE id = ?", (row["category_id"],)
            )
            cat = cur.fetchone()
            category_name = cat["name"] if cat else None

        return PasswordEntry((
            row["id"],
            row["website"],
            row["username"],
            row["encrypted_password"],
            row["notes"],
            row["created_at"],
            row["updated_at"],
            category_name,
        ))

    # -- passwords ---------------------------------------------------------

    def add_password(
        self,
        website: str,
        username: str,
        encrypted_password: str,
        notes: Optional[str] = None,
        category: Optional[str] = None,
    ) -> bool:
        category_id = self._get_or_create_category_id(category) if category else None
        try:
            with self.db.conn:
                self.db.conn.execute(
                    """INSERT INTO passwords
                           (website, username, encrypted_password, notes, category_id)
                       VALUES (?, ?, ?, ?, ?)""",
                    (website, username, encrypted_password, notes, category_id),
                )
            return True
        except sqlite3.Error as exc:
            print(f"Error adding password: {exc}")
            return False

    def get_password(self, website: str) -> Optional[PasswordEntry]:
        """Exact match lookup (case-insensitive)."""
        cur = self.db.conn.execute(
            "SELECT * FROM passwords WHERE website = ? COLLATE NOCASE LIMIT 1",
            (website,),
        )
        return self._resolve_row(cur.fetchone())

    def search_passwords(self, query: str) -> list[PasswordEntry]:
        """Partial, case-insensitive website search."""
        cur = self.db.conn.execute(
            "SELECT * FROM passwords WHERE website LIKE ? COLLATE NOCASE ORDER BY website",
            (f"%{query}%",),
        )
        return [self._resolve_row(row) for row in cur.fetchall()]

    def update_password(
        self,
        website: str,
        new_encrypted_password: str,
        new_username: Optional[str] = None,
        new_notes: Optional[str] = None,
    ) -> bool:
        try:
            with self.db.conn:
                if new_username is not None and new_notes is not None:
                    self.db.conn.execute(
                        """UPDATE passwords
                           SET encrypted_password = ?,
                               username = ?,
                               notes = ?,
                               updated_at = CURRENT_TIMESTAMP
                           WHERE website = ? COLLATE NOCASE""",
                        (new_encrypted_password, new_username, new_notes, website),
                    )
                elif new_username is not None:
                    self.db.conn.execute(
                        """UPDATE passwords
                           SET encrypted_password = ?,
                               username = ?,
                               updated_at = CURRENT_TIMESTAMP
                           WHERE website = ? COLLATE NOCASE""",
                        (new_encrypted_password, new_username, website),
                    )
                else:
                    self.db.conn.execute(
                        """UPDATE passwords
                           SET encrypted_password = ?,
                               updated_at = CURRENT_TIMESTAMP
                           WHERE website = ? COLLATE NOCASE""",
                        (new_encrypted_password, website),
                    )
            return True
        except sqlite3.Error as exc:
            print(f"Error updating password: {exc}")
            return False

    def update_password_by_id(self, entry_id: int, new_encrypted_password: str) -> bool:
        try:
            with self.db.conn:
                self.db.conn.execute(
                    """UPDATE passwords
                       SET encrypted_password = ?,
                           updated_at = CURRENT_TIMESTAMP
                       WHERE id = ?""",
                    (new_encrypted_password, entry_id),
                )
            return True
        except sqlite3.Error as exc:
            print(f"Error updating password by id: {exc}")
            return False

    def delete_password(self, website: str) -> bool:
        try:
            with self.db.conn:
                self.db.conn.execute(
                    "DELETE FROM passwords WHERE website = ? COLLATE NOCASE", (website,)
                )
            return True
        except sqlite3.Error as exc:
            print(f"Error deleting password: {exc}")
            return False

    def get_all_passwords(self) -> list[PasswordEntry]:
        cur = self.db.conn.execute(
            "SELECT * FROM passwords ORDER BY website COLLATE NOCASE"
        )
        return [self._resolve_row(row) for row in cur.fetchall()]

    def clear_all_passwords(self) -> bool:
        """Remove all encrypted vault entries and unused categories."""
        try:
            with self.db.conn:
                self.db.conn.execute("DELETE FROM passwords")
                self.db.conn.execute("DELETE FROM categories")
            return True
        except sqlite3.Error as exc:
            print(f"Error clearing password vault: {exc}")
            return False

    # -- categories --------------------------------------------------------

    def _get_or_create_category_id(self, name: str) -> int:
        cur = self.db.conn.execute(
            "SELECT id FROM categories WHERE name = ? COLLATE NOCASE", (name,)
        )
        row = cur.fetchone()
        if row:
            return row["id"]
        with self.db.conn:
            cur = self.db.conn.execute(
                "INSERT INTO categories (name) VALUES (?)", (name,)
            )
        return cur.lastrowid

    def get_all_categories(self) -> list[str]:
        cur = self.db.conn.execute("SELECT name FROM categories ORDER BY name")
        return [row["name"] for row in cur.fetchall()]

    def delete_category(self, name: str) -> bool:
        try:
            with self.db.conn:
                self.db.conn.execute(
                    "DELETE FROM categories WHERE name = ? COLLATE NOCASE", (name,)
                )
            return True
        except sqlite3.Error as exc:
            print(f"Error deleting category: {exc}")
            return False
