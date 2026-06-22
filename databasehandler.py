import os
import sqlite3
from datetime import datetime, timedelta, timezone
from sqlite3 import Error

import bcrypt 


def _get_db_path() -> str:
    try:
        import streamlit as st
        db_dir = st.secrets.get("SQLITE_DB_PATH", "./db")
        db_file = st.secrets.get("SQLITE_DB", "timesheetmanager.db")
    except Exception:
        db_dir = os.getenv("SQLITE_DB_PATH", "./db")
        db_file = os.getenv("SQLITE_DB", "timesheetmanager.db")

    os.makedirs(db_dir, exist_ok=True)
    return os.path.join(db_dir, db_file)


class DatabaseHandler:

    def __init__(self, db_file: str | None = None):
        self.db_file = db_file or _get_db_path()
        self._initialize_db()

    # Connection
    def _create_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_file)
        conn.execute("PRAGMA foreign_keys = ON")
        conn.row_factory = sqlite3.Row 
        return conn


    # Initialisation
    def _initialize_db(self) -> None:
        """Create tables and seed an admin account if no users exist."""
        self._create_tables()
        if self._read_user_count() == 0:
            self._seed_data()

    def _create_tables(self) -> None:
        """Create all application tables if they do not already exist."""
        with self._create_connection() as conn:
            cursor = conn.cursor()

            # users table
            # - password stored as bcrypt hash (OWASP A02)
            # - is_deleted supports soft-delete audit trail
            # - failed_attempts / locked_until (OWASP A07)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id               INTEGER PRIMARY KEY AUTOINCREMENT,
                    username         TEXT    NOT NULL UNIQUE,
                    password_hash    TEXT    NOT NULL,
                    is_admin         BOOLEAN NOT NULL DEFAULT 0,
                    is_deleted       BOOLEAN NOT NULL DEFAULT 0,
                    failed_attempts  INTEGER NOT NULL DEFAULT 0,
                    locked_until     TEXT    DEFAULT NULL,
                    created_at       TEXT    NOT NULL DEFAULT (datetime('now'))
                )
            """)

            # timesheets table
            # - user_id is a foreign key referencing users(id)
            # - is_deleted supports soft-delete audit trail
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS timesheets (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id      INTEGER NOT NULL,
                    project_name TEXT    NOT NULL,
                    hours_spent  REAL    NOT NULL,
                    date         TEXT    NOT NULL,
                    notes        TEXT    DEFAULT '',
                    is_deleted   BOOLEAN NOT NULL DEFAULT 0,
                    created_at   TEXT    NOT NULL DEFAULT (datetime('now')),
                    updated_at   TEXT    NOT NULL DEFAULT (datetime('now')),
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            """)

            conn.commit()

    def _seed_data(self) -> None:
        """
        Seed the database with an admin user and sample timesheet records.
        Called only when the users table is empty (first run).
        """
        # Sample user entries - passwords stored in .env file
        admin_password = os.getenv("ADMIN_PASSWORD")
        alice_password = os.getenv("ALICE_PASSWORD")
        bob_password   = os.getenv("BOB_PASSWORD")

        admin_id = self.create_user("admin",       admin_password, is_admin=True)
        alice_id = self.create_user("alice.jones", alice_password, is_admin=False)
        bob_id   = self.create_user("bob.smith",   bob_password,   is_admin=False)

        # Sample timesheet entries
        sample_timesheets = [
            (alice_id, "Cloud Migration - Phase 1",     7.5, "2025-01-06", "Initial infrastructure assessment"),
            (alice_id, "Cloud Migration - Phase 1",     6.0, "2025-01-07", "Azure resource group setup"),
            (alice_id, "ERP Integration",               8.0, "2025-01-08", "API mapping workshop with client"),
            (bob_id,   "Cyber Security Audit",          5.5, "2025-01-06", "Penetration testing - network layer"),
            (bob_id,   "Cyber Security Audit",          7.0, "2025-01-07", "Vulnerability report draft"),
            (bob_id,   "DevOps Transformation",         8.0, "2025-01-08", "CI/CD pipeline design"),
            (alice_id, "DevOps Transformation",         4.5, "2025-01-09", "Docker containerisation workshop"),
            (bob_id,   "Data Analytics Platform",       6.5, "2025-01-09", "Power BI dashboard build"),
            (alice_id, "Data Analytics Platform",       7.0, "2025-01-10", "ETL pipeline implementation"),
            (bob_id,   "Cloud Migration - Phase 2",     8.0, "2025-01-10", "Cutover planning session"),
        ]

        for (uid, project, hours, date, notes) in sample_timesheets:
            self.create_timesheet(uid, project, hours, date, notes)

    # User CRUD

    def create_user(self, username: str, password: str, is_admin: bool = False) -> int:
        # Hash the password with bcrypt using a work factor of 12
        password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12))

        with self._create_connection() as conn:
            cursor = conn.cursor()
            # Parameterised query prevents SQL injection (OWASP A03)
            cursor.execute(
                "INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)",
                (username, password_hash.decode("utf-8"), int(is_admin))
            )
            conn.commit()
            return cursor.lastrowid

    def read_user(self, user_id: int) -> sqlite3.Row | None:
        """Fetch a single active user by primary key."""
        with self._create_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM users WHERE id = ? AND is_deleted = 0",
                (user_id,)
            )
            return cursor.fetchone()

    def read_user_by_username(self, username: str) -> sqlite3.Row | None:
        """Fetch a single active user by username (used during authentication)."""
        with self._create_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM users WHERE username = ? AND is_deleted = 0",
                (username,)
            )
            return cursor.fetchone()

    def read_all_users(self) -> list[sqlite3.Row]:
        """Return all active (non-deleted) users ordered by username."""
        with self._create_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, username, is_admin, created_at FROM users WHERE is_deleted = 0 ORDER BY username"
            )
            return cursor.fetchall()

    def update_user(self, user_id: int, username: str, new_password: str | None = None) -> None:
        with self._create_connection() as conn:
            cursor = conn.cursor()
            if new_password:
                password_hash = bcrypt.hashpw(
                    new_password.encode("utf-8"), bcrypt.gensalt(rounds=12)
                ).decode("utf-8")
                cursor.execute(
                    "UPDATE users SET username = ?, password_hash = ? WHERE id = ? AND is_deleted = 0",
                    (username, password_hash, user_id)
                )
            else:
                cursor.execute(
                    "UPDATE users SET username = ? WHERE id = ? AND is_deleted = 0",
                    (username, user_id)
                )
            conn.commit()

    def delete_user(self, user_id: int) -> None:
        with self._create_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE users SET is_deleted = 1 WHERE id = ?",
                (user_id,)
            )
            conn.commit()

    def _read_user_count(self) -> int:
        """Return the total count of users (including soft-deleted) for seeding check."""
        with self._create_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM users")
            return cursor.fetchone()[0]

    # Authentication & Rate Limiting 

    def verify_password(self, username: str, plaintext_password: str) -> sqlite3.Row | None:
        """
        Verify a login attempt against the stored bcrypt hash.

        Implements account lockout to defend against brute-force attacks
        (OWASP A07 - Identification and Authentication Failures).

        Returns the user row on success, or None on failure / lockout.
        """
        try:
            max_attempts = int(os.getenv("MAX_LOGIN_ATTEMPTS", 5))
            lockout_mins = int(os.getenv("LOCKOUT_MINUTES", 15))
        except Exception:
            max_attempts, lockout_mins = 5, 15

        try:
            import streamlit as st
            max_attempts = int(st.secrets.get("MAX_LOGIN_ATTEMPTS", max_attempts))
            lockout_mins = int(st.secrets.get("LOCKOUT_MINUTES", lockout_mins))
        except Exception:
            pass

        user = self.read_user_by_username(username)
        if not user:
            return None

        # Check if account is currently locked
        if user["locked_until"]:
            locked_until = datetime.fromisoformat(user["locked_until"])
            if datetime.now(timezone.utc) < locked_until.replace(tzinfo=timezone.utc):
                return None 

        # Verify password using bcrypt constant-time comparison
        password_matches = bcrypt.checkpw(
            plaintext_password.encode("utf-8"),
            user["password_hash"].encode("utf-8")
        )

        with self._create_connection() as conn:
            cursor = conn.cursor()
            if password_matches:
                # Reset failure counter on success
                cursor.execute(
                    "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
                    (user["id"],)
                )
                conn.commit()
                return user
            else:
                new_attempts = user["failed_attempts"] + 1
                locked_until = None
                if new_attempts >= max_attempts:
                    locked_until = (
                        datetime.now(timezone.utc) + timedelta(minutes=lockout_mins)
                    ).isoformat()
                cursor.execute(
                    "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                    (new_attempts, locked_until, user["id"])
                )
                conn.commit()
                return None

    def get_lockout_info(self, username: str) -> dict:
        user = self.read_user_by_username(username)
        if not user:
            return {"is_locked": False, "locked_until": None, "failed_attempts": 0}

        is_locked = False
        if user["locked_until"]:
            locked_until_dt = datetime.fromisoformat(user["locked_until"])
            is_locked = datetime.now(timezone.utc) < locked_until_dt.replace(tzinfo=timezone.utc)

        return {
            "is_locked": is_locked,
            "locked_until": user["locked_until"],
            "failed_attempts": user["failed_attempts"],
        }

    def unlock_user(self, user_id: int) -> None:
        """Admin action to manually unlock a locked account."""
        with self._create_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
                (user_id,)
            )
            conn.commit()

    # Timesheet CRUD
    def create_timesheet(
        self,
        user_id: int,
        project_name: str,
        hours_spent: float,
        date: str,
        notes: str = ""
    ) -> int:
        with self._create_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO timesheets (user_id, project_name, hours_spent, date, notes)
                VALUES (?, ?, ?, ?, ?)
                """,
                (user_id, project_name, hours_spent, date, notes)
            )
            conn.commit()
            return cursor.lastrowid

    def read_timesheet(self, timesheet_id: int) -> sqlite3.Row | None:
        """Fetch a single active timesheet entry by primary key."""
        with self._create_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM timesheets WHERE id = ? AND is_deleted = 0",
                (timesheet_id,)
            )
            return cursor.fetchone()

    def read_timesheets_for_user(self, user_id: int) -> list[sqlite3.Row]:
        """Return all active timesheet entries for a specific user, newest first."""
        with self._create_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT t.*, u.username
                FROM   timesheets t
                JOIN   users u ON u.id = t.user_id
                WHERE  t.user_id = ? AND t.is_deleted = 0
                ORDER  BY t.date DESC, t.id DESC
                """,
                (user_id,)
            )
            return cursor.fetchall()

    def read_all_timesheets(self) -> list[sqlite3.Row]:
        """Return all active timesheet entries across all users (admin view)."""
        with self._create_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT t.*, u.username
                FROM   timesheets t
                JOIN   users u ON u.id = t.user_id
                WHERE  t.is_deleted = 0
                ORDER  BY t.date DESC, t.id DESC
                """
            )
            return cursor.fetchall()

    def update_timesheet(
        self,
        timesheet_id: int,
        project_name: str,
        hours_spent: float,
        date: str,
        notes: str = ""
    ) -> None:
        """Update an existing timesheet entry."""
        with self._create_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE timesheets
                SET    project_name = ?,
                       hours_spent  = ?,
                       date         = ?,
                       notes        = ?,
                       updated_at   = datetime('now')
                WHERE  id = ? AND is_deleted = 0
                """,
                (project_name, hours_spent, date, notes, timesheet_id)
            )
            conn.commit()

    def delete_timesheet(self, timesheet_id: int) -> None:
        """Soft-delete a timesheet entry by setting is_deleted = 1."""
        with self._create_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE timesheets SET is_deleted = 1 WHERE id = ?",
                (timesheet_id,)
            )
            conn.commit()