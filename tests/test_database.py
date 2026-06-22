"""
Run with:
    pytest tests/ -v

Or with coverage:
    pytest tests/ -v --cov=. --cov-report=term-missing
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
import bcrypt

from databasehandler import DatabaseHandler
from validation import (
    validate_username,
    validate_project_name,
    validate_hours,
    validate_date,
    validate_notes,
    validate_timesheet_form,
    validate_user_form,
)
from auth import validate_password_strength
import datetime


# Fixtures

@pytest.fixture
def db(tmp_path):
    """
    Provide a DatabaseHandler backed by a temporary SQLite file.
    Each test gets a completely fresh database.
    """
    db_file = str(tmp_path / "test.db")
    handler = DatabaseHandler(db_file=db_file)
    return handler


# DatabaseHandler — User tests

class TestUserCRUD:

    def test_create_user_returns_id(self, db):
        """create_user should return a positive integer ID."""
        uid = db.create_user("testuser", "Password1!", is_admin=False)
        assert isinstance(uid, int)
        assert uid > 0

    def test_create_user_password_is_hashed(self, db):
        """
        Stored password must be a bcrypt hash, never plaintext.
        """
        plaintext = "Password1!"
        db.create_user("secureuser", plaintext, is_admin=False)
        user = db.read_user_by_username("secureuser")
        stored_hash = user["password_hash"]

        # Must not store plaintext
        assert stored_hash != plaintext
        # Must be a valid bcrypt hash
        assert bcrypt.checkpw(plaintext.encode("utf-8"), stored_hash.encode("utf-8"))

    def test_read_user_by_id(self, db):
        """read_user should return the correct user for a given ID."""
        uid = db.create_user("alice", "Alice@123!", is_admin=False)
        user = db.read_user(uid)
        assert user is not None
        assert user["username"] == "alice"

    def test_read_user_by_username(self, db):
        """read_user_by_username should find a user by their unique username."""
        db.create_user("bob", "Bob@4567!", is_admin=False)
        user = db.read_user_by_username("bob")
        assert user is not None
        assert user["username"] == "bob"

    def test_read_nonexistent_user_returns_none(self, db):
        """Reading a user that does not exist should return None."""
        assert db.read_user(9999) is None

    def test_read_all_users(self, db):
        """read_all_users should return all active users."""
        db.create_user("user_a", "UserA@111!", is_admin=False)
        db.create_user("user_b", "UserB@222!", is_admin=False)
        # The seeded admin from _initialize_db is also present
        users = db.read_all_users()
        usernames = [u["username"] for u in users]
        assert "user_a" in usernames
        assert "user_b" in usernames

    def test_update_user_username(self, db):
        """update_user should change the username."""
        uid = db.create_user("oldname", "Pass@123!", is_admin=False)
        db.update_user(uid, "newname")
        user = db.read_user(uid)
        assert user["username"] == "newname"

    def test_update_user_password_rehashed(self, db):
        """
        OWASP A02 — updating a password must store a new bcrypt hash.
        """
        uid = db.create_user("passuser", "OldPass@1!", is_admin=False)
        db.update_user(uid, "passuser", new_password="NewPass@2!")
        user = db.read_user(uid)
        assert bcrypt.checkpw(b"NewPass@2!", user["password_hash"].encode("utf-8"))

    def test_soft_delete_user(self, db):
        """
        Deleted users should not appear in read_user or read_user_by_username.
        Soft delete preserves the record in the database.
        """
        uid = db.create_user("todelete", "Delete@1!", is_admin=False)
        db.delete_user(uid)
        assert db.read_user(uid) is None
        assert db.read_user_by_username("todelete") is None

    def test_soft_deleted_user_excluded_from_all_users(self, db):
        """Soft-deleted users should not appear in read_all_users."""
        uid = db.create_user("ghost", "Ghost@111!", is_admin=False)
        db.delete_user(uid)
        users = db.read_all_users()
        usernames = [u["username"] for u in users]
        assert "ghost" not in usernames

    def test_duplicate_username_raises(self, db):
        """Creating two users with the same username should raise an error."""
        db.create_user("dupeuser", "Dupe@123!", is_admin=False)
        with pytest.raises(Exception):
            db.create_user("dupeuser", "Dupe@456!", is_admin=False)


# DatabaseHandler — Authentication tests

class TestAuthentication:

    def test_verify_password_correct(self, db):
        """
        OWASP A02 — verify_password should return the user row on correct credentials.
        """
        db.create_user("loginuser", "Login@123!", is_admin=False)
        result = db.verify_password("loginuser", "Login@123!")
        assert result is not None
        assert result["username"] == "loginuser"

    def test_verify_password_wrong(self, db):
        """verify_password should return None for a wrong password."""
        db.create_user("wrongpass", "Correct@1!", is_admin=False)
        assert db.verify_password("wrongpass", "Wrong@1!") is None

    def test_verify_password_unknown_user(self, db):
        """verify_password should return None for a non-existent username."""
        assert db.verify_password("nobody", "Pass@123!") is None

    def test_account_lockout_after_max_attempts(self, db):
        """
        OWASP A07 — after MAX_LOGIN_ATTEMPTS failures, the account is locked.
        """
        os.environ["MAX_LOGIN_ATTEMPTS"] = "3"
        os.environ["LOCKOUT_MINUTES"] = "15"

        db.create_user("lockme", "LockMe@1!", is_admin=False)

        for _ in range(3):
            result = db.verify_password("lockme", "WrongPass@1!")
            assert result is None

        # Account should now be locked; correct password also fails
        result = db.verify_password("lockme", "LockMe@1!")
        assert result is None

        info = db.get_lockout_info("lockme")
        assert info["is_locked"] is True

    def test_failed_attempts_reset_on_success(self, db):
        """
        OWASP A07 — a successful login resets the failed attempt counter.
        """
        os.environ["MAX_LOGIN_ATTEMPTS"] = "5"
        db.create_user("resetme", "Reset@123!", is_admin=False)

        db.verify_password("resetme", "WrongPass@1!")
        db.verify_password("resetme", "WrongPass@1!")

        # Successful login
        db.verify_password("resetme", "Reset@123!")

        info = db.get_lockout_info("resetme")
        assert info["failed_attempts"] == 0
        assert info["is_locked"] is False

    def test_unlock_user_clears_lockout(self, db):
        """Admin unlock should clear the lockout and reset failed attempts."""
        os.environ["MAX_LOGIN_ATTEMPTS"] = "1"
        uid = db.create_user("lockeduser", "Locked@1!", is_admin=False)

        db.verify_password("lockeduser", "WrongPass@!")  # Triggers lockout

        db.unlock_user(uid)
        info = db.get_lockout_info("lockeduser")
        assert info["is_locked"] is False
        assert info["failed_attempts"] == 0


# DatabaseHandler — Timesheet tests

class TestTimesheetCRUD:

    @pytest.fixture(autouse=True)
    def setup_user(self, db):
        """Create a test user and store their ID for use in timesheet tests."""
        self.db = db
        self.user_id = db.create_user("tsuser", "Timesheet@1!", is_admin=False)

    def test_create_timesheet_returns_id(self):
        """create_timesheet should return a positive integer ID."""
        ts_id = self.db.create_timesheet(self.user_id, "Test Project", 7.5, "2025-01-10", "notes")
        assert isinstance(ts_id, int)
        assert ts_id > 0

    def test_read_timesheet(self):
        """read_timesheet should return the correct entry."""
        ts_id = self.db.create_timesheet(self.user_id, "Alpha Project", 5.0, "2025-02-01", "")
        ts = self.db.read_timesheet(ts_id)
        assert ts is not None
        assert ts["project_name"] == "Alpha Project"
        assert ts["hours_spent"] == 5.0

    def test_read_timesheets_for_user(self):
        """read_timesheets_for_user should return only that user's entries."""
        self.db.create_timesheet(self.user_id, "Project A", 4.0, "2025-03-01", "")
        self.db.create_timesheet(self.user_id, "Project B", 6.0, "2025-03-02", "")
        rows = self.db.read_timesheets_for_user(self.user_id)
        assert len(rows) >= 2

    def test_read_all_timesheets(self):
        """read_all_timesheets should return entries from all users."""
        other_id = self.db.create_user("other", "Other@1234!", is_admin=False)
        self.db.create_timesheet(self.user_id, "Project A", 3.0, "2025-04-01", "")
        self.db.create_timesheet(other_id,     "Project B", 4.5, "2025-04-01", "")
        rows = self.db.read_all_timesheets()
        project_names = [r["project_name"] for r in rows]
        assert "Project A" in project_names
        assert "Project B" in project_names

    def test_update_timesheet(self):
        """update_timesheet should change the stored values."""
        ts_id = self.db.create_timesheet(self.user_id, "Old Project", 4.0, "2025-05-01", "")
        self.db.update_timesheet(ts_id, "New Project", 6.5, "2025-05-02", "updated notes")
        ts = self.db.read_timesheet(ts_id)
        assert ts["project_name"] == "New Project"
        assert ts["hours_spent"] == 6.5

    def test_soft_delete_timesheet(self):
        """Deleted timesheets should not be returned by read_timesheet."""
        ts_id = self.db.create_timesheet(self.user_id, "Delete Me", 2.0, "2025-06-01", "")
        self.db.delete_timesheet(ts_id)
        assert self.db.read_timesheet(ts_id) is None

    def test_deleted_timesheet_excluded_from_user_list(self):
        """Soft-deleted entries should not appear in read_timesheets_for_user."""
        ts_id = self.db.create_timesheet(self.user_id, "Ghost Entry", 1.5, "2025-07-01", "")
        self.db.delete_timesheet(ts_id)
        rows = self.db.read_timesheets_for_user(self.user_id)
        ids = [r["id"] for r in rows]
        assert ts_id not in ids


# Validation tests

class TestValidation:

    # Username
    def test_valid_username(self):
        assert validate_username("alice.jones")[0] is True

    def test_username_too_short(self):
        ok, msg = validate_username("ab")
        assert ok is False
        assert "characters" in msg

    def test_username_empty(self):
        assert validate_username("")[0] is False

    def test_username_invalid_chars(self):
        ok, _ = validate_username("bad username!")
        assert ok is False

    # Project name
    def test_valid_project_name(self):
        assert validate_project_name("Cloud Migration")[0] is True

    def test_project_name_empty(self):
        assert validate_project_name("")[0] is False

    def test_project_name_too_long(self):
        ok, _ = validate_project_name("x" * 101)
        assert ok is False

    # Hours
    def test_valid_hours(self):
        assert validate_hours(7.5)[0] is True

    def test_hours_below_minimum(self):
        ok, _ = validate_hours(0.0)
        assert ok is False

    def test_hours_above_maximum(self):
        ok, _ = validate_hours(24.5)
        assert ok is False

    def test_hours_invalid_granularity(self):
        ok, _ = validate_hours(3.3)
        assert ok is False

    # Date
    def test_valid_date(self):
        past = datetime.date(2024, 6, 15)
        assert validate_date(past)[0] is True

    def test_future_date_rejected(self):
        future = datetime.date.today() + datetime.timedelta(days=1)
        ok, _ = validate_date(future)
        assert ok is False

    def test_date_before_2000_rejected(self):
        ancient = datetime.date(1999, 12, 31)
        ok, _ = validate_date(ancient)
        assert ok is False

    # Notes
    def test_valid_notes(self):
        assert validate_notes("Some notes here")[0] is True

    def test_notes_too_long(self):
        ok, _ = validate_notes("x" * 501)
        assert ok is False

    def test_empty_notes_ok(self):
        assert validate_notes("")[0] is True

    # timesheet form
    def test_valid_timesheet_form(self):
        ok, errors = validate_timesheet_form(
            "Valid Project", 7.5, datetime.date(2025, 1, 10), "good notes"
        )
        assert ok is True
        assert errors == []

    def test_invalid_timesheet_form_multiple_errors(self):
        ok, errors = validate_timesheet_form(
            "",   # empty project
            99.0, # invalid hours
            datetime.date.today() + datetime.timedelta(days=5),  # future date
            "x" * 600  # notes too long
        )
        assert ok is False
        assert len(errors) >= 3

    # Password strength
    def test_strong_password(self):
        ok, _ = validate_password_strength("Str0ng@Pass!")
        assert ok is True

    def test_weak_password_no_uppercase(self):
        ok, msg = validate_password_strength("weakpass1!")
        assert ok is False

    def test_weak_password_no_special_char(self):
        ok, _ = validate_password_strength("WeakPass1")
        assert ok is False

    def test_weak_password_too_short(self):
        ok, _ = validate_password_strength("Sh@1")
        assert ok is False