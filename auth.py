import re
import streamlit as st

from databasehandler import DatabaseHandler

_db = DatabaseHandler()


# Password validation

PASSWORD_MIN_LENGTH = 8
PASSWORD_POLICY = (
    "Password must be at least 8 characters and include an uppercase letter, "
    "a lowercase letter, a digit, and a special character (!@#$%^&*_-)."
)


def validate_password_strength(password: str) -> tuple[bool, str]:
    """
    Enforce a basic password policy before accepting a new password.

    Returns:
        (True, "") if the password meets the policy.
        (False, reason) if it does not.
    """
    if len(password) < PASSWORD_MIN_LENGTH:
        return False, f"Password must be at least {PASSWORD_MIN_LENGTH} characters."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"\d", password):
        return False, "Password must contain at least one digit."
    if not re.search(r"[!@#$%^&*_\-]", password):
        return False, "Password must contain at least one special character (!@#$%^&*_-)."
    return True, ""


# Session helpers

def init_session() -> None:
    """Initialise session state keys if they do not already exist."""
    defaults = {
        "logged_in": False,
        "user_id": None,
        "username": None,
        "is_admin": False,
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def login(username: str, password: str) -> tuple[bool, str]:
    if not username or not password:
        return False, "Please enter both username and password."

    # Check lockout status before attempting verification
    lockout = _db.get_lockout_info(username)
    if lockout["is_locked"]:
        return False, (
            "This account has been temporarily locked due to too many failed "
            "login attempts. Please try again later or contact an administrator."
        )

    user = _db.verify_password(username, password)
    if user is None:
        attempts = _db.get_lockout_info(username)["failed_attempts"]
        remaining = max(0, 5 - attempts)
        if remaining == 0:
            return False, (
                "Account locked due to too many failed attempts. "
                "Please contact an administrator."
            )
        return False, (
            f"Invalid username or password. "
            f"{remaining} attempt(s) remaining before lockout."
        )

    # Populate session 
    st.session_state.logged_in = True
    st.session_state.user_id   = user["id"]
    st.session_state.username  = user["username"]
    st.session_state.is_admin  = bool(user["is_admin"])
    return True, ""


def logout() -> None:
    """Clear all session state keys to log the user out."""
    for key in ["logged_in", "user_id", "username", "is_admin"]:
        st.session_state[key] = None
    st.session_state.logged_in = False


def require_login() -> bool:
    """Return True if the current session is authenticated, else False."""
    return bool(st.session_state.get("logged_in"))


def require_admin() -> bool:
    """Return True if the current session belongs to an admin user."""
    return bool(st.session_state.get("is_admin"))


def get_current_user_id() -> int | None:
    """Return the user_id of the currently logged-in user."""
    return st.session_state.get("user_id")


def get_current_username() -> str | None:
    """Return the username of the currently logged-in user."""
    return st.session_state.get("username")