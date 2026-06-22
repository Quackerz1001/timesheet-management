import re
from datetime import date

# Username

USERNAME_MIN = 3
USERNAME_MAX = 50
# Allow alphanumeric characters, dots, underscores, and hyphens
_USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9._\-]{3,50}$")


def validate_username(username: str) -> tuple[bool, str]:
    if not username or not username.strip():
        return False, "Username cannot be empty."
    username = username.strip()
    if not _USERNAME_PATTERN.match(username):
        return False, (
            f"Username must be {USERNAME_MIN}–{USERNAME_MAX} characters and may only "
            "contain letters, numbers, dots, underscores, and hyphens."
        )
    return True, ""


# Project name

PROJECT_MIN = 2
PROJECT_MAX = 100


def validate_project_name(name: str) -> tuple[bool, str]:
    """
    Validate a project name.

    Rules:
        - Between 2 and 100 characters.
        - Must not be only whitespace.
    """
    if not name or not name.strip():
        return False, "Project name cannot be empty."
    stripped = name.strip()
    if len(stripped) < PROJECT_MIN:
        return False, f"Project name must be at least {PROJECT_MIN} characters."
    if len(stripped) > PROJECT_MAX:
        return False, f"Project name must not exceed {PROJECT_MAX} characters."
    return True, ""


# Hours

HOURS_MIN = 0.5
HOURS_MAX = 24.0


def validate_hours(hours: float) -> tuple[bool, str]:
    if hours < HOURS_MIN or hours > HOURS_MAX:
        return False, f"Hours must be between {HOURS_MIN} and {HOURS_MAX}."
    if (hours * 2) % 1 != 0:
        return False, "Hours must be in increments of 0.5 (e.g. 1.0, 1.5, 2.0)."
    return True, ""


# Date

_DATE_MIN = date(2000, 1, 1)


def validate_date(entry_date: date) -> tuple[bool, str]:
    today = date.today()
    if entry_date > today:
        return False, "Date cannot be in the future."
    if entry_date < _DATE_MIN:
        return False, "Date cannot be before 1 January 2000."
    return True, ""


# Notes (optional)

NOTES_MAX = 500


def validate_notes(notes: str) -> tuple[bool, str]:
    """
    Validate optional notes field.

    Rules:
        - Maximum 500 characters.
    """
    if notes and len(notes) > NOTES_MAX:
        return False, f"Notes must not exceed {NOTES_MAX} characters."
    return True, ""


# validators


def validate_timesheet_form(
    project_name: str, hours: float, entry_date: date, notes: str
) -> tuple[bool, list[str]]:
    errors = []
    checks = [
        validate_project_name(project_name),
        validate_hours(hours),
        validate_date(entry_date),
        validate_notes(notes),
    ]
    for ok, msg in checks:
        if not ok:
            errors.append(msg)
    return (len(errors) == 0), errors


def validate_user_form(username: str, password: str | None) -> tuple[bool, list[str]]:
    from auth import validate_password_strength

    errors = []
    ok, msg = validate_username(username)
    if not ok:
        errors.append(msg)

    if password is not None:
        ok, msg = validate_password_strength(password)
        if not ok:
            errors.append(msg)

    return (len(errors) == 0), errors
