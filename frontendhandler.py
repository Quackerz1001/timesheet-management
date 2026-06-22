"""
frontendhandler.py
------------------
All Streamlit page functions for the Timesheet Management application.

Pages:
    login_page        -- Public login screen.
    show_main_app     -- Timesheet management for regular users (and admins).
    show_admin_app    -- User management restricted to admin accounts.

Security notes:
    - All database calls go through DatabaseHandler which uses parameterised
      queries (OWASP A03 - Injection).
    - Authentication state is checked at the top of each protected page function;
      unauthenticated access is rejected even if the URL is guessed (OWASP A07).
    - Sensitive actions (delete) require an explicit confirmation checkbox before
      the destructive button is enabled.
    - Error messages shown to users are generic where appropriate; detailed
      errors are not surfaced to the UI.
"""

import streamlit as st

import auth
from databasehandler import DatabaseHandler
from validation import (
    validate_timesheet_form,
    validate_user_form,
)

_db = DatabaseHandler()


# Helpers


def _require_auth() -> bool:
    """
    Guard function for protected pages.
    Returns True if authenticated; shows a warning and returns False otherwise.
    """
    if not auth.require_login():
        st.warning("You must be logged in to view this page.")
        return False
    return True


def _require_admin_auth() -> bool:
    """
    Guard function for admin-only pages.
    Returns True if authenticated as admin; shows an error otherwise.
    """
    if not _require_auth():
        return False
    if not auth.require_admin():
        st.error("Access denied. Administrator privileges required.")
        return False
    return True


def _display_timesheets_table(rows) -> None:
    """Render a list of timesheet rows as a formatted Streamlit table."""
    if not rows:
        st.info("No timesheet entries found.")
        return

    data = []
    for row in rows:
        entry = {
            "ID": row["id"],
            "Date": row["date"],
            "Project": row["project_name"],
            "Hours": row["hours_spent"],
            "Notes": row["notes"] or "",
        }
        # Admin view includes the username column
        if "username" in row.keys():
            entry["User"] = row["username"]
        data.append(entry)

    st.dataframe(data, use_container_width=True)


# Login page


def login_page() -> None:
    """
    Public login page.

    Implements OWASP A07 controls:
        - Generic error messages (username/password not distinguished).
        - Account lockout feedback without disclosing internal state.
        - Session initialised on success with minimal data only.
    """
    auth.init_session()

    st.subheader("Please log in to continue")

    with st.form("login_form"):
        username = st.text_input("Username", max_chars=50)
        password = st.text_input("Password", type="password", max_chars=128)
        submitted = st.form_submit_button("Log In")

    if submitted:
        success, error_msg = auth.login(username, password)
        if success:
            st.success(f"Welcome back, {auth.get_current_username()}!")
            st.rerun()
        else:
            st.error(error_msg)


# Timesheet management page


def show_main_app() -> None:
    """
    Timesheet management page.

    Regular users see and manage their own entries only.
    Admins see all entries across all users.
    """
    if not _require_auth():
        return

    user_id = auth.get_current_user_id()
    username = auth.get_current_username()
    is_admin = auth.require_admin()

    st.subheader(f"Logged in as: **{username}**" + (" (Admin)" if is_admin else ""))

    # Logout button in the sidebar
    with st.sidebar:
        if st.button("Log Out", use_container_width=True):
            auth.logout()
            st.rerun()

    # Browse / View timesheets

    st.header("Timesheet Entries")

    if is_admin:
        rows = _db.read_all_timesheets()
        st.caption("Showing all entries (admin view)")
    else:
        rows = _db.read_timesheets_for_user(user_id)
        st.caption("Showing your entries")

    _display_timesheets_table(rows)

    st.divider()

    # Create timesheet entry
    st.header("Log Time")

    with st.form("create_timesheet_form", clear_on_submit=True):
        project_name = st.text_input(
            "Project Name", max_chars=100, placeholder="e.g. Cloud Migration - Phase 1"
        )
        col1, col2 = st.columns(2)
        with col1:
            hours_spent = st.number_input(
                "Hours Spent",
                min_value=0.5,
                max_value=24.0,
                value=8.0,
                step=0.5,
                format="%.1f",
            )
        with col2:
            import datetime

            entry_date = st.date_input("Date", value=datetime.date.today())

        notes = st.text_area(
            "Notes (optional)",
            max_chars=500,
            placeholder="Brief description of work done",
        )
        submitted = st.form_submit_button("Log Time")

    if submitted:
        valid, errors = validate_timesheet_form(
            project_name, hours_spent, entry_date, notes
        )
        if not valid:
            for err in errors:
                st.error(err)
        else:
            _db.create_timesheet(
                user_id=user_id,
                project_name=project_name.strip(),
                hours_spent=hours_spent,
                date=entry_date.isoformat(),
                notes=notes.strip(),
            )
            st.success(f"Logged {hours_spent}h to '{project_name}' on {entry_date}.")
            st.rerun()

    st.divider()

    # Update timesheet entry
    st.header("Edit an Entry")

    with st.form("update_timesheet_form"):
        ts_id_to_update = st.number_input("Timesheet ID to Edit", min_value=1, step=1)
        upd_project = st.text_input("Project Name", max_chars=100)
        col1, col2 = st.columns(2)
        with col1:
            upd_hours = st.number_input(
                "Hours Spent",
                min_value=0.5,
                max_value=24.0,
                value=8.0,
                step=0.5,
                format="%.1f",
            )
        with col2:
            import datetime

            upd_date = st.date_input(
                "Date", key="upd_date", value=datetime.date.today()
            )
        upd_notes = st.text_area("Notes (optional)", max_chars=500)
        update_submitted = st.form_submit_button("Update Entry")

    if update_submitted:
        existing = _db.read_timesheet(ts_id_to_update)
        if not existing:
            st.error("Timesheet entry not found.")
        elif not is_admin and existing["user_id"] != user_id:
            # Prevent users editing other users' entries (OWASP A01 - Broken Access Control)
            st.error("You do not have permission to edit this entry.")
        else:
            valid, errors = validate_timesheet_form(
                upd_project, upd_hours, upd_date, upd_notes
            )
            if not valid:
                for err in errors:
                    st.error(err)
            else:
                _db.update_timesheet(
                    ts_id_to_update,
                    upd_project.strip(),
                    upd_hours,
                    upd_date.isoformat(),
                    upd_notes.strip(),
                )
                st.success("Entry updated successfully.")
                st.rerun()

    st.divider()

    # Delete timesheet entry (with confirmation)
    st.header("Delete an Entry")

    ts_id_to_delete = st.number_input(
        "Timesheet ID to Delete", min_value=1, step=1, key="del_ts_id"
    )
    confirm_delete = st.checkbox("I confirm I want to delete this entry")

    if st.button("Delete Entry", disabled=not confirm_delete):
        existing = _db.read_timesheet(ts_id_to_delete)
        if not existing:
            st.error("Timesheet entry not found.")
        elif not is_admin and existing["user_id"] != user_id:
            st.error("You do not have permission to delete this entry.")
        else:
            _db.delete_timesheet(ts_id_to_delete)
            st.success("Entry deleted successfully.")
            st.rerun()


# Admin page — user management


def show_admin_app() -> None:
    """
    User management page — restricted to admin users.

    Implements OWASP A01 (Broken Access Control) by re-checking admin
    privileges server-side on every render, not relying solely on whether
    the nav item is visible.
    """
    if not _require_admin_auth():
        return

    # Logout button in the sidebar
    with st.sidebar:
        if st.button("Log Out", use_container_width=True, key="admin_logout"):
            auth.logout()
            st.rerun()

    # Browse all users
    st.header("All Users")

    users = _db.read_all_users()
    if users:
        user_data = [
            {
                "ID": u["id"],
                "Username": u["username"],
                "Admin": "Yes" if u["is_admin"] else "No",
                "Created": u["created_at"],
            }
            for u in users
        ]
        st.dataframe(user_data, use_container_width=True)
    else:
        st.info("No users found.")

    st.divider()

    # Create user
    st.header("Create User")

    with st.form("create_user_form", clear_on_submit=True):
        new_username = st.text_input("Username", max_chars=50)
        new_password = st.text_input(
            "Password", type="password", max_chars=128, help=auth.PASSWORD_POLICY
        )
        new_is_admin = st.checkbox("Grant admin privileges")
        create_submitted = st.form_submit_button("Create User")

    if create_submitted:
        valid, errors = validate_user_form(new_username, new_password)
        if not valid:
            for err in errors:
                st.error(err)
        else:
            existing = _db.read_user_by_username(new_username.strip())
            if existing:
                st.error("A user with that username already exists.")
            else:
                uid = _db.create_user(
                    new_username.strip(), new_password, is_admin=new_is_admin
                )
                st.success(f"User '{new_username}' created (ID: {uid}).")
                st.rerun()

    st.divider()

    # Update user
    st.header("Update User")

    with st.form("update_user_form"):
        upd_user_id = st.number_input("User ID to Update", min_value=1, step=1)
        upd_username = st.text_input("New Username", max_chars=50)
        upd_password = st.text_input(
            "New Password (leave blank to keep current)",
            type="password",
            max_chars=128,
            help=auth.PASSWORD_POLICY,
        )
        update_user_submitted = st.form_submit_button("Update User")

    if update_user_submitted:
        password_to_validate = upd_password if upd_password else None
        valid, errors = validate_user_form(upd_username, password_to_validate)
        if not valid:
            for err in errors:
                st.error(err)
        else:
            existing = _db.read_user(upd_user_id)
            if not existing:
                st.error("User not found.")
            else:
                _db.update_user(upd_user_id, upd_username.strip(), upd_password or None)
                st.success(f"User ID {upd_user_id} updated.")
                st.rerun()

    st.divider()

    # Unlock locked account
    st.header("Unlock Account")
    st.caption(
        "Use this to manually unlock an account locked due to failed login attempts."
    )

    with st.form("unlock_form"):
        unlock_user_id = st.number_input("User ID to Unlock", min_value=1, step=1)
        unlock_submitted = st.form_submit_button("Unlock Account")

    if unlock_submitted:
        target = _db.read_user(unlock_user_id)
        if not target:
            st.error("User not found.")
        else:
            _db.unlock_user(unlock_user_id)
            st.success(f"Account for '{target['username']}' has been unlocked.")

    st.divider()

    # Delete (soft) user
    st.header("Delete User")

    del_user_id = st.number_input(
        "User ID to Delete", min_value=1, step=1, key="del_uid"
    )
    confirm_del_user = st.checkbox("I confirm I want to delete this user")

    if st.button("Delete User", disabled=not confirm_del_user):
        target = _db.read_user(del_user_id)
        if not target:
            st.error("User not found.")
        elif target["username"] == auth.get_current_username():
            st.error("You cannot delete your own account.")
        else:
            _db.delete_user(del_user_id)
            st.success(f"User '{target['username']}' has been deleted.")
            st.rerun()
