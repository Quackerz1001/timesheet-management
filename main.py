"""
main.py
-------
Entry point for the Consulting Timesheet Management application.

Run with:
    streamlit run main.py

The app loads environment variables from a local .env file when running
locally, and from Streamlit secrets when deployed to Streamlit Community Cloud.
"""

import os

# Load .env for local development (has no effect on Streamlit Cloud)
from dotenv import load_dotenv
load_dotenv()

import streamlit as st
import frontendhandler
import auth


def main() -> None:
    st.set_page_config(
        page_title="Consulting Timesheet Management",
        page_icon="🕐",
        layout="wide",
        initial_sidebar_state="auto",
    )

    st.title("🕐 Consulting Timesheet Management")

    # Initialise session state on every run
    auth.init_session()

    if not auth.require_login():
        # Show login page only — no navigation
        nav = st.navigation(
            [st.Page(frontendhandler.login_page, title="Login")],
            position="hidden"
        )
    elif auth.require_admin():
        # Admins get both pages
        nav = st.navigation([
            st.Page(frontendhandler.show_main_app, title="Timesheets", icon="📋"),
            st.Page(frontendhandler.show_admin_app, title="Admin",      icon="🔧"),
        ])
    else:
        # Regular users get the timesheet page only
        nav = st.navigation([
            st.Page(frontendhandler.show_main_app, title="Timesheets", icon="📋"),
        ])

    nav.run()


if __name__ == "__main__":
    main()