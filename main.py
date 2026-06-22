from dotenv import load_dotenv

load_dotenv()

import streamlit as st  # noqa: E402
import frontendhandler  # noqa: E402
import auth  # noqa: E402


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
        # Show login page only
        nav = st.navigation(
            [st.Page(frontendhandler.login_page, title="Login")], position="hidden"
        )
    elif auth.require_admin():
        # Admins get both pages
        nav = st.navigation(
            [
                st.Page(frontendhandler.show_main_app, title="Timesheets", icon="📋"),
                st.Page(frontendhandler.show_admin_app, title="Admin", icon="🔧"),
            ]
        )
    else:
        # Regular users get the timesheet page only
        nav = st.navigation(
            [
                st.Page(frontendhandler.show_main_app, title="Timesheets", icon="📋"),
            ]
        )

    nav.run()


if __name__ == "__main__":
    main()
