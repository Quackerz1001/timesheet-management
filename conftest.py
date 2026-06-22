import os

os.environ.setdefault("SQLITE_DB_PATH", "./db")
os.environ.setdefault("SQLITE_DB", "test.db")
os.environ.setdefault("MAX_LOGIN_ATTEMPTS", "5")
os.environ.setdefault("LOCKOUT_MINUTES", "15")
os.environ.setdefault("SECRET_KEY", "test-secret-key-not-for-production")
os.environ.setdefault("ADMIN_PASSWORD", "Admin@1234!")
os.environ.setdefault("ALICE_PASSWORD", "Consult@99!")
os.environ.setdefault("BOB_PASSWORD", "Timesheet#7!")