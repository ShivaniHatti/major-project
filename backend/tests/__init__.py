import os
import tempfile
import uuid
from pathlib import Path

BASE_DIR = Path(tempfile.gettempdir()) / "sentinelx-tests"
BASE_DIR.mkdir(exist_ok=True)
TEST_DATABASE_PATH = BASE_DIR / f"sentinelx-{uuid.uuid4().hex}.db"
TEST_DATABASE_URI = f"sqlite:///{TEST_DATABASE_PATH}"

os.environ["DATABASE_URL"] = TEST_DATABASE_URI
os.environ.setdefault("SENTINELX_ENV", "development")
os.environ.setdefault("SESSION_COOKIE_SECURE", "false")
