import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tests import TEST_DATABASE_URI
from app import app
from extensions import db
from collectors.file_collector import FileCollector
from processing.normalizer import normalize_event
from services.event_service import ingest_events


class EventIngestionPipelineTests(unittest.TestCase):
    def setUp(self):
        self.assertIn('sentinelx-tests', app.config['SQLALCHEMY_DATABASE_URI'])
        self.assertNotIn('backend\\sentinelx.db', app.config['SQLALCHEMY_DATABASE_URI'])
        self.assertEqual(app.config['SQLALCHEMY_DATABASE_URI'], TEST_DATABASE_URI)
        self.app_context = app.app_context()
        self.app_context.push()
        db.drop_all()
        db.create_all()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def test_normalize_linux_failed_login_event(self):
        record = {
            "source": "linux",
            "message": "Jan 15 12:00:00 webserver sshd[1111]: Failed password for invalid user alice from 10.0.0.5 port 22 ssh2"
        }

        event = normalize_event(record, source="linux")

        self.assertEqual(event["event_type"], "failed_login")
        self.assertEqual(event["username"], "alice")
        self.assertEqual(event["source_ip"], "10.0.0.5")
        self.assertEqual(event["severity"], "high")

    def test_collect_and_store_file_logs(self):
        with TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "auth.log"
            log_path.write_text(
                "Jan 15 12:10:00 webserver sshd[2222]: Accepted password for bob from 10.0.0.7 port 22 ssh2\n",
                encoding="utf-8",
            )

            collector = FileCollector(allowed_roots=[Path(temp_dir)])
            records = collector.collect(log_path)

            self.assertEqual(len(records), 1)
            stored_events = ingest_events(records, source="file")

            self.assertEqual(len(stored_events), 1)
            self.assertEqual(stored_events[0].event_type, "login_success")
            self.assertEqual(stored_events[0].username, "bob")


if __name__ == "__main__":
    unittest.main()
