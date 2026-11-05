import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from datetime import datetime, timedelta, timezone

from app import app
from extensions import db
from models import SecurityEvent


class AlertsApiTests(unittest.TestCase):
    def test_alerts_endpoint_returns_detection_results(self):
        with app.app_context():
            db.drop_all()
            db.create_all()

            now = datetime.now(timezone.utc)
            for i in range(5):
                event = SecurityEvent(
                    source='simulation',
                    event_type='failed_login',
                    username='testuser',
                    source_ip=f'192.168.1.{i + 10}',
                    hostname='test-host',
                    message=f'Simulated failed login attempt {i + 1}',
                    severity='warning',
                    event_time=now - timedelta(minutes=1),
                )
                db.session.add(event)

            db.session.commit()

            client = app.test_client()
            response = client.get('/api/alerts')

            self.assertEqual(response.status_code, 200)
            payload = response.get_json()
            self.assertGreaterEqual(payload['alert_count'], 1)
            self.assertEqual(payload['alerts'][0]['alert_type'], 'brute_force_attempt')

            db.drop_all()
