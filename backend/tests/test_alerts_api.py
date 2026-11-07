import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from datetime import datetime, timedelta, timezone

from tests import TEST_DATABASE_URI
from app import app
from extensions import db
from models import SecurityEvent


class AlertsApiTests(unittest.TestCase):
    def setUp(self):
        self.app_context = app.app_context()
        self.app_context.push()
        db.drop_all()
        db.create_all()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def test_alerts_endpoint_returns_detection_results(self):
        self.assertIn('sentinelx-tests', app.config['SQLALCHEMY_DATABASE_URI'])
        self.assertNotIn('backend\\sentinelx.db', app.config['SQLALCHEMY_DATABASE_URI'])
        self.assertEqual(app.config['SQLALCHEMY_DATABASE_URI'], TEST_DATABASE_URI)

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

    def test_alerts_endpoint_captures_suspicious_ip_and_anomaly_results(self):
        now = datetime.now(timezone.utc)
        for i in range(4):
            db.session.add(SecurityEvent(
                source='linux',
                event_type='failed_login',
                username=f'user{i % 2}',
                source_ip='203.0.113.9',
                hostname='jumpbox',
                message=f'Failed password for user{i % 2} from 203.0.113.9',
                severity='warning',
                event_time=now - timedelta(minutes=i + 1),
            ))
        db.session.commit()

        client = app.test_client()
        response = client.get('/api/alerts')
        self.assertEqual(response.status_code, 200)

        payload = response.get_json()
        alert_types = {alert.get('alert_type') for alert in payload['alerts'] if isinstance(alert, dict)}
        anomaly_types = {alert.get('anomaly_type') for alert in payload['alerts'] if isinstance(alert, dict)}
        self.assertTrue(alert_types.intersection({'suspicious_source_ip', 'brute_force_attempt'}))
        self.assertTrue(anomaly_types.intersection({'source_ip_anomaly', 'event_type_concentration'}))

    def test_alerts_endpoint_ignores_normal_activity(self):
        now = datetime.now(timezone.utc)
        db.session.add(SecurityEvent(
            source='linux',
            event_type='login_success',
            username='normaluser',
            source_ip='10.0.0.5',
            hostname='web-01',
            message='Accepted password for normaluser',
            severity='info',
            event_time=now - timedelta(minutes=1),
        ))
        db.session.commit()

        client = app.test_client()
        response = client.get('/api/alerts')
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload['alert_count'], 0)
        self.assertEqual(payload['alerts'], [])
