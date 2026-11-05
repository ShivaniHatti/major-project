import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import app
from detection.event_correlation import correlate_events
from extensions import db
from investigation.hypothesis_engine import generate_hypotheses
from models import SecurityEvent


class InvestigationFlowTests(unittest.TestCase):
    def setUp(self):
        self.app_context = app.app_context()
        self.app_context.push()
        db.drop_all()
        db.create_all()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def test_correlation_groups_related_events(self):
        now = datetime.now(timezone.utc)
        for i in range(4):
            db.session.add(SecurityEvent(
                source='linux',
                event_type='failed_login',
                username='alice',
                source_ip='10.0.0.11',
                hostname='web-server',
                message=f'Failed password for alice from 10.0.0.11 port 22 ssh2 {i + 1}',
                severity='high',
                event_time=now - timedelta(minutes=i),
            ))

        db.session.commit()
        correlations = correlate_events(window_minutes=60)

        self.assertGreater(len(correlations), 0)
        self.assertGreater(correlations[0]['event_count'], 1)

    def test_hypothesis_generation_returns_case_summary(self):
        correlations = [{
            'key_type': 'username',
            'value': 'alice',
            'event_count': 4,
            'event_types': ['failed_login'],
        }]

        hypotheses = generate_hypotheses(correlations)

        self.assertTrue(hypotheses)
        self.assertIn('Credential abuse', hypotheses[0]['title'])


if __name__ == '__main__':
    unittest.main()
