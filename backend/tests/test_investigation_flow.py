import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tests import TEST_DATABASE_URI
from app import app
from detection.event_correlation import correlate_events
from extensions import db
from detection.anomaly_detection import detect_anomalies
from detection.rule_engine import run_rule_engine
from investigation.evidence_manager import identify_missing_evidence
from investigation.evidence_sufficiency import assess_hypotheses
from investigation.hypothesis_engine import generate_hypotheses
from investigation.investigation_agent import run_investigation_cycle
from investigation.nbe_engine import DEFAULT_TOOL_LIBRARY, select_next_best_tool
from models import SecurityEvent
from services.event_service import create_security_event, get_event_stats, ingest_events


class InvestigationFlowTests(unittest.TestCase):
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

    def test_tool_selection_handles_failed_login_and_failed_tool_penalty(self):
        incident = {
            'event_type': 'failed_login',
            'username': 'dsmith',
            'source_ip': '10.9.9.44',
            'hostname': 'web-04',
        }

        selection = select_next_best_tool(
            incident,
            evidence=[],
            context={},
            available_tools=DEFAULT_TOOL_LIBRARY,
            failed_tools=['auth_log_review'],
        )

        self.assertEqual(selection['selected_tool'], 'Network flow analysis')
        self.assertTrue(any(item['type'] == 'network_telemetry' for item in selection['evidence_gap_addressed']))
        self.assertIn('next_recommended_investigation_action', selection)
        self.assertIn('risk_level', selection)

    def test_missing_evidence_and_hypothesis_assessment_handle_incomplete_data(self):
        incident = {'event_type': 'failed_login', 'username': 'alice', 'source_ip': '10.0.0.11'}
        missing = identify_missing_evidence(incident, evidence=[])
        self.assertTrue(any(item['type'] == 'failed_login' for item in missing))
        self.assertTrue(any(item['type'] == 'network_telemetry' for item in missing))

        assessment = assess_hypotheses([], [], evidence=[])
        self.assertEqual(assessment['status'], 'inconclusive')
        self.assertEqual(assessment['score'], 0.0)

        hypotheses = generate_hypotheses([], evidence=[])
        self.assertEqual(hypotheses, [])

    def test_investigation_cycle_integrates_correlation_tool_choice_and_event_service(self):
        now = datetime.now(timezone.utc)
        for i in range(3):
            db.session.add(SecurityEvent(
                source='linux',
                event_type='failed_login',
                username='alice',
                source_ip='10.0.0.11',
                hostname='web-server',
                message=f'Failed login for alice from 10.0.0.11 {i + 1}',
                severity='high',
                event_time=now - timedelta(minutes=i),
            ))
        db.session.commit()

        investigation = run_investigation_cycle(
            {'event_type': 'failed_login', 'username': 'alice', 'source_ip': '10.0.0.11'},
            context={'window_minutes': 60},
            evidence=[],
            available_tools=DEFAULT_TOOL_LIBRARY,
            failed_tools=[],
        )

        self.assertIn('tool_selection', investigation)
        self.assertIn('missing_evidence', investigation)
        self.assertTrue(investigation['hypotheses'])
        self.assertTrue(investigation['correlations'])

        created = create_security_event({
            'event_type': 'suspicious_data_transfer',
            'message': 'Large outbound transfer detected',
            'source_ip': '203.0.113.9',
            'hostname': 'finance-db',
            'severity': 'warning',
        })
        self.assertIsNotNone(created.id)

        stored = ingest_events([{'message': 'Failed password for bob from 10.10.10.9', 'source': 'linux'}], source='linux')
        self.assertEqual(len(stored), 1)
        stats = get_event_stats()
        self.assertGreaterEqual(stats['total_events'], 1)

    def test_rule_engine_detects_failed_login_burst_and_privilege_activity(self):
        records = [
            {
                'event_type': 'failed_login',
                'username': 'alice',
                'source_ip': '10.0.0.15',
                'hostname': 'web-1',
                'message': 'Failed password for alice from 10.0.0.15 port 22',
                'event_time': datetime.now(timezone.utc).isoformat(),
            }
            for _ in range(5)
        ]
        records.append({
            'event_type': 'privilege_escalation',
            'username': 'alice',
            'source_ip': '10.0.0.15',
            'hostname': 'web-1',
            'message': 'sudo: alice executed root command /bin/bash',
            'event_time': datetime.now(timezone.utc).isoformat(),
        })

        alerts = run_rule_engine(records, config={"failed_login_threshold": 3, "failed_login_window_minutes": 30})
        self.assertTrue(alerts)
        self.assertTrue(any(item['rule'] == 'failed_login_burst' for item in alerts))
        self.assertTrue(any(item['rule'] == 'privilege_activity' for item in alerts))

    def test_anomaly_detection_handles_missing_and_malformed_data(self):
        empty_result = detect_anomalies(None)
        self.assertEqual(empty_result, [])

        malformed = detect_anomalies(['not-a-dict', {'message': 'something'}])
        self.assertTrue(isinstance(malformed, list))

        records = [
            {
                'event_type': 'failed_login',
                'username': 'mallory',
                'source_ip': '203.0.113.9',
                'hostname': 'jumpbox',
                'message': 'Failed password for mallory from 203.0.113.9',
                'event_time': datetime.now(timezone.utc).isoformat(),
            }
            for _ in range(4)
        ]
        anomalies = detect_anomalies(records, config={"failed_login_threshold": 3, "source_ip_threshold": 2})
        self.assertTrue(anomalies)
        self.assertTrue(any(item['anomaly_type'] in {'login_frequency_spike', 'source_ip_anomaly'} for item in anomalies))


if __name__ == '__main__':
    unittest.main()
