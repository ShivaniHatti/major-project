from datetime import datetime, timedelta, timezone

from detection.anomaly_detection import detect_anomalies
from detection.rule_engine import run_rule_engine
from detection_engine import detect_brute_force
from extensions import db
from models import SecurityEvent


def _serialize_event(event):
    if hasattr(event, "to_dict"):
        return event.to_dict()
    if isinstance(event, dict):
        return event
    return {}


def _get_recent_event_records(window_minutes=10):
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
    events = SecurityEvent.query.filter(SecurityEvent.event_time >= cutoff).order_by(SecurityEvent.id.desc()).all()
    return [_serialize_event(event) for event in events if event is not None]


def _deduplicate_alerts(alerts):
    deduped = []
    seen = set()
    for alert in alerts or []:
        if not isinstance(alert, dict):
            continue
        key = (
            alert.get("rule") or alert.get("alert_type") or alert.get("anomaly_type"),
            alert.get("username"),
            alert.get("source_ip"),
            alert.get("hostname"),
            alert.get("event_count"),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(alert)
    return deduped


def evaluate_security_alerts(window_minutes=10, threshold=5):
    """Combine the legacy brute-force detector with explainable rule and anomaly checks."""
    recent_events = _get_recent_event_records(window_minutes=window_minutes)

    legacy_alerts = detect_brute_force(window_minutes=window_minutes, threshold=threshold)
    rule_alerts = run_rule_engine(
        recent_events,
        config={
            "failed_login_threshold": threshold,
            "failed_login_window_minutes": window_minutes,
            "suspicious_source_ip_threshold": max(2, min(5, threshold - 1)),
        },
        window_minutes=window_minutes,
    )
    anomaly_alerts = detect_anomalies(
        recent_events,
        config={
            "failed_login_threshold": threshold,
            "source_ip_threshold": max(2, min(5, threshold - 1)),
            "host_threshold": max(3, threshold),
        },
    )

    combined = legacy_alerts + rule_alerts + anomaly_alerts
    return _deduplicate_alerts(combined)


def run_brute_force_detection(window_minutes=10, threshold=5):
    """Run brute force detection by delegating to the existing detection engine."""
    return detect_brute_force(window_minutes=window_minutes, threshold=threshold)


def simulate_failed_logins(username="testuser", count=5):
    """Insert synthetic failed-login events for brute-force detection tests."""
    for i in range(count):
        event = SecurityEvent(
            source="simulation",
            event_type="failed_login",
            username=username,
            source_ip="192.168.1.100",
            hostname="test-machine",
            message=f"Simulated failed login attempt {i + 1}",
            severity="warning",
            event_time=datetime.now(timezone.utc),
        )
        db.session.add(event)

    db.session.commit()

    return {
        "message": "Five failed login events inserted successfully" if count == 5 else f"{count} failed login events inserted successfully",
        "username": username,
        "attempts": count,
    }
