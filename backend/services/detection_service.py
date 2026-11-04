from datetime import datetime, timezone
from extensions import db
from models import SecurityEvent
from detection_engine import detect_brute_force


def run_brute_force_detection(window_minutes=10, threshold=5):
    """
    Run brute force detection by delegating directly to the existing detection engine.
    Preserves original detection logic, parameters, and return format.
    """
    return detect_brute_force(window_minutes=window_minutes, threshold=threshold)


def simulate_failed_logins(username="testuser", count=5):
    """
    Insert synthetic failed login events for testing brute force detection.
    Preserves original simulation fields, defaults, and UTC timestamp generation.
    """
    for i in range(count):
        event = SecurityEvent(
            source="simulation",
            event_type="failed_login",
            username=username,
            source_ip="192.168.1.100",
            hostname="test-machine",
            message=f"Simulated failed login attempt {i + 1}",
            severity="warning",
            event_time=datetime.now(timezone.utc)
        )
        db.session.add(event)

    db.session.commit()

    return {
        "message": "Five failed login events inserted successfully" if count == 5 else f"{count} failed login events inserted successfully",
        "username": username,
        "attempts": count
    }
