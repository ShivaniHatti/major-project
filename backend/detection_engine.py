
from datetime import datetime, timedelta, timezone

from models import SecurityEvent


def detect_brute_force(window_minutes=10, threshold=5):
    """
    Detect users with 5 or more failed logins
    within the last 10 minutes.
    """

    cutoff_time = datetime.now(timezone.utc) - timedelta(
        minutes=window_minutes
    )

    failed_events = SecurityEvent.query.filter(
        SecurityEvent.event_type == "failed_login",
        SecurityEvent.event_time >= cutoff_time
    ).all()

    user_attempts = {}

    for event in failed_events:
        username = event.username or "unknown"

        user_attempts[username] = (
            user_attempts.get(username, 0) + 1
        )

    alerts = []

    for username, attempts in user_attempts.items():
        if attempts >= threshold:
            alerts.append({
                "alert_type": "brute_force_attempt",
                "username": username,
                "attempts": attempts,
                "severity": "high",
                "reason": (
                    f"{attempts} failed login attempts "
                    f"within {window_minutes} minutes"
                )
            })

    return alerts
