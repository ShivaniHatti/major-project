from extensions import db
from models import SecurityEvent


def get_all_events():
    """
    Retrieve all security events ordered by ID descending.
    Preserves the exact query and ordering from the original GET /api/events endpoint.
    """
    return SecurityEvent.query.order_by(SecurityEvent.id.desc()).all()


def create_security_event(data):
    """
    Validate and persist a new security event.
    Preserves original validation rules, defaults, and returns the model instance.
    Raises ValueError if required fields are missing.
    """
    data = data or {}

    required_fields = ["event_type", "message"]
    if any(not data.get(field) for field in required_fields):
        raise ValueError("event_type and message are required")

    event = SecurityEvent(
        source=data.get("source", "manual"),
        event_type=data["event_type"],
        username=data.get("username"),
        source_ip=data.get("source_ip"),
        hostname=data.get("hostname"),
        message=data["message"],
        severity=data.get("severity", "info")
    )

    db.session.add(event)
    db.session.commit()

    return event
