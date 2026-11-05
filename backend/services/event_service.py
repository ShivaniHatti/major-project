from datetime import datetime, timezone

from extensions import db
from models import SecurityEvent
from processing.normalizer import normalize_event


def _coerce_event_time(value):
    if value is None:
        return datetime.now(timezone.utc)
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value)
            if parsed.tzinfo is None:
                return parsed.replace(tzinfo=timezone.utc)
            return parsed
        except ValueError:
            return datetime.now(timezone.utc)
    return datetime.now(timezone.utc)


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
        severity=data.get("severity", "info"),
        event_time=_coerce_event_time(data.get("event_time"))
    )

    db.session.add(event)
    db.session.commit()

    return event


def ingest_events(raw_events, source="manual"):
    """Normalize and persist one or more event records from a source."""
    if raw_events is None:
        return []

    if isinstance(raw_events, dict):
        raw_events = [raw_events]

    stored_events = []
    for record in raw_events:
        normalized = normalize_event(record, source=source)
        event = SecurityEvent(
            source=normalized.get("source", source),
            event_type=normalized["event_type"],
            username=normalized.get("username"),
            source_ip=normalized.get("source_ip"),
            hostname=normalized.get("hostname"),
            message=normalized["message"],
            severity=normalized.get("severity", "info"),
            event_time=_coerce_event_time(normalized.get("event_time"))
        )
        db.session.add(event)
        stored_events.append(event)

    db.session.commit()
    return stored_events


def get_event_stats():
    source_counts = db.session.query(
        SecurityEvent.source,
        db.func.count(SecurityEvent.id)
    ).group_by(SecurityEvent.source).all()

    severity_counts = db.session.query(
        SecurityEvent.severity,
        db.func.count(SecurityEvent.id)
    ).group_by(SecurityEvent.severity).all()

    return {
        "by_source": {source: count for source, count in source_counts},
        "by_severity": {severity: count for severity, count in severity_counts},
        "total_events": SecurityEvent.query.count()
    }
