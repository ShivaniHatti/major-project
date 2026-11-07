"""Correlate events by user, IP, device, and time."""

from collections import defaultdict
from datetime import datetime, timedelta, timezone

from models import SecurityEvent


def correlate_events(window_minutes=30, max_events=200):
    """Group security events by shared identifiers and time proximity."""
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
    events = SecurityEvent.query.filter(
        SecurityEvent.event_time >= cutoff
    ).order_by(SecurityEvent.event_time.desc()).limit(max_events).all()

    grouped = defaultdict(list)
    for event in events:
        keys = []
        if event.username:
            keys.append(("username", event.username))
        if event.source_ip:
            keys.append(("source_ip", event.source_ip))
        if event.hostname:
            keys.append(("hostname", event.hostname))

        if not keys:
            continue

        for key_type, value in keys:
            grouped[(key_type, value)].append(event)

    correlations = []
    for (key_type, value), related_events in grouped.items():
        if len(related_events) < 2:
            continue

        related_events.sort(key=lambda item: item.event_time or datetime.now(timezone.utc))
        severity_order = {"info": 1, "low": 2, "warning": 3, "high": 4, "critical": 5}
        correlation = {
            "key_type": key_type,
            "value": value,
            "event_count": len(related_events),
            "event_types": sorted({event.event_type for event in related_events}),
            "severity": max((event.severity for event in related_events), key=lambda s: severity_order.get((s or "info").lower(), 0)),
            "first_seen": related_events[0].event_time.isoformat() if related_events[0].event_time else None,
            "last_seen": related_events[-1].event_time.isoformat() if related_events[-1].event_time else None,
            "sample_messages": [event.message for event in related_events[:3]],
        }
        correlations.append(correlation)

    return sorted(correlations, key=lambda item: item["event_count"], reverse=True)