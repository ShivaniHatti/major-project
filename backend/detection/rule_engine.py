"""Explainable, deterministic detection rules for SentinelX event streams."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone

DEFAULT_RULE_CONFIG = {
    "failed_login_threshold": 5,
    "failed_login_window_minutes": 10,
    "suspicious_login_window_minutes": 15,
    "suspicious_source_ip_threshold": 3,
    "privilege_keywords": (
        "sudo",
        "privilege",
        "role change",
        "administrator",
        "root",
        "admin",
    ),
}


def _to_event_dict(event):
    if event is None:
        return {}
    if hasattr(event, "to_dict"):
        return event.to_dict()
    if isinstance(event, dict):
        return event
    if isinstance(event, str):
        return {"message": event}
    return {}


def _coerce_datetime(value):
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        for fmt in (
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%d %H:%M:%S.%f%z",
            "%Y-%m-%d %H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
        ):
            try:
                parsed = datetime.strptime(text, fmt)
                return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)
            except ValueError:
                continue
    return None


def _normalize_events(events):
    if events is None:
        return []
    if isinstance(events, dict):
        events = [events]
    if not isinstance(events, (list, tuple, set)):
        return []

    normalized = []
    for event in events:
        record = _to_event_dict(event)
        if record:
            normalized.append(record)
    return normalized


def _event_matches_keyword(event, keywords):
    message = str(event.get("message") or event.get("details") or "").lower()
    if not message:
        return False
    return any(keyword.lower() in message for keyword in keywords)


def _add_alert(alerts, seen, rule_name, severity, reason, **details):
    key = (rule_name, details.get("username"), details.get("source_ip"), details.get("hostname"), details.get("event_count"))
    if key in seen:
        return
    seen.add(key)
    payload = {
        "alert_type": details.get("alert_type", rule_name),
        "rule": rule_name,
        "severity": severity,
        "reason": reason,
        "supporting_events": details.get("supporting_events", []),
    }
    for field_name in ("username", "source_ip", "hostname", "event_count", "first_seen", "last_seen"):
        if field_name in details:
            payload[field_name] = details[field_name]
    alerts.append(payload)


def run_rule_engine(events=None, config=None, window_minutes=None):
    """Return explainable rule-based detections derived from a list of events."""
    records = _normalize_events(events)
    config = dict(DEFAULT_RULE_CONFIG, **(config or {}))
    if window_minutes is not None:
        config["failed_login_window_minutes"] = int(window_minutes)

    if not records:
        return []

    alerts = []
    seen = set()
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=config["failed_login_window_minutes"])

    failed_by_user = defaultdict(list)
    failed_by_ip = defaultdict(list)
    for event in records:
        event_type = str(event.get("event_type") or "").lower()
        event_time = _coerce_datetime(event.get("event_time"))
        if event_time is None:
            event_time = datetime.now(timezone.utc)
        if event_type == "failed_login":
            username = str(event.get("username") or "unknown").strip() or "unknown"
            source_ip = str(event.get("source_ip") or "unknown").strip() or "unknown"
            failed_by_user[username].append((event_time, event))
            failed_by_ip[source_ip].append((event_time, event))

    for username, attempts in failed_by_user.items():
        recent = [entry for entry_time, entry in attempts if entry_time >= cutoff]
        if len(recent) >= int(config["failed_login_threshold"]):
            recent_times = [entry_time for entry_time, _ in attempts if entry_time >= cutoff]
            _add_alert(
                alerts,
                seen,
                "failed_login_burst",
                "high",
                f"{len(recent)} failed login attempts detected for {username} within the last {config['failed_login_window_minutes']} minutes.",
                alert_type="brute_force_attempt",
                username=username,
                source_ip=next((entry.get("source_ip") for _, entry in reversed(attempts) if entry.get("source_ip")), None),
                event_count=len(recent),
                supporting_events=[entry.get("message") for entry in recent[:5]],
                first_seen=min(recent_times).isoformat(),
                last_seen=max(recent_times).isoformat(),
            )

    for source_ip, attempts in failed_by_ip.items():
        recent = [entry for entry_time, entry in attempts if entry_time >= cutoff]
        if len(recent) >= int(config["suspicious_source_ip_threshold"]):
            recent_times = [entry_time for entry_time, _ in attempts if entry_time >= cutoff]
            _add_alert(
                alerts,
                seen,
                "suspicious_source_ip",
                "medium",
                f"Source IP {source_ip} generated {len(recent)} failed login events in a short interval.",
                alert_type="suspicious_source_ip",
                username=next((entry.get("username") for _, entry in reversed(attempts) if entry.get("username")), None),
                source_ip=source_ip,
                event_count=len(recent),
                supporting_events=[entry.get("message") for entry in recent[:5]],
                first_seen=min(recent_times).isoformat(),
                last_seen=max(recent_times).isoformat(),
            )

    for event in records:
        event_type = str(event.get("event_type") or "").lower()
        if event_type in {"login_success", "privilege_escalation", "role_change", "user_activity"}:
            message = str(event.get("message") or "")
            if _event_matches_keyword(event, config["privilege_keywords"]):
                _add_alert(
                    alerts,
                    seen,
                    "privilege_activity",
                    "high",
                    "Privileged or administrative activity was detected in the event stream.",
                    alert_type="privilege_activity",
                    username=event.get("username"),
                    source_ip=event.get("source_ip"),
                    hostname=event.get("hostname"),
                    event_count=1,
                    supporting_events=[message],
                )

    # Suspicious success after a burst of failures.
    for event in records:
        if str(event.get("event_type") or "").lower() != "login_success":
            continue
        username = str(event.get("username") or "").strip()
        source_ip = str(event.get("source_ip") or "").strip()
        if not username and not source_ip:
            continue
        suspicious_context = False
        if username in failed_by_user and len([entry for entry_time, entry in failed_by_user[username] if entry_time >= cutoff]) >= max(2, int(config["failed_login_threshold"]) // 2):
            suspicious_context = True
        if source_ip in failed_by_ip and len([entry for entry_time, entry in failed_by_ip[source_ip] if entry_time >= cutoff]) >= max(2, int(config["suspicious_source_ip_threshold"])):
            suspicious_context = True
        if suspicious_context:
            _add_alert(
                alerts,
                seen,
                "suspicious_login_after_failures",
                "medium",
                f"Successful login for {username or source_ip} followed a recent burst of failed authentication attempts.",
                alert_type="suspicious_login_after_failures",
                username=username or None,
                source_ip=source_ip or None,
                hostname=event.get("hostname"),
                event_count=1,
                supporting_events=[event.get("message")],
            )

    return alerts


def evaluate_security_rules(events=None, config=None, window_minutes=None):
    """Compatibility wrapper for the rule engine API."""
    return run_rule_engine(events=events, config=config, window_minutes=window_minutes)


def detect_security_rules(events=None, config=None, window_minutes=None):
    return run_rule_engine(events=events, config=config, window_minutes=window_minutes)

