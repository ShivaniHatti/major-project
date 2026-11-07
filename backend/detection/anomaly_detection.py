"""Rule-based anomaly scoring for SentinelX event streams.

This module intentionally avoids claiming real ML behavior; it applies a
transparent scoring model to available telemetry and flags unusual patterns.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone

DEFAULT_ANOMALY_CONFIG = {
    "failed_login_threshold": 4,
    "source_ip_threshold": 3,
    "host_threshold": 5,
    "event_type_threshold": 0.7,
}


def _event_to_dict(event):
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
        record = _event_to_dict(event)
        if not record:
            continue
        if not record.get("event_type") and record.get("message"):
            record["event_type"] = "log_entry"
        normalized.append(record)
    return normalized


def _safe_float(value, default=0.0):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _score_anomaly(base_score, count, threshold):
    if threshold <= 0:
        return min(1.0, base_score)
    return min(1.0, max(0.0, (count / float(threshold)) * 0.8 + base_score * 0.2))


def detect_anomalies(events=None, config=None):
    """Return a list of anomaly records when suspicious patterns are detected.

    This is a deterministic scoring layer, not a trained ML model.
    """
    events = _normalize_events(events)
    config = dict(DEFAULT_ANOMALY_CONFIG, **(config or {}))

    if not events:
        return []

    anomalies = []
    seen = set()

    failure_counts_by_user = defaultdict(int)
    failure_counts_by_ip = defaultdict(int)
    host_counts = defaultdict(int)
    event_type_counts = Counter()

    for event in events:
        event_type = str(event.get("event_type") or "log_entry").lower()
        event_type_counts[event_type] += 1
        username = str(event.get("username") or "").strip()
        source_ip = str(event.get("source_ip") or "").strip()
        hostname = str(event.get("hostname") or "").strip()

        if event_type == "failed_login":
            if username:
                failure_counts_by_user[username] += 1
            if source_ip:
                failure_counts_by_ip[source_ip] += 1
        if hostname:
            host_counts[hostname] += 1

    for username, count in failure_counts_by_user.items():
        threshold = int(config["failed_login_threshold"])
        if count >= threshold:
            score = _score_anomaly(0.7, count, threshold)
            anomaly = {
                "anomaly_type": "login_frequency_spike",
                "severity": "high" if score >= 0.8 else "medium",
                "score": round(score, 2),
                "reason": f"User '{username}' generated {count} failed login events, which exceeds the configured threshold.",
                "username": username,
                "event_count": count,
            }
            key = (anomaly["anomaly_type"], username)
            if key not in seen:
                seen.add(key)
                anomalies.append(anomaly)

    for source_ip, count in failure_counts_by_ip.items():
        threshold = int(config["source_ip_threshold"])
        if count >= threshold:
            score = _score_anomaly(0.6, count, threshold)
            anomaly = {
                "anomaly_type": "source_ip_anomaly",
                "severity": "high" if score >= 0.8 else "medium",
                "score": round(score, 2),
                "reason": f"Source IP '{source_ip}' is associated with {count} failed login attempts.",
                "source_ip": source_ip,
                "event_count": count,
            }
            key = (anomaly["anomaly_type"], source_ip)
            if key not in seen:
                seen.add(key)
                anomalies.append(anomaly)

    for hostname, count in host_counts.items():
        threshold = int(config["host_threshold"])
        if count >= threshold:
            score = _score_anomaly(0.5, count, threshold)
            anomaly = {
                "anomaly_type": "host_activity_spike",
                "severity": "medium" if score >= 0.5 else "low",
                "score": round(score, 2),
                "reason": f"Host '{hostname}' generated {count} events, which is substantially higher than the baseline.",
                "hostname": hostname,
                "event_count": count,
            }
            key = (anomaly["anomaly_type"], hostname)
            if key not in seen:
                seen.add(key)
                anomalies.append(anomaly)

    total_events = float(len(events))
    if total_events > 1:
        for event_type, count in event_type_counts.items():
            share = count / total_events
            if count >= 2 and share >= _safe_float(config["event_type_threshold"], 0.7):
                anomaly = {
                    "anomaly_type": "event_type_concentration",
                    "severity": "medium" if share >= 0.8 else "low",
                    "score": round(min(1.0, share), 2),
                    "reason": f"Event type '{event_type}' represents {share:.0%} of the observed stream.",
                    "event_type": event_type,
                    "event_count": count,
                }
                key = (anomaly["anomaly_type"], event_type)
                if key not in seen:
                    seen.add(key)
                    anomalies.append(anomaly)

    return sorted(anomalies, key=lambda item: item.get("score", 0.0), reverse=True)


def score_anomalies(events=None, config=None):
    """Compatibility wrapper for detection anomaly scoring."""
    return detect_anomalies(events=events, config=config)

