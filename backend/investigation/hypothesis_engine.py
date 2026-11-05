"""Generate competing incident hypotheses from correlated events."""

from __future__ import annotations


def generate_hypotheses(correlations):
    hypotheses = []
    for index, group in enumerate(correlations or [], start=1):
        key_type = group.get("key_type")
        value = group.get("value")
        event_count = group.get("event_count", 0)
        event_types = group.get("event_types", [])

        if "failed_login" in event_types and event_count >= 3:
            hypotheses.append({
                "id": f"H{index}",
                "title": f"Credential abuse against {value}",
                "description": f"Multiple failed logins for {value} suggest attempted credential abuse or brute-force activity.",
                "confidence": min(0.95, 0.4 + (event_count * 0.12)),
                "supporting_events": event_count,
                "related_key": {"type": key_type, "value": value},
            })
        elif key_type == "source_ip" and event_count >= 2:
            hypotheses.append({
                "id": f"H{index}",
                "title": f"Suspicious activity from {value}",
                "description": f"The same IP {value} is associated with multiple suspicious events across the monitored environment.",
                "confidence": min(0.9, 0.5 + (event_count * 0.1)),
                "supporting_events": event_count,
                "related_key": {"type": key_type, "value": value},
            })
        elif key_type == "username" and event_count >= 2:
            hypotheses.append({
                "id": f"H{index}",
                "title": f"User-focused anomaly for {value}",
                "description": f"The user {value} appears in multiple related security events across hosts or sources.",
                "confidence": min(0.8, 0.45 + (event_count * 0.09)),
                "supporting_events": event_count,
                "related_key": {"type": key_type, "value": value},
            })

    return hypotheses