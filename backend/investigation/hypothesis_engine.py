"""Generate competing incident hypotheses from correlated events."""


def generate_hypotheses(correlations, evidence=None):
    hypotheses = []
    for index, group in enumerate(correlations or [], start=1):
        key_type = group.get("key_type")
        value = group.get("value")
        event_count = group.get("event_count", 0)
        event_types = group.get("event_types", [])

        if "failed_login" in event_types and event_count >= 3:
            hypotheses.append({
                "id": "H{0}".format(index),
                "title": "Credential abuse against {0}".format(value),
                "description": "Multiple failed logins for {0} suggest attempted credential abuse or brute-force activity.".format(value),
                "confidence": min(0.95, 0.4 + (event_count * 0.12)),
                "supporting_events": event_count,
                "related_key": {"type": key_type, "value": value},
                "needs_evidence": ["failed_login", "user_activity", "network_telemetry"],
            })
        elif key_type == "source_ip" and event_count >= 2:
            hypotheses.append({
                "id": "H{0}".format(index),
                "title": "Suspicious activity from {0}".format(value),
                "description": "The same IP {0} is associated with multiple suspicious events across the monitored environment.".format(value),
                "confidence": min(0.9, 0.5 + (event_count * 0.1)),
                "supporting_events": event_count,
                "related_key": {"type": key_type, "value": value},
                "needs_evidence": ["network_telemetry", "host_telemetry"],
            })
        elif key_type == "username" and event_count >= 2:
            hypotheses.append({
                "id": "H{0}".format(index),
                "title": "User-focused anomaly for {0}".format(value),
                "description": "The user {0} appears in multiple related security events across hosts or sources.".format(value),
                "confidence": min(0.8, 0.45 + (event_count * 0.09)),
                "supporting_events": event_count,
                "related_key": {"type": key_type, "value": value},
                "needs_evidence": ["user_activity", "host_telemetry"],
            })

    if not hypotheses and evidence:
        hypotheses.append({
            "id": "H1",
            "title": "Unresolved incident with insufficient evidence",
            "description": "The incident is active but currently lacks enough corroborating telemetry to prefer one explanation.",
            "confidence": 0.35,
            "supporting_events": 1,
            "related_key": {"type": "context", "value": "incident"},
            "needs_evidence": ["contextual_evidence"],
        })

    return hypotheses