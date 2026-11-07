"""Evidence registry and gap analysis for investigation workflows."""

from datetime import datetime, timezone


_EVIDENCE_STORE = []


def register_evidence(source, evidence_type, details, confidence=0.5, source_id=None, context=None):
    """Register a collected evidence artifact with weak provenance metadata."""
    entry = {
        "id": len(_EVIDENCE_STORE) + 1,
        "source": source,
        "type": evidence_type,
        "details": details or {},
        "confidence": float(confidence),
        "source_id": source_id,
        "context": context or {},
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    _EVIDENCE_STORE.append(entry)
    return entry


def get_available_evidence(limit=50):
    """Return the newest evidence entries."""
    return list(reversed(_EVIDENCE_STORE))[:limit]


def identify_missing_evidence(incident, evidence=None):
    """Infer evidence gaps from a security incident and evidence already acquired."""
    incident = incident or {}
    evidence = evidence or []
    existing_types = set()
    for item in evidence:
        if isinstance(item, dict):
            evidence_type = item.get("type") or item.get("evidence_type") or item.get("event_type")
            if evidence_type:
                existing_types.add(str(evidence_type))

    missing = []
    target_user = incident.get("username") or incident.get("user")
    target_ip = incident.get("source_ip") or incident.get("ip") or incident.get("src_ip")
    target_host = incident.get("hostname") or incident.get("host")

    if incident.get("alert_type") or incident.get("event_type"):
        if "failed_login" in str(incident.get("event_type") or incident.get("alert_type") or "").lower():
            if "failed_login" not in existing_types:
                missing.append({"type": "failed_login", "reason": "Review recent authentication failures for the affected user or environment."})
            if target_user and "user_activity" not in existing_types:
                missing.append({"type": "user_activity", "reason": "Inspect the affected user account and login telemetry."})
        if target_ip and "network_telemetry" not in existing_types:
            missing.append({"type": "network_telemetry", "reason": "Correlate the source IP with outbound or inbound network events."})

    if target_host and "host_telemetry" not in existing_types:
        missing.append({"type": "host_telemetry", "reason": "Review host-level telemetry for the impacted workload."})
    if not missing and incident:
        missing.append({"type": "contextual_evidence", "reason": "Gather additional contextual evidence relevant to the triggered incident."})

    return missing
