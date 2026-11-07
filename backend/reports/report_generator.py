"""Generate structured investigation reports from live backend evidence."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

from detection.event_correlation import correlate_events
from detection.anomaly_detection import detect_anomalies
from detection.rule_engine import run_rule_engine
from investigation.evidence_manager import get_available_evidence, identify_missing_evidence
from investigation.evidence_sufficiency import assess_hypotheses
from investigation.hypothesis_engine import generate_hypotheses
from investigation.nbe_engine import select_next_best_tool
from models import SecurityEvent
from services.detection_service import evaluate_security_alerts


def _serialize_event(event):
    if event is None:
        return {}
    if hasattr(event, "to_dict"):
        return event.to_dict()
    if isinstance(event, dict):
        return event
    return {}


def _recent_event_records(incident=None, context=None, limit=25):
    context = context or {}
    window_minutes = int(context.get("window_minutes") or 30)
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
    query = SecurityEvent.query.filter(SecurityEvent.event_time >= cutoff)

    incident = incident or {}
    username = str(incident.get("username") or incident.get("user") or "").strip()
    source_ip = str(incident.get("source_ip") or incident.get("ip") or incident.get("src_ip") or "").strip()
    hostname = str(incident.get("hostname") or incident.get("host") or "").strip()

    if username:
        query = query.filter(SecurityEvent.username == username)
    if source_ip:
        query = query.filter(SecurityEvent.source_ip == source_ip)
    if hostname:
        query = query.filter(SecurityEvent.hostname == hostname)

    events = query.order_by(SecurityEvent.event_time.desc(), SecurityEvent.id.desc()).limit(limit).all()
    return [_serialize_event(event) for event in events]


def _build_incident_summary(incident, alerts=None):
    incident = incident or {}
    alerts = alerts or []
    summary = {
        "event_type": incident.get("event_type") or incident.get("alert_type") or (alerts[0].get("alert_type") if alerts and isinstance(alerts[0], dict) else "security_incident"),
        "source_ip": incident.get("source_ip") or incident.get("ip") or incident.get("src_ip"),
        "username": incident.get("username") or incident.get("user"),
        "hostname": incident.get("hostname") or incident.get("host"),
        "severity": incident.get("severity") or max((alert.get("severity") for alert in alerts if isinstance(alert, dict) and alert.get("severity")), default="unknown", key=lambda value: ["info", "low", "warning", "high", "critical"].index(value.lower()) if isinstance(value, str) and value.lower() in ["info", "low", "warning", "high", "critical"] else -1),
    }
    description = []
    if summary["username"]:
        description.append(f"User {summary['username']}")
    if summary["source_ip"]:
        description.append(f"source IP {summary['source_ip']}")
    if summary["hostname"]:
        description.append(f"host {summary['hostname']}")
    description.append("is under investigation due to suspicious security activity.")
    summary["description"] = " ".join(description)
    return summary


def _build_recommendations(missing_evidence, tool_selection, hypotheses):
    recommendations = []
    for item in missing_evidence:
        if isinstance(item, dict):
            reason = item.get("reason") or item.get("type")
            if reason:
                recommendations.append(f"Collect missing evidence: {reason}")
    if tool_selection and isinstance(tool_selection, dict):
        action = tool_selection.get("next_recommended_investigation_action")
        if action:
            recommendations.append(action)
    if hypotheses:
        top_hypothesis = hypotheses[0]
        title = top_hypothesis.get("title")
        if title:
            recommendations.append(f"Prioritize validation of hypothesis: {title}")
    if not recommendations:
        recommendations.append("Continue monitoring the affected environment and re-run the investigation when new telemetry arrives.")
    return recommendations


def generate_investigation_report(incident=None, context=None, evidence=None, available_tools=None, failed_tools=None):
    """Return a structured investigation report from the current backend evidence state."""
    incident = incident or {}
    context = context or {}
    evidence = evidence or []

    window_minutes = int(context.get("window_minutes") or 30)
    recent_events = _recent_event_records(incident=incident, context=context)
    if not evidence and recent_events:
        evidence = recent_events

    alerts = evaluate_security_alerts(window_minutes=window_minutes, threshold=int(context.get("threshold") or 5))
    if incident and recent_events:
        rule_alerts = run_rule_engine(recent_events, config={"failed_login_threshold": int(context.get("threshold") or 5), "failed_login_window_minutes": window_minutes}, window_minutes=window_minutes)
        anomaly_alerts = detect_anomalies(recent_events, config={"failed_login_threshold": int(context.get("threshold") or 5), "source_ip_threshold": max(2, min(5, int(context.get("threshold") or 5) - 1))})
        alerts = list(alerts) + list(rule_alerts) + list(anomaly_alerts)
        deduped = []
        seen = set()
        for alert in alerts:
            if not isinstance(alert, dict):
                continue
            key = (
                alert.get("rule") or alert.get("alert_type") or alert.get("anomaly_type"),
                alert.get("username"),
                alert.get("source_ip"),
                alert.get("hostname"),
                alert.get("event_count"),
            )
            if key in seen:
                continue
            seen.add(key)
            deduped.append(alert)
        alerts = deduped

    correlations = correlate_events(window_minutes=window_minutes)
    hypotheses = generate_hypotheses(correlations, evidence)
    evidence_assessment = assess_hypotheses(correlations, hypotheses, evidence)
    missing_evidence = identify_missing_evidence(incident, evidence)
    tool_selection = select_next_best_tool(
        incident,
        evidence=evidence,
        context=context,
        available_tools=available_tools,
        failed_tools=failed_tools,
    )

    report_id = f"sentinelx-report-{uuid4().hex[:12]}"
    generated_at = datetime.now(timezone.utc).isoformat()
    evidence_inventory = []
    for event in recent_events:
        evidence_inventory.append({
            "type": event.get("event_type") or "security_event",
            "source": event.get("source") or "unknown",
            "severity": event.get("severity") or "info",
            "username": event.get("username"),
            "source_ip": event.get("source_ip"),
            "hostname": event.get("hostname"),
            "message": event.get("message"),
            "timestamp": event.get("event_time"),
            "confidence": 0.7,
        })
    evidence_inventory.extend(list(get_available_evidence(limit=20)))

    limitations = []
    if not recent_events:
        limitations.append("No recent security events were available for the requested investigation window.")
    if not hypotheses:
        limitations.append("No high-confidence hypothesis was generated from the current event set.")
    if not alerts:
        limitations.append("No alerting thresholds were triggered for the current evidence set.")
    if not limitations:
        limitations.append("The report reflects the current evidence scope and should be re-evaluated as new telemetry arrives.")

    report = {
        "report_id": report_id,
        "generated_at": generated_at,
        "incident_summary": _build_incident_summary(incident, alerts),
        "alerts": alerts,
        "supporting_security_events": recent_events,
        "evidence_inventory": evidence_inventory,
        "missing_evidence": missing_evidence,
        "competing_hypotheses": hypotheses,
        "confidence_and_uncertainty": {
            "status": evidence_assessment.get("status", "inconclusive"),
            "score": evidence_assessment.get("score", 0.0),
            "summary": evidence_assessment.get("summary", "Insufficient evidence to support a firm conclusion."),
            "missing_evidence": evidence_assessment.get("missing_evidence", []),
        },
        "next_best_evidence": tool_selection,
        "recommended_actions": _build_recommendations(missing_evidence, tool_selection, hypotheses),
        "investigation_limitations": limitations,
    }
    return report
""
