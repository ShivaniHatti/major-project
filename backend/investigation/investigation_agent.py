"""Coordinate the alert-to-evidence workflow for SentinelX investigations."""

from detection.event_correlation import correlate_events
from investigation.evidence_manager import get_available_evidence, identify_missing_evidence
from investigation.evidence_sufficiency import assess_hypotheses
from investigation.hypothesis_engine import generate_hypotheses
from investigation.nbe_engine import select_next_best_tool


def run_investigation_cycle(incident, context=None, evidence=None, available_tools=None, failed_tools=None):
    """Run the investigation lifecycle from alert to next-best tool selection."""
    context = context or {}
    incident = incident or {}
    if evidence is None:
        evidence = get_available_evidence()

    correlations = correlate_events(window_minutes=context.get("window_minutes", 30))
    hypotheses = generate_hypotheses(correlations, evidence)
    evidence_assessment = assess_hypotheses(correlations, hypotheses, evidence)
    missing_evidence = identify_missing_evidence(incident, evidence)
    tool_selection = select_next_best_tool(incident, evidence=evidence, context=context, available_tools=available_tools, failed_tools=failed_tools)

    return {
        "incident": incident,
        "context": context,
        "evidence": evidence,
        "correlations": correlations,
        "hypotheses": hypotheses,
        "evidence_assessment": evidence_assessment,
        "missing_evidence": missing_evidence,
        "tool_selection": tool_selection,
    }
