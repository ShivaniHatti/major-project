"""Evaluate whether correlated evidence is sufficient to support a hypothesis."""

from __future__ import annotations


def assess_hypotheses(correlations, hypotheses):
    if not hypotheses:
        return {
            "status": "inconclusive",
            "summary": "No viable hypothesis reached the evidence threshold.",
            "score": 0.0,
        }

    total_score = 0.0
    for hypothesis in hypotheses:
        support = float(hypothesis.get("confidence", 0.0))
        event_weight = min(1.0, (hypothesis.get("supporting_events", 0) / 5.0))
        total_score += support * 0.7 + event_weight * 0.3

    average_score = total_score / len(hypotheses)

    if average_score >= 0.75:
        status = "supported"
        summary = "The evidence strongly supports the leading hypothesis."
    elif average_score >= 0.5:
        status = "likely"
        summary = "The evidence supports the leading hypothesis but additional checks may still be needed."
    else:
        status = "inconclusive"
        summary = "The evidence remains inconclusive and should be supplemented with additional telemetry."

    return {
        "status": status,
        "summary": summary,
        "score": round(average_score, 2),
        "hypothesis_count": len(hypotheses),
        "correlation_count": len(correlations or []),
    }