"""Evaluate whether correlated evidence is sufficient to support a hypothesis."""


def _coerce_float(value, default=0.0):
    try:
        return float(value)
    except (TypeError, ValueError):
        return float(default)


def assess_hypotheses(correlations, hypotheses, evidence=None):
    if not hypotheses:
        return {
            "status": "inconclusive",
            "summary": "No viable hypothesis reached the evidence threshold.",
            "score": 0.0,
            "missing_evidence": [],
        }

    total_score = 0.0
    for hypothesis in hypotheses:
        support = _coerce_float(hypothesis.get("confidence", 0.0), 0.0)
        event_weight = min(1.0, float(hypothesis.get("supporting_events", 0)) / 5.0)
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

    missing_evidence = []
    if evidence:
        for item in evidence:
            if isinstance(item, dict) and item.get("type"):
                missing_evidence.append(item.get("type"))

    return {
        "status": status,
        "summary": summary,
        "score": round(average_score, 2),
        "hypothesis_count": len(hypotheses),
        "correlation_count": len(correlations or []),
        "missing_evidence": missing_evidence,
    }