
"""Select the next-best investigation tool using a transparent scoring model."""

from __future__ import annotations


# Default tools used by the existing investigation engine.
DEFAULT_TOOLS = [
    {
        "name": "credential_review",
        "category": "identity",
        "cost": 3,
        "risk": 2,
        "relevance": 8,
    },
    {
        "name": "endpoint_forensics",
        "category": "endpoint",
        "cost": 5,
        "risk": 4,
        "relevance": 7,
    },
    {
        "name": "network_trace",
        "category": "network",
        "cost": 4,
        "risk": 5,
        "relevance": 6,
    },
    {
        "name": "memory_snapshot",
        "category": "host",
        "cost": 6,
        "risk": 3,
        "relevance": 5,
    },
    {
        "name": "log_correlation",
        "category": "log",
        "cost": 2,
        "risk": 1,
        "relevance": 9,
    },
]


# Tool library used by investigation-flow integration.
DEFAULT_TOOL_LIBRARY = [
    {
        "name": "auth_log_review",
        "category": "identity",
        "cost": 2,
        "risk": 1,
        "relevance": 10,
    },
    {
        "name": "network_flow_analysis",
        "category": "network",
        "cost": 4,
        "risk": 3,
        "relevance": 8,
    },
    {
        "name": "endpoint_forensics",
        "category": "endpoint",
        "cost": 5,
        "risk": 5,
        "relevance": 6,
    },
]


def _score_tool(tool, context):
    """Calculate a transparent investigation-tool score."""

    relevance = float(tool.get("relevance", 0) or 0)
    cost = float(tool.get("cost", 5) or 5)
    risk = float(tool.get("risk", 5) or 5)

    failure_penalty = 0.0
    used_tools = set(context.get("used_tools") or [])

    if tool.get("name") in used_tools:
        failure_penalty = 25.0

    evidence = context.get("evidence") or {}
    warning = str(context.get("warning") or "").lower()
    hypothesis = str(context.get("hypothesis") or "").lower()

    tool_name = str(tool.get("name", "")).lower()

    if "credential" in tool_name or "auth" in tool_name:
        if (
            "username" in evidence
            or "account" in evidence
            or "credential" in hypothesis
            or "failed_login" in str(evidence).lower()
        ):
            relevance += 2.5

    if "endpoint" in tool_name:
        if (
            "hostname" in evidence
            or "host" in evidence
            or "endpoint" in hypothesis
        ):
            relevance += 2.5

    if "network" in tool_name:
        if (
            "source_ip" in evidence
            or "network" in warning
            or "ip" in evidence
        ):
            relevance += 2.0

    if "log" in tool_name:
        if (
            "log" in warning
            or "failed" in warning
            or "event" in hypothesis
        ):
            relevance += 2.0

    normalized_cost = max(0.0, 1.0 - (cost / 10.0))
    normalized_risk = max(0.0, 1.0 - (risk / 10.0))

    feasibility = 0.8 if tool.get("category") else 0.5

    score = (
        (relevance * 0.45)
        + (normalized_cost * 25.0)
        + (normalized_risk * 20.0)
        + (feasibility * 25.0)
        - failure_penalty
    )

    return max(0.0, round(score, 2))


def select_next_tool(context):
    """Return the best investigation option with rationale and alternatives."""

    context = context or {}

    tools = context.get("available_tools")

    # Use default tools only when available_tools is not supplied.
    # An explicitly empty list must remain empty.
    if tools is None:
        tools = DEFAULT_TOOLS

    scored = []

    for tool in tools:
        if not isinstance(tool, dict):
            continue

        scored.append({
            "name": tool.get("name"),
            "category": tool.get("category", "unknown"),
            "cost": tool.get("cost", 5),
            "risk": tool.get("risk", 5),
            "relevance": tool.get("relevance", 0),
            "score": _score_tool(tool, context),
        })

    scored.sort(
        key=lambda item: item["score"],
        reverse=True,
    )

    if not scored:
        return {
            "selected_tool": None,
            "score": 0.0,
            "selection_reason": (
                "No valid investigation tools are available. "
                "Configure an investigation tool before continuing."
            ),
            "expected_evidence": [],
            "evidence_gap": (
                "The investigation cannot collect additional evidence "
                "until a valid tool is available."
            ),
            "estimated_cost": 0.0,
            "risk_level": "unknown",
            "alternative_tools": [],
            "next_recommended_action": (
                "Add valid investigation tools and retry tool selection."
            ),
        }

    selected = scored[0]

    alternative_tools = [
        item
        for item in scored[1:4]
        if item["name"] != selected["name"]
    ]

    evidence_gap = context.get("evidence") or {}
    expected_evidence = []

    if (
        "username" in evidence_gap
        or "credential" in str(context.get("hypothesis") or "").lower()
    ):
        expected_evidence.append("account identity")

    if (
        "source_ip" in evidence_gap
        or "ip" in str(context.get("warning") or "").lower()
    ):
        expected_evidence.append("source IP provenance")

    if (
        "hostname" in evidence_gap
        or "endpoint" in str(context.get("hypothesis") or "").lower()
    ):
        expected_evidence.append("host telemetry")

    reason = (
        f"{selected['name']} best matches the current evidence gap "
        f"and investigation priority with a score of {selected['score']} "
        "because it provides relevant evidence at a practical cost."
    )

    return {
        "selected_tool": selected["name"],
        "score": selected["score"],
        "selection_reason": reason,
        "expected_evidence": (
            expected_evidence
            or ["supporting telemetry for the current hypothesis"]
        ),
        "evidence_gap": (
            "Missing or weak evidence required to validate "
            "the active hypothesis."
        ),
        "estimated_cost": selected["cost"],
        "risk_level": selected["risk"],
        "alternative_tools": alternative_tools,
        "next_recommended_action": (
            f"Collect {selected['name']} evidence and "
            "re-evaluate the active hypothesis."
        ),
    }


def _display_tool_name(name):
    """Convert internal tool identifiers into readable names."""

    names = {
        "log_correlation": "Authentication log review",
        "auth_log_review": "Authentication log review",
        "network_flow_analysis": "Network flow analysis",
        "network_trace": "Network trace analysis",
        "credential_review": "Credential and identity review",
        "endpoint_forensics": "Endpoint forensic analysis",
        "memory_snapshot": "Memory snapshot analysis",
    }

    return names.get(name, str(name or "Unknown investigation tool"))


def select_next_best_tool(
    incident,
    evidence=None,
    context=None,
    available_tools=None,
    failed_tools=None,
):
    """Select the next-best tool using incident, evidence, cost and risk."""

    incident = incident or {}
    context = dict(context or {})

    if available_tools is not None:
        context["available_tools"] = available_tools

    # Combine incident and evidence information.
    evidence_context = dict(incident)

    if isinstance(evidence, dict):
        evidence_context.update(evidence)
    elif isinstance(evidence, list):
        for item in evidence:
            if isinstance(item, dict):
                evidence_context.update(item)

    context["evidence"] = evidence_context

    failed = set(failed_tools or [])
    context["used_tools"] = list(
        set(context.get("used_tools") or []) | failed
    )

    result = select_next_tool(context)
    selected = result.get("selected_tool")

    if selected is None:
        return {
            **result,
            "selected_tool": None,
            "selection_score": 0.0,
            "evidence_gap_addressed": [],
            "alternative_tools": [],
            "next_recommended_investigation_action": (
                "Register available investigation tools before proceeding."
            ),
        }

    selection_score = round(
        min(1.0, max(0.0, float(result.get("score", 0)) / 100.0)),
        4,
    )

    selected_name = _display_tool_name(selected)

    alternatives = [
        {
            **tool,
            "name": _display_tool_name(tool.get("name")),
        }
        for tool in result.get("alternative_tools", [])
    ]

    try:
        numeric_risk = float(result.get("risk_level", 5))
    except (TypeError, ValueError):
        numeric_risk = 5.0

    if numeric_risk <= 3:
        risk_level = "low"
    elif numeric_risk <= 6:
        risk_level = "medium"
    else:
        risk_level = "high"

    # Build evidence-gap records from actual incident fields.
    evidence_gap_records = []

    if incident.get("event_type") == "failed_login":
        evidence_gap_records.append({
            "type": "failed_login",
            "description": (
                "Authentication activity requires investigation."
            ),
        })

    if evidence_context.get("source_ip"):
        evidence_gap_records.append({
            "type": "network_telemetry",
            "description": (
                "Network source IP requires verification."
            ),
        })

    if evidence_context.get("hostname"):
        evidence_gap_records.append({
            "type": "endpoint_telemetry",
            "description": (
                "Endpoint activity requires verification."
            ),
        })

    next_action = (
        f"Execute {selected_name}, collect supporting evidence, "
        "and reassess the active investigation hypothesis."
    )

    return {
        **result,
        "selected_tool": selected_name,
        "selection_score": selection_score,
        "score": selection_score,
        "evidence_gap_addressed": evidence_gap_records,
        "risk_level": risk_level,
        "alternative_tools": alternatives,
        "next_recommended_investigation_action": next_action,
        "next_recommended_action": next_action,
    }


def choose_next_best_evidence(context):
    """Compatibility wrapper for existing callers."""

    return select_next_tool(context)
