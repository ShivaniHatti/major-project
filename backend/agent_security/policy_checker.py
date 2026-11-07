"""Simple policy enforcement for permitted actions and agent state checks."""

DEFAULT_POLICY = {
    "allowed_actions": [
        "collect_evidence",
        "query_logs",
        "analyze_event",
        "correlate_events",
        "generate_hypothesis",
        "select_tool",
    ],
    "blocked_actions": ["delete_evidence", "disable_monitoring"],
}


def evaluate_agent_policy(agent_id, action, status=None, health=None, metadata=None):
    """Return (allowed, message) after evaluating agent safety policy."""
    if not agent_id:
        return False, "Agent identifier is required."

    if status in ("inactive", "suspended", "disabled"):
        return False, "Agent is not active and cannot execute actions."

    if health in ("unhealthy", "critical"):
        return False, "Agent health is not sufficient for execution."

    policy = metadata or {}
    allowed = policy.get("allowed_actions", DEFAULT_POLICY["allowed_actions"])
    blocked = policy.get("blocked_actions", DEFAULT_POLICY["blocked_actions"])

    if action in blocked:
        return False, "This action is explicitly blocked by policy."
    if allowed and action not in allowed:
        return False, "This action is not permitted for the registered policy."
    return True, "Policy evaluation passed."
