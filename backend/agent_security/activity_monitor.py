"""Track agent activities and recent actions for policy enforcement."""

from collections import defaultdict
from datetime import datetime, timezone


_ACTIVITY_LOG = defaultdict(list)


def record_activity(agent_id, action, result="unknown", details=None):
    """Append a timestamped activity record for an agent."""
    current = {
        "agent_id": str(agent_id),
        "action": str(action),
        "result": str(result),
        "details": details or {},
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    _ACTIVITY_LOG[str(agent_id)].append(current)
    return current


def get_recent_activity(agent_id, limit=10):
    """Return recent activity for an agent, newest first."""
    records = _ACTIVITY_LOG.get(str(agent_id), [])
    return list(reversed(records))[:limit]


def get_activity_log():
    """Return a shallow copy of the in-memory activity log."""
    return {agent_id: list(records) for agent_id, records in _ACTIVITY_LOG.items()}
