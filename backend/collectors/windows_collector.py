"""Authorized Windows Event Log collection."""

from typing import Any, Dict, List, Optional, Union


class WindowsCollector:
    """Collect Windows events from a generic record list or JSON payload."""

    def collect(self, records: Optional[Union[List[Dict[str, Any]], Dict[str, Any]]] = None):
        if records is None:
            return []

        if isinstance(records, dict):
            items = [records]
        else:
            items = list(records)

        collected = []
        for entry in items:
            if not isinstance(entry, dict):
                continue
            payload = dict(entry)
            payload.setdefault("source", "windows")
            payload.setdefault("event_type", payload.get("event_type") or payload.get("EventID") or "windows_event")
            payload.setdefault("message", payload.get("message") or payload.get("Message") or "Windows event payload")
            payload.setdefault("hostname", payload.get("hostname") or payload.get("HostName") or "unknown")
            collected.append(payload)

        return collected