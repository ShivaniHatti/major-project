"""Normalize source records into a common event schema."""

import re
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Union


def _normalize_event_time(value: Any) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value
    if isinstance(value, str):
        stripped = value.strip()
        for fmt in (
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%d %H:%M:%S.%f%z",
            "%Y-%m-%d %H:%M:%S%z",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
        ):
            try:
                parsed = datetime.strptime(stripped, fmt)
                if parsed.tzinfo is None:
                    return parsed.replace(tzinfo=timezone.utc)
                return parsed
            except ValueError:
                continue
    return datetime.now(timezone.utc)


def _extract_username(message: str) -> Optional[str]:
    match = re.search(r"(?:for invalid user |for )(?P<user>\S+) from", message, re.IGNORECASE)
    if match:
        return match.group("user")
    return None


def _extract_ip(message: str) -> Optional[str]:
    match = re.search(r"(?:from|src|source) (?P<ip>\d{1,3}(?:\.\d{1,3}){3})", message, re.IGNORECASE)
    if match:
        return match.group("ip")
    return None


def _infer_event_type(message: str, source: Optional[str] = None) -> str:
    lower = (message or "").lower()
    if "failed password" in lower or "authentication failure" in lower:
        return "failed_login"
    if "accepted password" in lower or "session opened" in lower or "successful login" in lower:
        return "login_success"
    if "event id" in lower or source == "windows":
        return "windows_event"
    if "audit" in lower:
        return "audit_event"
    if "error" in lower:
        return "error_event"
    return "log_entry"


def _map_severity(value: Optional[str], event_type: str, message: str) -> str:
    normalized = (value or "").strip().lower()
    if normalized in {"critical", "high", "warning", "info", "low"}:
        return normalized

    lower = (message or "").lower()
    if event_type == "failed_login" or "failed password" in lower:
        return "high"
    if event_type == "login_success" or "accepted password" in lower:
        return "info"
    if "error" in lower or "denied" in lower:
        return "warning"
    return "info"


def normalize_event(record: Union[Dict[str, Any], Any], source: Optional[str] = None) -> Dict[str, Any]:
    if record is None:
        raise ValueError("No record supplied for normalization.")
    if not isinstance(record, dict):
        record = {"message": str(record), "raw": str(record)}

    raw_message = str(record.get("message") or record.get("raw") or "").strip()
    if not raw_message:
        raise ValueError("Event message is required for normalization.")

    event_source = (source or record.get("source") or "unknown").lower()
    raw_event_type = str(record.get("event_type") or "").strip().lower()
    fallback_event_type = _infer_event_type(raw_message, event_source)
    if raw_event_type in {"", "log_entry", "linux_log", "file_event", "windows_event"}:
        event_type = fallback_event_type
    else:
        event_type = raw_event_type
    username = record.get("username") or _extract_username(raw_message)
    source_ip = record.get("source_ip") or _extract_ip(raw_message)
    hostname = record.get("hostname") or record.get("host") or record.get("system_name") or "unknown"
    severity = _map_severity(record.get("severity"), event_type, raw_message)

    return {
        "source": event_source,
        "event_type": event_type,
        "username": username,
        "source_ip": source_ip,
        "hostname": hostname,
        "message": raw_message,
        "severity": severity,
        "event_time": _normalize_event_time(record.get("event_time")).isoformat(),
    }