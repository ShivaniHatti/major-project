"""Authorized Linux log collection."""

import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Union


class LinuxCollector:
    """Collect and normalize Linux/Unix authentication log records."""

    DEFAULT_LOG_PATHS = (
        "/var/log/auth.log",
        "/var/log/secure",
        "/var/log/syslog",
    )

    def collect(self, paths=None):
        log_paths = paths or self.DEFAULT_LOG_PATHS
        collected = []

        for raw_path in log_paths:
            path = Path(raw_path)
            if not path.exists():
                continue
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    message = line.strip()
                    if not message:
                        continue
                    collected.append(self.parse_line(message, path))

        return collected

    def parse_line(self, line: str, path: Optional[Union[Path, str]] = None):
        record = {
            "source": "linux",
            "source_path": str(path) if path else "linux",
            "raw": line,
            "message": line,
            "event_type": "linux_log",
            "hostname": "unknown",
        }

        timestamp_match = re.match(
            r"^(?P<ts>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<service>[^\s:]+)(?:\[[^\]]+\])?:\s*(?P<message>.*)$",
            line,
        )
        if timestamp_match:
            record["hostname"] = timestamp_match.group("host")
            record["message"] = timestamp_match.group("message")

        lower = record["message"].lower()
        if "failed password" in lower:
            record["event_type"] = "failed_login"
            username_match = re.search(r"(?:for invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)", record["message"])
            if username_match:
                record["username"] = username_match.group("user")
                record["source_ip"] = username_match.group("ip")
        elif "accepted password" in lower or "session opened" in lower:
            record["event_type"] = "login_success"
            login_match = re.search(r"for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)", record["message"])
            if login_match:
                record["username"] = login_match.group("user")
                record["source_ip"] = login_match.group("ip")

        return record