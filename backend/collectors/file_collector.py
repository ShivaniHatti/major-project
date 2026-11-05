"""Safe ingestion of approved sample log files."""

import csv
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Union


class FileCollector:
    """Collect log records from a controlled set of local file sources."""

    def __init__(self, allowed_roots: Optional[Sequence[Union[str, Path]]] = None):
        base_dir = Path(__file__).resolve().parents[1]
        default_roots = [base_dir / "data", base_dir]
        self.allowed_roots = [Path(root).resolve() for root in (allowed_roots or default_roots)]

    def _is_allowed(self, file_path: Path) -> bool:
        resolved = file_path.resolve()
        return any(str(resolved).startswith(str(root)) for root in self.allowed_roots)

    def collect(self, file_path: Union[str, Path]) -> List[Dict[str, Any]]:
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Log file not found: {file_path}")
        if not self._is_allowed(path):
            raise ValueError("The requested file is outside the approved collection roots.")

        suffix = path.suffix.lower()
        if suffix == ".json":
            return self._read_json_file(path)
        if suffix == ".csv":
            return self._read_csv_file(path)
        return self._read_text_file(path)

    def _read_json_file(self, path: Path) -> List[Dict[str, Any]]:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(payload, dict):
            return [self._build_record(payload, path)]
        if isinstance(payload, list):
            return [self._build_record(item, path) for item in payload]
        return []

    def _read_csv_file(self, path: Path) -> List[Dict[str, Any]]:
        with path.open("r", encoding="utf-8", newline="") as handle:
            rows = list(csv.DictReader(handle))
        return [self._build_record(row, path) for row in rows]

    def _read_text_file(self, path: Path) -> List[Dict[str, Any]]:
        records: List[Dict[str, Any]] = []
        with path.open("r", encoding="utf-8") as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if not line:
                    continue
                records.append(
                    self._build_record(
                        {
                            "source": "file",
                            "event_type": "log_entry",
                            "message": line,
                            "raw": line,
                            "hostname": path.stem,
                        },
                        path,
                    )
                )
        return records

    def _build_record(self, payload: Dict[str, Any], path: Path) -> Dict[str, Any]:
        if not isinstance(payload, dict):
            payload = {"message": str(payload), "raw": str(payload)}

        record = dict(payload)
        record.setdefault("source", "file")
        record.setdefault("event_type", "log_entry")
        record.setdefault("hostname", path.stem)
        record.setdefault("message", record.get("raw") or "No message provided")
        record.setdefault("raw", record.get("message"))
        return record


def collect_allowed_file(file_path: Union[str, Path], allowed_roots: Optional[Sequence[Union[str, Path]]] = None) -> List[Dict[str, Any]]:
    collector = FileCollector(allowed_roots=allowed_roots)
    return collector.collect(file_path)