"""
Tamper-evident audit log — hash-chained, append-only JSONL.

Every action taken against a target is recorded here, whether it was
allowed or refused by the scope gate. Each entry's hash depends on its own
content plus the previous entry's hash, so editing, deleting, or reordering
any historical entry breaks the chain from that point forward — detectable
by verify_log_integrity() without needing any external signing infrastructure.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_GENESIS_HASH = "0" * 64


@dataclass
class AuditLogEntry:
    timestamp: str
    engagement_id: str
    module: str
    target: str
    action: str
    allowed: bool
    detail: dict[str, Any] = field(default_factory=dict)
    prev_hash: str = ""
    entry_hash: str = ""

    def compute_hash(self) -> str:
        payload = {
            "timestamp": self.timestamp,
            "engagement_id": self.engagement_id,
            "module": self.module,
            "target": self.target,
            "action": self.action,
            "allowed": self.allowed,
            "detail": self.detail,
            "prev_hash": self.prev_hash,
        }
        serialised = json.dumps(payload, sort_keys=True, default=str)
        return hashlib.sha256(serialised.encode()).hexdigest()


class AuditLog:
    """Append-only, hash-chained JSONL audit log for one engagement."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._last_hash = self._read_last_hash()

    def _read_last_hash(self) -> str:
        if not self.path.exists():
            return _GENESIS_HASH
        last = _GENESIS_HASH
        with open(self.path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                entry = json.loads(line)
                last = entry.get("entry_hash", _GENESIS_HASH)
        return last

    def record(
        self,
        engagement_id: str,
        module: str,
        target: str,
        action: str,
        allowed: bool,
        detail: dict[str, Any] | None = None,
    ) -> AuditLogEntry:
        entry = AuditLogEntry(
            timestamp=datetime.now(UTC).isoformat(),
            engagement_id=engagement_id,
            module=module,
            target=target,
            action=action,
            allowed=allowed,
            detail=detail or {},
            prev_hash=self._last_hash,
        )
        entry.entry_hash = entry.compute_hash()

        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(asdict(entry), default=str) + "\n")

        self._last_hash = entry.entry_hash
        return entry

    def read_all(self) -> list[dict]:
        if not self.path.exists():
            return []
        entries = []
        with open(self.path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    entries.append(json.loads(line))
        return entries


def verify_log_integrity(path: str | Path) -> tuple[bool, int | None]:
    """Walk the hash chain from the start. Returns (is_valid, first_broken_line)
    — first_broken_line is None when the log is valid (including an empty/absent log)."""
    path = Path(path)
    if not path.exists():
        return True, None

    prev_hash = _GENESIS_HASH
    with open(path, encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)

            if entry.get("prev_hash") != prev_hash:
                return False, line_num

            recomputed = AuditLogEntry(
                timestamp=entry["timestamp"],
                engagement_id=entry["engagement_id"],
                module=entry["module"],
                target=entry["target"],
                action=entry["action"],
                allowed=entry["allowed"],
                detail=entry.get("detail", {}),
                prev_hash=entry["prev_hash"],
            ).compute_hash()

            if recomputed != entry.get("entry_hash"):
                return False, line_num

            prev_hash = entry["entry_hash"]

    return True, None
