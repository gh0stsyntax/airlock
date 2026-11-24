"""Append-only audit log (JSON lines) with a hash chain and secret redaction.

Every record contains the hash of the previous record, so deleting or editing a line breaks verification.
This is tamper-*evident*, not tamper-proof: someone with write access can rewrite the whole file —
ship the latest hash somewhere else (e.g. CI output) if that matters.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

_SECRET_KEY = re.compile(r"(key|secret|token|passw|authorization|credential|cookie)", re.I)
_SECRET_VALUE = re.compile(r"(sk-[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{20,}|nvapi-[A-Za-z0-9]{10,}|AKIA[0-9A-Z]{16}|Bearer\s+[A-Za-z0-9._\-]{16,})")
GENESIS = "0" * 64


def redact(value: Any, key: str = "") -> Any:
    if _SECRET_KEY.search(key):
        return "***"
    if isinstance(value, dict):
        return {k: redact(v, str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(v, key) for v in value]
    if isinstance(value, str):
        return _SECRET_VALUE.sub("***", value)
    return value


def _digest(prev: str, body: str) -> str:
    return hashlib.sha256((prev + body).encode("utf-8")).hexdigest()


class AuditLog:
    def __init__(self, path: str | Path, clock=time.time) -> None:
        self.path = Path(path)
        self._clock = clock
        self._last = self._read_last_hash()

    def _read_last_hash(self) -> str:
        if not self.path.exists():
            return GENESIS
        last = GENESIS
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                last = json.loads(line)["hash"]
        return last

    def record(self, event: Dict[str, Any]) -> str:
        body = json.dumps({"ts": round(self._clock(), 3), **redact(event)}, ensure_ascii=False, sort_keys=True)
        h = _digest(self._last, body)
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps({"prev": self._last, "body": body, "hash": h}, ensure_ascii=False) + "\n")
        self._last = h
        return h

    @staticmethod
    def verify(path: str | Path) -> Tuple[bool, Optional[int]]:
        """(True, None) if the chain is intact, else (False, index of the first broken record)."""
        prev = GENESIS
        p = Path(path)
        if not p.exists():
            return True, None
        for i, line in enumerate(l for l in p.read_text(encoding="utf-8").splitlines() if l.strip()):
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                return False, i
            if rec.get("prev") != prev or rec.get("hash") != _digest(prev, rec.get("body", "")):
                return False, i
            prev = rec["hash"]
        return True, None
