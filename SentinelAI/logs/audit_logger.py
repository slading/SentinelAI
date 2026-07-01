import asyncio
import hashlib
import json
from pathlib import Path
from typing import Dict, Any, Optional
from SentinelAI.config.settings import settings
from SentinelAI.models.audit import AuditEvent

class CryptographicAuditLogger:
    """
    Implements an Immutable WORM-style append-only audit trail with SHA-256 cryptographic chaining.
    Each audit entry includes the SHA-256 hash of the previous line.
    """
    def __init__(self, log_path: str = None):
        import os
        if log_path is None:
            log_path = "/tmp/SentinelAI/logs/audit.log" if os.getenv("VERCEL") == "1" else settings.audit_log_path
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = asyncio.Lock()
        self._last_hash = self._initialize_last_hash()

    def _initialize_last_hash(self) -> str:
        if not self.log_path.exists():
            return "0" * 64
        try:
            with open(self.log_path, "r", encoding="utf-8") as f:
                lines = [line.strip() for line in f if line.strip()]
                if not lines:
                    return "0" * 64
                last_line = json.loads(lines[-1])
                return last_line.get("event_hash", "0" * 64)
        except Exception:
            return "0" * 64

    async def log_event(self, trace_id: str, action: str, actor: str = "System_Orchestrator", payload: Dict[str, Any] = None) -> AuditEvent:
        async with self._lock:
            event = AuditEvent(
                trace_id=trace_id,
                action=action,
                actor=actor,
                payload=payload or {},
                prev_hash=self._last_hash
            )
            
            # Compute SHA-256 hash of this event block
            block_data = json.dumps(event.model_dump(exclude={"event_hash"}), sort_keys=True)
            event.event_hash = hashlib.sha256(block_data.encode("utf-8")).hexdigest()
            self._last_hash = event.event_hash

            # Append to immutable log
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(event.model_dump()) + "\n")

            return event

    async def get_audit_trail(self, trace_id: Optional[str] = None, limit: int = 50) -> list[dict]:
        async with self._lock:
            if not self.log_path.exists():
                return []
            results = []
            with open(self.log_path, "r", encoding="utf-8") as f:
                for line in f:
                    if not line.strip():
                        continue
                    try:
                        record = json.loads(line.strip())
                        if trace_id is None or record.get("trace_id") == trace_id:
                            results.append(record)
                    except json.JSONDecodeError:
                        continue
            return results[-limit:]

audit_logger = CryptographicAuditLogger()
