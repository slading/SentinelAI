import asyncio
from typing import List, Dict
from datetime import datetime, timezone, timedelta
from SentinelAI.models.transaction import Transaction

class SlidingWindowBuffer:
    """
    In-memory transaction buffer storing recent transactions per user_id.
    Provides fast slice access for Pandas feature calculations.
    """
    def __init__(self, retention_days: int = 7):
        self.retention_days = retention_days
        self._buffer: Dict[str, List[Transaction]] = {}
        self._lock = asyncio.Lock()

    async def add_transaction(self, tx: Transaction) -> None:
        async with self._lock:
            if tx.user_id not in self._buffer:
                self._buffer[tx.user_id] = []
            self._buffer[tx.user_id].append(tx)
            self._cleanup_user(tx.user_id, tx.timestamp)

    def _cleanup_user(self, user_id: str, reference_time: datetime) -> None:
        cutoff = reference_time - timedelta(days=self.retention_days)
        # Keep transactions newer than cutoff
        self._buffer[user_id] = [
            t for t in self._buffer[user_id] 
            if (t.timestamp.replace(tzinfo=timezone.utc) if t.timestamp.tzinfo is None else t.timestamp) >= cutoff
        ]

    async def get_user_history(self, user_id: str) -> List[Transaction]:
        async with self._lock:
            return list(self._buffer.get(user_id, []))

    async def get_all_transactions(self) -> List[Transaction]:
        async with self._lock:
            all_txs = []
            for tx_list in self._buffer.values():
                all_txs.extend(tx_list)
            return sorted(all_txs, key=lambda x: x.timestamp, reverse=True)

# Global singleton buffer
transaction_buffer = SlidingWindowBuffer()
