import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Union
from SentinelAI.models.transaction import Transaction, DeviceFingerprint

class TransactionNormalizer:
    @staticmethod
    def normalize(raw_data: Union[Dict[str, Any], Transaction]) -> Transaction:
        if isinstance(raw_data, Transaction):
            return raw_data
        
        # Ensure trace_id
        trace_id = raw_data.get("trace_id") or f"tx_{uuid.uuid4().hex[:8]}"
        
        # Handle device fingerprint parsing
        raw_device = raw_data.get("device", {})
        if isinstance(raw_device, dict):
            device = DeviceFingerprint(**raw_device)
        elif isinstance(raw_device, DeviceFingerprint):
            device = raw_device
        else:
            device = DeviceFingerprint()

        # Parse timestamps safely
        raw_ts = raw_data.get("timestamp")
        if isinstance(raw_ts, str):
            try:
                ts = datetime.fromisoformat(raw_ts)
            except ValueError:
                ts = datetime.now(timezone.utc)
        elif isinstance(raw_ts, datetime):
            ts = raw_ts
        else:
            ts = datetime.now(timezone.utc)

        return Transaction(
            trace_id=trace_id,
            transaction_id=raw_data.get("transaction_id", f"txn_{uuid.uuid4().hex[:12]}"),
            user_id=str(raw_data.get("user_id", "usr_unknown")),
            amount=float(raw_data.get("amount", 0.0)),
            currency=str(raw_data.get("currency", "USD")),
            timestamp=ts,
            merchant=str(raw_data.get("merchant", "Online Store")),
            merchant_category=str(raw_data.get("merchant_category", "general")),
            card_pan_masked=str(raw_data.get("card_pan_masked", "400012******3456")),
            device=device,
            metadata=raw_data.get("metadata", {})
        )
