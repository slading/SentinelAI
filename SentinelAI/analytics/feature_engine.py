import pandas as pd
from typing import List, Dict, Any
from datetime import datetime, timezone, timedelta
from SentinelAI.models.transaction import Transaction

class PandasFeatureEngine:
    @staticmethod
    def extract_features(tx: Transaction, user_history: List[Transaction]) -> Dict[str, Any]:
        """
        Converts transaction history to Pandas DataFrame and computes vectorized rolling features:
        - 1-hour transaction velocity count
        - 24-hour total spend amount
        - Historical user median amount
        - Historical standard deviation
        """
        if not user_history:
            return {
                "velocity_1h_count": 1,
                "velocity_24h_spend": tx.amount,
                "user_median_spend": tx.amount,
                "user_std_spend": 10.0,
                "history_count": 1
            }

        # Convert to Pandas DataFrame
        data = []
        for t in user_history:
            # Ensure UTC timezone awareness
            ts = t.timestamp
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            data.append({
                "amount": t.amount,
                "timestamp": ts,
                "merchant": t.merchant,
                "country": t.device.country_code,
                "city": t.device.city
            })
        
        df = pd.DataFrame(data)
        df = df.sort_values(by="timestamp").reset_index(drop=True)

        current_time = tx.timestamp
        if current_time.tzinfo is None:
            current_time = current_time.replace(tzinfo=timezone.utc)

        # Time window masks
        mask_1h = df["timestamp"] >= (current_time - timedelta(hours=1))
        mask_24h = df["timestamp"] >= (current_time - timedelta(hours=24))

        velocity_1h_count = int(mask_1h.sum())
        velocity_24h_spend = float(df.loc[mask_24h, "amount"].sum())
        
        user_median = float(df["amount"].median())
        user_std = float(df["amount"].std())
        if pd.isna(user_std) or user_std == 0:
            user_std = max(user_median * 0.25, 15.0)

        return {
            "velocity_1h_count": velocity_1h_count,
            "velocity_24h_spend": velocity_24h_spend,
            "user_median_spend": user_median,
            "user_std_spend": user_std,
            "history_count": len(df)
        }
