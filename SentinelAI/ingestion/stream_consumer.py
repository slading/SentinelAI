import random
import uuid
from datetime import datetime, timezone
from SentinelAI.models.transaction import Transaction, DeviceFingerprint

class StreamConsumerSimulator:
    """
    Simulates transaction streams from Payment Gateway / Core Banking webhook.
    Generates realistic benign traffic interspersed with structured fraud scenarios.
    """
    SCENARIOS = [
        "BENIGN_STANDARD",
        "BENIGN_RECURRING",
        "FRAUD_HIGH_VALUE_NIGHT",
        "FRAUD_IMPOSSIBLE_TRAVEL",
        "FRAUD_VELOCITY_SMURFING"
    ]

    CITIES = {
        "PL": [("Warsaw", "185.23.44.11"), ("Krakow", "185.23.45.22")],
        "DE": [("Berlin", "144.76.12.99"), ("Munich", "144.76.88.12")],
        "GB": [("London", "81.2.69.142")],
        "KP": [("Pyongyang", "175.45.176.1")] # High risk country
    }

    @classmethod
    def generate_synthetic_transaction(cls, forced_scenario: str = None) -> Transaction:
        scenario = forced_scenario or random.choices(
            cls.SCENARIOS, 
            weights=[65, 20, 6, 5, 4], 
            k=1
        )[0]

        trace_id = f"tx_{uuid.uuid4().hex[:8]}"
        user_id = random.choice(["usr_101", "usr_202", "usr_303", "usr_888"])
        now = datetime.now(timezone.utc)

        if scenario == "BENIGN_STANDARD":
            amount = round(random.uniform(15.0, 180.0), 2)
            merchant = random.choice(["Biedronka Supermarket", "Zabka Express", "Uber Rides", "Amazon Europe"])
            category = "retail"
            country = "PL"
            city, ip = cls.CITIES[country][0]
        
        elif scenario == "BENIGN_RECURRING":
            amount = 14.99
            merchant = "Netflix Subscription"
            category = "digital_services"
            country = "PL"
            city, ip = cls.CITIES[country][0]

        elif scenario == "FRAUD_HIGH_VALUE_NIGHT":
            user_id = "usr_101"
            amount = round(random.uniform(11500.0, 24000.0), 2)
            merchant = "Luxury Jewelry Vault Ltd"
            category = "luxury"
            country = "KP"
            city, ip = cls.CITIES[country][0]

        elif scenario == "FRAUD_IMPOSSIBLE_TRAVEL":
            user_id = "usr_202"
            amount = round(random.uniform(3200.0, 4800.0), 2)
            merchant = "Electronic Superstore Tokyo"
            category = "electronics"
            country = "DE"
            city, ip = ("Tokyo", "202.12.33.19")

        elif scenario == "FRAUD_VELOCITY_SMURFING":
            user_id = "usr_303"
            amount = round(random.uniform(980.0, 999.0), 2) # Just under typical 1000 limit
            merchant = "Crypto Exchange Deposit"
            category = "financial"
            country = "GB"
            city, ip = cls.CITIES[country][0]
        else:
            amount = 50.0
            merchant = "Generic Store"
            category = "retail"
            country = "PL"
            city, ip = ("Warsaw", "127.0.0.1")

        device = DeviceFingerprint(
            device_id=f"dev_{user_id}_mobile",
            ip_address=ip,
            country_code=country,
            city=city,
            user_agent="Sentinel Fintech App v4.2"
        )

        return Transaction(
            trace_id=trace_id,
            user_id=user_id,
            amount=amount,
            currency="USD",
            timestamp=now,
            merchant=merchant,
            merchant_category=category,
            device=device,
            metadata={"scenario": scenario}
        )
