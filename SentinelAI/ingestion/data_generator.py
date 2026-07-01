"""
SentinelAI Transaction Data Generator Module.

This module acts as a synthetic data generator designed for fintech compliance
and fraud detection pipelines. It generates realistic chronological transaction streams
interspersed with complex, automated financial crime patterns (AML/Fraud scenarios).

Supported Automated Fraud Scenarios:
1. Cross-Device Fraud: Single IP address accessing >5 accounts within a 10-minute window.
2. Velocity Spike: Single account executing >20 transactions within 60 seconds.
3. Dormant Reactivation: Account dormant for >180 days executing >10 transactions within 5 minutes.
4. Geo Mismatch: Transaction originating from a country code differing from account registration.
5. Impossible Travel: Consecutive transactions from two different countries separated by <1 hour.
"""

import argparse
import csv
import json
import random
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from faker import Faker

# Constants for realistic data synthesis
CURRENCIES: List[str] = ["USD", "EUR", "GBP", "RUB"]
TRANSACTION_TYPES: List[str] = ["deposit", "withdrawal", "transfer"]
MERCHANT_CATEGORIES: List[str] = [
    "retail",
    "groceries",
    "gaming",
    "crypto",
    "luxury",
    "travel",
    "electronics",
    "utilities",
]
STATUSES: List[str] = ["completed", "pending", "failed"]

COUNTRY_IP_POOLS: Dict[str, List[str]] = {
    "US": ["198.51.100.14", "203.0.113.45", "64.233.160.1"],
    "DE": ["144.76.12.99", "144.76.88.12", "46.4.100.20"],
    "GB": ["81.2.69.142", "212.58.244.20", "82.165.197.1"],
    "PL": ["185.23.44.11", "185.23.45.22", "212.77.98.9"],
    "FR": ["195.154.120.1", "62.210.16.2", "212.27.48.10"],
    "JP": ["202.12.33.19", "133.242.18.1", "118.23.11.5"],
    "NG": ["197.210.64.12", "105.112.25.4"],
    "KP": ["175.45.176.1", "175.45.176.14"],
}


@dataclass
class AccountProfile:
    """Represents a persistent user account profile for synthetic data generation."""

    account_id: str
    home_country: str
    preferred_currency: str
    primary_device_id: str
    primary_ip: str
    registered_at: datetime
    last_active_at: datetime
    is_dormant: bool = False


@dataclass
class TransactionRecord:
    """Represents an individual financial transaction log entry."""

    transaction_id: str
    account_id: str
    amount: float
    currency: str
    timestamp: datetime
    ip_address: str
    country: str
    device_id: str
    transaction_type: str
    merchant_category: str
    status: str
    is_fraud: bool = False
    fraud_scenario: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Converts the record into a serializable dictionary format."""
        return {
            "transaction_id": self.transaction_id,
            "account_id": self.account_id,
            "amount": round(self.amount, 2),
            "currency": self.currency,
            "timestamp": self.timestamp.isoformat(),
            "ip_address": self.ip_address,
            "country": self.country,
            "device_id": self.device_id,
            "transaction_type": self.transaction_type,
            "merchant_category": self.merchant_category,
            "status": self.status,
            "is_fraud": self.is_fraud,
            "fraud_scenario": self.fraud_scenario or "NONE",
        }


class FintechDataGenerator:
    """Engine for generating synthetic financial transactions and injecting fraud patterns."""

    def __init__(
        self,
        num_accounts: int = 100,
        num_transactions: int = 1000,
        fraud_rate: float = 0.05,
        seed: int = 42,
    ) -> None:
        """Initialize the synthetic generator with strict reproducibility seeds."""
        self.num_accounts = max(num_accounts, 15)  # Ensure sufficient accounts for fraud scenarios
        self.num_transactions = max(num_transactions, 50)
        self.fraud_rate = max(0.0, min(fraud_rate, 1.0))
        self.seed = seed

        random.seed(self.seed)
        self.faker = Faker()
        Faker.seed(self.seed)

        self.base_time = datetime.now(timezone.utc)
        self.accounts: List[AccountProfile] = []
        self._generate_account_profiles()

    def _generate_account_profiles(self) -> None:
        """Creates a population of user accounts with realistic regional and behavioral attributes."""
        countries = ["US", "DE", "GB", "PL", "FR"]
        currency_map = {"US": "USD", "DE": "EUR", "GB": "GBP", "PL": "EUR", "FR": "EUR"}

        for i in range(1, self.num_accounts + 1):
            country = random.choice(countries)
            reg_days_ago = random.randint(30, 400)
            registered_at = self.base_time - timedelta(days=reg_days_ago)

            # Designate ~10% of accounts as dormant (>180 days inactive)
            is_dormant = reg_days_ago > 200 and (i % 10 == 0)
            if is_dormant:
                last_active = registered_at + timedelta(days=random.randint(1, 15))
            else:
                last_active = self.base_time - timedelta(days=random.randint(0, 5))

            ip_pool = COUNTRY_IP_POOLS.get(country, ["127.0.0.1"])
            primary_ip = random.choice(ip_pool)

            profile = AccountProfile(
                account_id=f"ACC_{10000 + i}",
                home_country=country,
                preferred_currency=currency_map.get(country, "USD"),
                primary_device_id=f"DEV_{uuid.uuid4().hex[:8].upper()}",
                primary_ip=primary_ip,
                registered_at=registered_at,
                last_active_at=last_active,
                is_dormant=is_dormant,
            )
            self.accounts.append(profile)

    def _generate_benign_transaction(self, account: AccountProfile, ts: datetime) -> TransactionRecord:
        """Generates a standard, legitimate transaction matching the account's historical profile."""
        # Log-normal style distribution for typical spending
        amount = round(random.expovariate(1.0 / 85.0) + 5.0, 2)
        if amount > 2500.0:
            amount = round(random.uniform(15.0, 350.0), 2)

        status_weights = [92, 5, 3]  # completed, pending, failed
        status = random.choices(STATUSES, weights=status_weights, k=1)[0]

        return TransactionRecord(
            transaction_id=str(uuid.uuid4()),
            account_id=account.account_id,
            amount=amount,
            currency=account.preferred_currency,
            timestamp=ts,
            ip_address=account.primary_ip,
            country=account.home_country,
            device_id=account.primary_device_id,
            transaction_type=random.choice(TRANSACTION_TYPES),
            merchant_category=random.choice(MERCHANT_CATEGORIES),
            status=status,
            is_fraud=False,
            fraud_scenario=None,
        )

    def _inject_cross_device_fraud(self, target_time: datetime) -> List[TransactionRecord]:
        """
        Scenario 1: Cross-Device Fraud.
        Single attacker IP accesses >5 distinct accounts within a 10-minute window.
        """
        records: List[TransactionRecord] = []
        attacker_ip = "185.220.101.7"  # Flagged Tor/Proxy IP
        attacker_device = "DEV_ATTACKER_99"
        
        # Select 6 distinct non-dormant accounts
        victim_accounts = random.sample([a for a in self.accounts if not a.is_dormant], k=6)
        
        for idx, acc in enumerate(victim_accounts):
            # All 6 events within 8 minutes
            tx_time = target_time + timedelta(seconds=idx * 75)
            records.append(
                TransactionRecord(
                    transaction_id=str(uuid.uuid4()),
                    account_id=acc.account_id,
                    amount=round(random.uniform(450.0, 990.0), 2),
                    currency=acc.preferred_currency,
                    timestamp=tx_time,
                    ip_address=attacker_ip,
                    country="NG",  # Mismatched country for high risk
                    device_id=attacker_device,
                    transaction_type="transfer",
                    merchant_category="crypto",
                    status="completed",
                    is_fraud=True,
                    fraud_scenario="Cross-Device Fraud",
                )
            )
        return records

    def _inject_velocity_spike(self, target_time: datetime) -> List[TransactionRecord]:
        """
        Scenario 2: Velocity Spike.
        Single account executes >20 rapid transactions within a 60-second window (Card testing / Botting).
        """
        records: List[TransactionRecord] = []
        victim = random.choice([a for a in self.accounts if not a.is_dormant])
        
        # 22 transactions within 55 seconds
        for idx in range(22):
            tx_time = target_time + timedelta(seconds=int(idx * 2.4))
            records.append(
                TransactionRecord(
                    transaction_id=str(uuid.uuid4()),
                    account_id=victim.account_id,
                    amount=round(random.uniform(4.99, 19.99), 2),
                    currency=victim.preferred_currency,
                    timestamp=tx_time,
                    ip_address=victim.primary_ip,
                    country=victim.home_country,
                    device_id=victim.primary_device_id,
                    transaction_type="withdrawal",
                    merchant_category="gaming",
                    status="completed",
                    is_fraud=True,
                    fraud_scenario="Velocity Spike",
                )
            )
        return records

    def _inject_dormant_reactivation(self, target_time: datetime) -> List[TransactionRecord]:
        """
        Scenario 3: Dormant Reactivation.
        Account inactive for >180 days suddenly executes >10 transactions within 5 minutes.
        """
        records: List[TransactionRecord] = []
        dormant_accounts = [a for a in self.accounts if a.is_dormant]
        if not dormant_accounts:
            dormant_accounts = [self.accounts[0]]
        victim = random.choice(dormant_accounts)
        
        # 12 transactions within 4.5 minutes (270 seconds)
        for idx in range(12):
            tx_time = target_time + timedelta(seconds=idx * 22)
            records.append(
                TransactionRecord(
                    transaction_id=str(uuid.uuid4()),
                    account_id=victim.account_id,
                    amount=round(random.uniform(850.0, 2400.0), 2),
                    currency=victim.preferred_currency,
                    timestamp=tx_time,
                    ip_address=victim.primary_ip,
                    country=victim.home_country,
                    device_id=victim.primary_device_id,
                    transaction_type="transfer",
                    merchant_category="luxury",
                    status="completed",
                    is_fraud=True,
                    fraud_scenario="Dormant Reactivation",
                )
            )
        return records

    def _inject_geo_mismatch(self, target_time: datetime) -> List[TransactionRecord]:
        """
        Scenario 4: Geo Mismatch.
        Transaction originating from IP country code differing from account registration jurisdiction.
        """
        records: List[TransactionRecord] = []
        victim = random.choice([a for a in self.accounts if not a.is_dormant])
        
        foreign_country = "KP" if victim.home_country != "KP" else "NG"
        foreign_ip = COUNTRY_IP_POOLS.get(foreign_country, ["175.45.176.1"])[0]

        records.append(
            TransactionRecord(
                transaction_id=str(uuid.uuid4()),
                account_id=victim.account_id,
                amount=round(random.uniform(3200.0, 7500.0), 2),
                currency=victim.preferred_currency,
                timestamp=target_time,
                ip_address=foreign_ip,
                country=foreign_country,
                device_id=f"DEV_{uuid.uuid4().hex[:6].upper()}",
                transaction_type="withdrawal",
                merchant_category="electronics",
                status="completed",
                is_fraud=True,
                fraud_scenario="Geo Mismatch",
            )
        )
        return records

    def _inject_impossible_travel(self, target_time: datetime) -> List[TransactionRecord]:
        """
        Scenario 5: Impossible Travel.
        Consecutive transactions originating from two different countries separated by <1 hour.
        """
        records: List[TransactionRecord] = []
        victim = random.choice([a for a in self.accounts if not a.is_dormant])
        
        # First transaction in home country
        t1 = target_time
        records.append(
            TransactionRecord(
                transaction_id=str(uuid.uuid4()),
                account_id=victim.account_id,
                amount=round(random.uniform(60.0, 150.0), 2),
                currency=victim.preferred_currency,
                timestamp=t1,
                ip_address=victim.primary_ip,
                country=victim.home_country,
                device_id=victim.primary_device_id,
                transaction_type="deposit",
                merchant_category="retail",
                status="completed",
                is_fraud=True,
                fraud_scenario="Impossible Travel",
            )
        )

        # Second transaction 32 minutes later in Tokyo (JP)
        t2 = t1 + timedelta(minutes=32)
        foreign_country = "JP" if victim.home_country != "JP" else "US"
        foreign_ip = COUNTRY_IP_POOLS.get(foreign_country, ["202.12.33.19"])[0]

        records.append(
            TransactionRecord(
                transaction_id=str(uuid.uuid4()),
                account_id=victim.account_id,
                amount=round(random.uniform(1800.0, 4200.0), 2),
                currency=victim.preferred_currency,
                timestamp=t2,
                ip_address=foreign_ip,
                country=foreign_country,
                device_id=f"DEV_{uuid.uuid4().hex[:6].upper()}",
                transaction_type="withdrawal",
                merchant_category="luxury",
                status="completed",
                is_fraud=True,
                fraud_scenario="Impossible Travel",
            )
        )
        return records

    def generate_stream(self) -> List[TransactionRecord]:
        """
        Orchestrates full synthetic stream generation, balancing benign activity
        with automated injection of the 5 complex fraud scenarios.
        """
        target_fraud_count = int(self.num_transactions * self.fraud_rate)
        all_records: List[TransactionRecord] = []
        current_fraud_count = 0

        # Generators for the 5 scenarios
        scenarios = [
            self._inject_cross_device_fraud,
            self._inject_velocity_spike,
            self._inject_dormant_reactivation,
            self._inject_geo_mismatch,
            self._inject_impossible_travel,
        ]

        # Inject fraud scenarios until target count is met
        window_start = self.base_time - timedelta(days=7)
        while current_fraud_count < target_fraud_count:
            scenario_func = random.choice(scenarios)
            rand_offset = timedelta(seconds=random.randint(0, 7 * 86400 - 3600))
            scenario_time = window_start + rand_offset
            
            generated_fraud = scenario_func(scenario_time)
            all_records.extend(generated_fraud)
            current_fraud_count += len(generated_fraud)

        # Generate benign transactions for remainder
        benign_count = max(0, self.num_transactions - len(all_records))
        active_accounts = [a for a in self.accounts if not a.is_dormant]
        
        for _ in range(benign_count):
            acc = random.choice(active_accounts)
            rand_offset = timedelta(seconds=random.randint(0, 7 * 86400))
            tx_time = window_start + rand_offset
            all_records.append(self._generate_benign_transaction(acc, tx_time))

        # Sort all records chronologically by timestamp
        all_records.sort(key=lambda r: r.timestamp)
        
        # Trim or pad slightly if exact size needed, but keep intact if close
        return all_records[: max(self.num_transactions, len(all_records))]


def export_records(records: List[TransactionRecord], output_path: str) -> None:
    """Exports generated transaction stream to CSV or JSONL format."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    
    if path.suffix.lower() == ".csv":
        with open(path, mode="w", newline="", encoding="utf-8") as csv_file:
            writer = csv.DictWriter(
                csv_file,
                fieldnames=[
                    "transaction_id",
                    "account_id",
                    "amount",
                    "currency",
                    "timestamp",
                    "ip_address",
                    "country",
                    "device_id",
                    "transaction_type",
                    "merchant_category",
                    "status",
                    "is_fraud",
                    "fraud_scenario",
                ],
            )
            writer.writeheader()
            for rec in records:
                writer.writerow(rec.to_dict())
    else:
        # Default to JSON Lines (.jsonl)
        with open(path, mode="w", encoding="utf-8") as jsonl_file:
            for rec in records:
                jsonl_file.write(json.dumps(rec.to_dict()) + "\n")


def main() -> None:
    """Command-line interface entry point for the synthetic transaction generator."""
    parser = argparse.ArgumentParser(
        description="SentinelAI Synthetic Transaction Stream & Fraud Scenario Generator"
    )
    parser.add_argument("--accounts", type=int, default=100, help="Number of simulated account profiles")
    parser.add_argument("--transactions", type=int, default=1000, help="Total number of transactions to generate")
    parser.add_argument("--fraud-rate", type=float, default=0.05, help="Target ratio of fraudulent transactions (0.0 - 1.0)")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for deterministic reproducibility")
    parser.add_argument(
        "--output",
        type=str,
        default="SentinelAI/logs/transactions.jsonl",
        help="Output file path (must end in .csv or .jsonl)",
    )

    args = parser.parse_args()

    print(f"=== SentinelAI Data Generator Initializing ===")
    print(f"Accounts: {args.accounts} | Target Transactions: {args.transactions} | Fraud Rate: {args.fraud_rate * 100:.1f}%")
    print(f"Random Seed: {args.seed} | Output Target: {args.output}")

    generator = FintechDataGenerator(
        num_accounts=args.accounts,
        num_transactions=args.transactions,
        fraud_rate=args.fraud_rate,
        seed=args.seed,
    )

    records = generator.generate_stream()
    fraud_records = [r for r in records if r.is_fraud]

    export_records(records, args.output)

    print("\n--- Generation Complete ---")
    print(f"Total Generated Transactions: {len(records)}")
    print(f"Total Fraudulent Events: {len(fraud_records)} ({len(fraud_records)/len(records)*100:.1f}%)")
    
    # Summary by typology
    typologies: Dict[str, int] = {}
    for r in fraud_records:
        typ = r.fraud_scenario or "Unknown"
        typologies[typ] = typologies.get(typ, 0) + 1
        
    for scenario_name, count in typologies.items():
        print(f"  * {scenario_name}: {count} txs")
    print(f"\nStream successfully written to: {args.output}")


if __name__ == "__main__":
    main()
