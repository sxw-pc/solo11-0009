"""Shared fixtures for fingerprint tests: a synthetic masked-style dataset.

The data mimics a delivery-ready masked table: a global pseudonym key column,
protected token columns, several numeric analytic columns and categorical
columns suitable for canary rows.
"""

from __future__ import annotations

import csv
import hashlib
import random
from pathlib import Path

import pytest

from maskline.fingerprint.config import FingerprintConfig, NumericColumn

MASTER_KEY = "test-master-key-0123456789-abcdef-very-secret"
DATASET_NAME = "acceptance_leads"


def pseudonym(seed_value: str) -> str:
    digest = hashlib.sha256(("global-salt:" + seed_value).encode("utf-8")).hexdigest()
    return "psn_" + digest[:40]


@pytest.fixture
def master_key() -> str:
    return MASTER_KEY


@pytest.fixture
def synthetic_table(tmp_path: Path) -> dict[str, Path]:
    rng = random.Random(20261112)
    rows = []
    cities = ["北京", "上海", "广州", "深圳", "杭州", "成都", "武汉", "西安"]
    tiers = ["A", "B", "C"]
    channels = ["自然流量", "广告", "转介绍", "展会"]
    for index in range(600):
        rows.append({
            "customer_id": pseudonym(f"customer-{index:05d}"),
            "account_id": pseudonym(f"account-{index:05d}"),
            "advisor_id": pseudonym(f"advisor-{index % 27:04d}"),
            "city": rng.choice(cities),
            "tier": rng.choice(tiers),
            "channel": rng.choice(channels),
            "age": rng.randint(18, 72),
            "annual_income_k": rng.randint(80, 900) * 10,
            "credit_score": round(rng.uniform(350, 850), 2),
            "monthly_spend": round(rng.uniform(50, 20000), 2),
            "visit_count": rng.randint(0, 60),
        })
    csv_path = tmp_path / "leads.masked.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    return {"csv": csv_path, "rows": rows}


@pytest.fixture
def fingerprint_config() -> FingerprintConfig:
    return FingerprintConfig(
        dataset_name=DATASET_NAME,
        key_column="customer_id",
        protected_columns=("account_id", "advisor_id"),
        numeric_columns=(
            NumericColumn(name="age", quantum=2.0, mark_rate=0.5, integer=True),
            NumericColumn(name="annual_income_k", mark_rate=0.5, integer=True),
            NumericColumn(name="credit_score", mark_rate=0.5),
            NumericColumn(name="monthly_spend", mark_rate=0.5),
            NumericColumn(name="visit_count", quantum=1.0, mark_rate=0.4, integer=True),
        ),
        canary_columns=("city", "tier", "channel"),
        canary_count=10,
        embed_row_order=True,
        min_rows=50,
    )
