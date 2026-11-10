"""Synthetic demo data generator (fixed seed, no real personal information)."""

from __future__ import annotations

import csv
import random
import sqlite3
from datetime import date, timedelta
from pathlib import Path
from typing import Any

from .detectors.checksums import (
    credit_code_check_digit,
    id_card_check_digit,
    luhn_check_digit,
)

SURNAMES = "赵钱孙李周吴郑王冯陈褚卫蒋沈韩杨朱秦许何吕施张孔曹严华金魏陶姜"
GIVEN = "安宁禾一然青川林溪晨雨欣悦哲远知秋和宁"
CITIES = (
    "北京市",
    "上海市",
    "杭州市",
    "南京市",
    "成都市",
    "武汉市",
    "西安市",
    "广州市",
)
STREETS = ("示例路", "样例街", "演示巷", "合成大道")
STATUSES = ("active", "pending", "suspended")
STAGES = ("new", "qualified", "won", "lost")


def synthetic_id_card(rng: random.Random, birthday: date) -> str:
    area = "999999"  # deliberately non-existent administrative code
    sequence = f"{rng.randint(1, 999):03d}"
    first17 = f"{area}{birthday:%Y%m%d}{sequence}"
    result = first17 + id_card_check_digit(first17)
    return result.lower() if rng.random() < 0.15 else result


def synthetic_bank_card(rng: random.Random) -> str:
    prefix = "4111" + "".join(str(rng.randint(0, 9)) for _ in range(11))
    return prefix + luhn_check_digit(prefix)


def synthetic_credit_code(rng: random.Random, index: int) -> str:
    prefix = f"91999999MA0ABC{index:03d}"
    return prefix + credit_code_check_digit(prefix)


def synthetic_phone(rng: random.Random) -> str:
    return "1" + rng.choice("35789") + "".join(str(rng.randint(0, 9)) for _ in range(9))


def synthetic_name(rng: random.Random) -> str:
    return rng.choice(SURNAMES) + rng.choice(GIVEN)


def synthetic_address(rng: random.Random) -> str:
    city = rng.choice(CITIES)
    street = rng.choice(STREETS)
    return f"{city}演示区{street}{rng.randint(1, 200)}号"


def synthetic_ip(rng: random.Random) -> str:
    # RFC 5737 documentation ranges are safe, non-routable examples.
    ranges = ("192.0.2.", "198.51.100.", "203.0.113.")
    return rng.choice(ranges) + str(rng.randint(1, 254))


def _make_customers(rng: random.Random, count: int) -> list[tuple[Any, ...]]:
    rows: list[tuple[Any, ...]] = []
    for index in range(1, count + 1):
        birthday = date(1965, 1, 1) + timedelta(days=rng.randint(0, 9000))
        age = 2024 - birthday.year
        phone = synthetic_phone(rng)
        row = (
            index,
            synthetic_name(rng),
            phone,
            f"contact{index:03d}@example.invalid",
            synthetic_id_card(rng, birthday),
            synthetic_bank_card(rng),
            synthetic_address(rng),
            birthday.isoformat(),
            age,
            round(rng.uniform(100, 90000), 2),
            rng.choice(STATUSES),
            "" if index % 7 == 0 else f"演示客户{index:03d}的跟进备注",
        )
        rows.append(row)
    return rows


def _make_orders(rng: random.Random, count: int, customer_count: int) -> list[tuple[Any, ...]]:
    base = date(2024, 1, 1)
    rows = []
    for index in range(1, count + 1):
        created = base + timedelta(days=rng.randint(0, 364), minutes=rng.randint(0, 1439))
        rows.append(
            (
                index,
                rng.randint(1, customer_count),
                f"ORD-{index:05d}",
                round(rng.uniform(10, 5000), 2),
                synthetic_ip(rng),
                synthetic_phone(rng),
                created.strftime("%Y-%m-%d %H:%M:%S"),
                rng.choice(STAGES),
            )
        )
    return rows


def _make_leads(rng: random.Random, count: int) -> list[tuple[Any, ...]]:
    rows = []
    for index in range(1, count + 1):
        rows.append(
            (
                index,
                synthetic_name(rng),
                synthetic_phone(rng),
                f"lead{index:03d}@example.invalid",
                synthetic_address(rng),
                synthetic_credit_code(rng, index),
                rng.randint(10, 100),
                rng.choice(STAGES),
            )
        )
    return rows


def generate_fixture(
    raw_dir: str | Path,
    seed: int = 20240513,
    customers: int = 36,
    orders: int = 90,
    leads: int = 18,
) -> dict[str, Path]:
    target = Path(raw_dir).expanduser().resolve()
    target.mkdir(parents=True, exist_ok=True)
    rng = random.Random(seed)
    sqlite_path = target / "demo.sqlite"
    csv_path = target / "leads.csv"
    for path in (sqlite_path, csv_path):
        if path.exists():
            path.unlink()
    for suffix in ("-wal", "-shm"):
        sidecar = Path(str(sqlite_path) + suffix)
        if sidecar.exists():
            sidecar.unlink()
    customer_rows = _make_customers(rng, customers)
    order_rows = _make_orders(rng, orders, customers)
    lead_rows = _make_leads(rng, leads)
    conn = sqlite3.connect(sqlite_path)
    try:
        conn.executescript(
            """
            CREATE TABLE customers (
                customer_id INTEGER PRIMARY KEY,
                full_name TEXT NOT NULL,
                phone TEXT NOT NULL,
                email TEXT,
                id_card TEXT NOT NULL,
                bank_card TEXT NOT NULL,
                address TEXT,
                birth_date TEXT,
                age INTEGER,
                balance REAL,
                status TEXT,
                notes TEXT
            );
            CREATE TABLE orders (
                order_id INTEGER PRIMARY KEY,
                customer_id INTEGER NOT NULL,
                order_no TEXT NOT NULL,
                amount REAL NOT NULL,
                ip_address TEXT NOT NULL,
                contact_phone TEXT,
                created_at TEXT NOT NULL,
                status TEXT NOT NULL
            );
            """
        )
        conn.executemany("INSERT INTO customers VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", customer_rows)
        conn.executemany("INSERT INTO orders VALUES (?,?,?,?,?,?,?,?)", order_rows)
        conn.commit()
    finally:
        conn.close()
    header = [
        "lead_id", "contact_name", "mobile", "email", "address",
        "company_code", "score", "stage",
    ]
    with csv_path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(header)
        writer.writerows(lead_rows)
    return {"sqlite": sqlite_path, "csv": csv_path}
