#!/usr/bin/env python3
"""Generate the fixed-seed synthetic demo fixtures.

Usage:
    python scripts/make_fixture.py [--output-dir data/raw] [--seed 20240513]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from maskline.fixturegen import generate_fixture  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", default=str(ROOT / "data" / "raw"))
    parser.add_argument("--seed", type=int, default=20240513)
    parser.add_argument("--customers", type=int, default=36)
    parser.add_argument("--orders", type=int, default=90)
    parser.add_argument("--leads", type=int, default=18)
    args = parser.parse_args()
    paths = generate_fixture(
        args.output_dir,
        seed=args.seed,
        customers=args.customers,
        orders=args.orders,
        leads=args.leads,
    )
    for kind, path in paths.items():
        print(f"{kind}: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
