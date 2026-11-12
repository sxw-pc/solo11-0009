#!/usr/bin/env python3
"""Rotate the pseudonym key in a maskline secret file.

Adds a fresh pseudonym key entry with a new kid, marks it current, and keeps
all previous entries so historical mappings remain revealable. The file is
rewritten atomically and keeps 0600 permissions.

Usage:
    python scripts/rotate_key.py /secure/path/maskline-secret.txt --kid 2026-Q2
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from maskline.config import ConfigError, rotate_pseudonym_key  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("secret_file", help="path to the YAML secret file to rotate")
    parser.add_argument(
        "--kid", required=True,
        help="key id for the new pseudonym key (must not already exist in the file)",
    )
    parser.add_argument(
        "--no-promote", action="store_true",
        help="add the key without marking it current",
    )
    args = parser.parse_args()
    try:
        store = rotate_pseudonym_key(
            args.secret_file, args.kid, promote=not args.no_promote
        )
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"rotated {args.secret_file}")
    print(f"current kid : {store.current_kid()}")
    print(f"keys on file: {', '.join(store.kids())}")
    print(
        "note: old key entries were retained; mappings created with them "
        "stay revealable as long as those entries remain in this file"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
