"""Cross-dataset association matching: equality joins and semantic links."""

from __future__ import annotations

import re
from collections import defaultdict
from itertools import combinations
from typing import Callable

from ..detectors.base import CONFIDENCE_LOW
from .model import Association, ColRef, ColumnProfile

DEFAULT_MIN_CONTAINMENT = 0.6
DEFAULT_MIN_OVERLAP = 3

# Column-name synonym groups used for semantic (non-joinable) association hints.
NAME_GROUPS: tuple[tuple[str, ...], ...] = (
    ("phone", "mobile", "tel", "telephone", "手机", "电话", "手机号", "联系电话"),
    ("name", "fullname", "姓名", "名称", "联系人"),
    ("email", "mail", "邮箱", "电子邮箱"),
    ("address", "addr", "地址", "住址", "通讯地址"),
    ("idcard", "身份证", "证件号", "证件号码"),
    ("bankcard", "card", "银行卡", "卡号", "账号"),
)

_TOKEN_SPLIT_RE = re.compile(r"[^a-z0-9一-龥]+")

# Tokens that say "this is a key" without saying *which* entity it keys.
_GENERIC_KEY_TOKENS = frozenset(
    {
        "id", "no", "num", "number", "code", "sn", "uuid", "guid", "key",
        "编号", "标识", "卡号", "账号", "工号", "单号", "证件号",
    }
)


def _name_tokens(name: str) -> set[str]:
    lowered = name.lower()
    tokens = {token for token in _TOKEN_SPLIT_RE.split(lowered) if token}
    tokens.add(lowered)
    return tokens


def _names_compatible(left: str, right: str) -> bool:
    """Require a shared entity token for pure surrogate-key value overlaps.

    Integer surrogate keys from unrelated columns overlap by chance (1..N
    ranges), so an equality edge between two columns with no detected
    sensitive type additionally needs a non-generic shared name token:
    ``member_id``/``member_id`` matches, ``member_id``/``order_id`` does not.
    """
    left_tokens = _name_tokens(left) - _GENERIC_KEY_TOKENS
    right_tokens = _name_tokens(right) - _GENERIC_KEY_TOKENS
    return any(len(token) >= 2 for token in left_tokens & right_tokens)


def _name_group(name: str) -> int | None:
    tokens = _name_tokens(name)
    for index, group in enumerate(NAME_GROUPS):
        if tokens & set(group):
            return index
    return None


def match_equality(
    profiles: dict[str, ColumnProfile],
    values: dict[str, frozenset[str]],
    min_containment: float = DEFAULT_MIN_CONTAINMENT,
    min_overlap: int = DEFAULT_MIN_OVERLAP,
    pair_ignored: Callable[[ColRef, ColRef], bool] | None = None,
) -> list[Association]:
    """Find value-set overlaps between key-candidate columns of different datasets.

    A pair qualifies when the smaller value set is largely contained in the
    larger one (containment >= ``min_containment``) and at least ``min_overlap``
    distinct values are shared.
    """
    index: dict[str, list[str]] = defaultdict(list)
    for key, hashes in values.items():
        profile = profiles.get(key)
        if profile is None or profile.ignored or not hashes:
            continue
        for value_hash in hashes:
            index[value_hash].append(key)
    pair_overlap: dict[tuple[str, str], int] = defaultdict(int)
    for keys in index.values():
        if len(keys) < 2:
            continue
        for left, right in combinations(sorted(set(keys)), 2):
            left_ref = profiles[left].ref
            right_ref = profiles[right].ref
            if left_ref.dataset_fingerprint == right_ref.dataset_fingerprint:
                continue
            pair_overlap[(left, right)] += 1
    associations: list[Association] = []
    for (left, right), overlap in pair_overlap.items():
        smaller = min(len(values[left]), len(values[right]))
        if smaller == 0:
            continue
        containment = overlap / smaller
        if overlap < min_overlap or containment < min_containment:
            continue
        left_profile = profiles[left]
        right_profile = profiles[right]
        left_ref = left_profile.ref
        right_ref = right_profile.ref
        if not left_profile.sensitive_type and not right_profile.sensitive_type:
            if not _names_compatible(left_ref.column, right_ref.column):
                continue
        if pair_ignored is not None and pair_ignored(left_ref, right_ref):
            continue
        associations.append(
            Association(
                left=left_ref,
                right=right_ref,
                kind="equals",
                score=round(containment, 4),
                overlap=overlap,
                containment=round(containment, 4),
                reason=f"shared-values:{overlap}/{smaller}",
            )
        )
    return sorted(
        associations, key=lambda item: (-item.score, item.left.key, item.right.key)
    )


def match_semantic(
    profiles: dict[str, ColumnProfile],
    equality_edges: list[Association],
    type_ignored: Callable[[str], bool] | None = None,
) -> list[Association]:
    """Find same-meaning columns across datasets that cannot be value-joined.

    Two flavours: columns sharing the same detected sensitive type, and
    untyped columns whose names fall into the same synonym group. These edges
    are hints about related dimensions, not joinable keys.
    """
    ignored = type_ignored or (lambda _type: False)
    equality_pairs = {
        tuple(sorted((edge.left.key, edge.right.key))) for edge in equality_edges
    }
    seen: set[tuple[str, str]] = set()
    associations: list[Association] = []

    by_type: dict[str, list[ColumnProfile]] = defaultdict(list)
    for profile in profiles.values():
        if profile.ignored or not profile.sensitive_type:
            continue
        if ignored(profile.sensitive_type) or profile.score < CONFIDENCE_LOW:
            continue
        by_type[profile.sensitive_type].append(profile)
    for sensitive_type, columns in by_type.items():
        for left, right in combinations(sorted(columns, key=lambda p: p.ref.key), 2):
            if left.ref.dataset_fingerprint == right.ref.dataset_fingerprint:
                continue
            pair = tuple(sorted((left.ref.key, right.ref.key)))
            if pair in equality_pairs or pair in seen:
                continue
            seen.add(pair)
            associations.append(
                Association(
                    left=left.ref,
                    right=right.ref,
                    kind="semantic",
                    score=round(min(left.score, right.score) * 0.5, 4),
                    reason=f"same-sensitive-type:{sensitive_type}",
                )
            )

    by_group: dict[int, list[ColumnProfile]] = defaultdict(list)
    for profile in profiles.values():
        if profile.ignored or profile.sensitive_type:
            continue
        group = _name_group(profile.ref.column)
        if group is not None:
            by_group[group].append(profile)
    for group, columns in by_group.items():
        for left, right in combinations(sorted(columns, key=lambda p: p.ref.key), 2):
            if left.ref.dataset_fingerprint == right.ref.dataset_fingerprint:
                continue
            pair = tuple(sorted((left.ref.key, right.ref.key)))
            if pair in equality_pairs or pair in seen:
                continue
            seen.add(pair)
            associations.append(
                Association(
                    left=left.ref,
                    right=right.ref,
                    kind="semantic",
                    score=0.2,
                    reason=f"column-name-group:{NAME_GROUPS[group][0]}",
                )
            )
    return sorted(
        associations, key=lambda item: (-item.score, item.left.key, item.right.key)
    )
