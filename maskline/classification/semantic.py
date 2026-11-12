"""Semantic normalization: map differently named columns to one semantic key.

The normalizer merges a built-in synonym dictionary with aliases declared by the
active rule packs. Columns sharing a semantic key are forced onto one consistent
classification; when two columns of the same semantic key would receive
different labels, a ``semantic_drift`` alert is emitted and the highest-protection
label wins deterministically (handled by the engine).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .models import Alert, RulePack
from .tolerant import leaf_token

# Built-in, standard-agnostic synonym groups. Keys match the detector sensitive
# types where one exists, so content detection and name semantics stay aligned.
BUILTIN_ALIASES: dict[str, tuple[str, ...]] = {
    "mobile_phone": (
        "phone", "mobile", "tel", "telephone", "mobile_phone", "mobile_number",
        "contact_phone", "cellphone", "phone_number", "phone_no", "hotline",
        "联系电话", "移动电话", "手机", "手机号",
    ),
    "email": (
        "email", "mail", "email_addr", "email_address", "电子邮箱", "邮箱", "电子邮件",
    ),
    "person_name": (
        "name", "full_name", "person_name", "contact_name", "user_name", "username",
        "real_name", "姓名",
    ),
    "id_card": (
        "id_card", "idcard", "identity_no", "cert_no", "id_number", "身份证", "身份证号",
    ),
    "bank_card": (
        "bank_card", "card_no", "card_number", "account_no", "银行卡", "银行卡号", "账号",
    ),
    "address": (
        "address", "addr", "home_address", "contact_address", "地址", "住址", "联系地址",
    ),
    "ipv4": ("ip", "ip_address", "client_ip", "remote_ip", "ip地址"),
    "credit_code": (
        "credit_code", "company_code", "org_code", "统一社会信用代码",
    ),
    "birth_date": ("birth_date", "birthday", "dob", "出生日期", "生日"),
}

_NORMALIZE_RE = re.compile(r"[\s\-]+")


def _normalize_name(name: str) -> str:
    return _NORMALIZE_RE.sub("_", name.strip().lower())


@dataclass
class SemanticResolver:
    exact: dict[str, str] = field(default_factory=dict)

    @classmethod
    def build(cls, packs: list[RulePack]) -> "SemanticResolver":
        resolver = cls()
        for canonical, names in BUILTIN_ALIASES.items():
            resolver.exact.setdefault(_normalize_name(canonical), canonical)
            for name in names:
                resolver.exact.setdefault(_normalize_name(name), canonical)
        for pack in packs:
            for group in pack.aliases:
                canonical = group.canonical
                resolver.exact.setdefault(_normalize_name(canonical), canonical)
                for name in group.names:
                    # Built-in synonyms win; a conflicting custom alias is kept
                    # out of the exact index and reported by the engine later.
                    resolver.exact.setdefault(_normalize_name(name), canonical)
        return resolver

    def resolve(self, column_name: str, degraded: bool = False) -> tuple[str | None, list[Alert]]:
        alerts: list[Alert] = []
        token = leaf_token(column_name)
        canonical = self.exact.get(_normalize_name(token))
        if canonical is None and degraded:
            alerts.append(
                Alert(
                    code="semantic_unresolved_degraded",
                    severity="info",
                    message=(
                        f"降级字段 {column_name!r} 无法建立语义归一，"
                        "同语义统一分级不适用，请人工确认。"
                    ),
                    column=column_name,
                )
            )
        return canonical, alerts
