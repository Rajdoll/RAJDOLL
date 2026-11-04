"""Engagements, scope, target accounts, and session-check configuration (AFD A1, A2, A11)."""

import re
from dataclasses import dataclass
from datetime import date
from typing import Any

from pydantic import BaseModel, Field, ValidationError, field_validator
from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from rajdoll.core import scope as scope_rules
from rajdoll.core.crypto import FieldCipher, KeyStore
from rajdoll.core.enums import (
    AuthMethod,
    Decision,
    EngagementStatus,
    ScanStatus,
    SessionStatus,
    Severity,
)
from rajdoll.core.models import Engagement, Finding, Scan, ScopeRule, TargetAccount
from rajdoll.services import settings as app_settings
from rajdoll.services.errors import Conflict, FieldError, NotFound, ValidationFailed
from rajdoll.services.session_check import CheckResult, Prober
from rajdoll.services.target_sessions import (
    SessionParseError,
    TargetSession,
    parse_session_text,
    session_from_parts,
)

MAX_NAME_LENGTH = 200
MAX_NOTES_LENGTH = 4000
_HEADER_TOKEN = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}$")
_UNFINISHED_SCAN = (
    ScanStatus.QUEUED,
    ScanStatus.RUNNING,
    ScanStatus.AWAITING_CHECKPOINT,
    ScanStatus.PAUSED,
)
SEVERITIES = [s.value for s in Severity]


# --------------------------------------------------------------------------------------
# Input models
# --------------------------------------------------------------------------------------


@dataclass
class EngagementInput:
    name: str
    target_url: str
    organization: str | None = None
    notes: str | None = None
    start_date: date | None = None
    end_date: date | None = None


def _blank_to_none(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _parse_date(value: Any, field: str, errors: list[FieldError]) -> date | None:
    text = _blank_to_none(value)
    if text is None:
        return None
    try:
        return date.fromisoformat(text)
    except ValueError:
        errors.append(FieldError(field, "Tanggal harus berformat YYYY-MM-DD."))
        return None


def engagement_input(data: dict[str, Any]) -> EngagementInput:
    """Validate form or JSON fields for creating or editing an engagement."""
    errors: list[FieldError] = []
    name = _blank_to_none(data.get("name"))
    if name is None:
        errors.append(FieldError("name", "Nama aplikasi wajib diisi."))
    elif len(name) > MAX_NAME_LENGTH:
        errors.append(FieldError("name", f"Nama aplikasi maksimal {MAX_NAME_LENGTH} karakter."))
    target_url = _blank_to_none(data.get("target_url")) or ""
    if not target_url:
        errors.append(FieldError("target_url", "URL target wajib diisi."))
    else:
        try:
            scope_rules.url_host(target_url)
        except scope_rules.ScopeError as exc:
            errors.append(FieldError("target_url", f"URL target: {exc}"))
    organization = _blank_to_none(data.get("organization"))
    if organization and len(organization) > MAX_NAME_LENGTH:
        errors.append(FieldError("organization", "Nama instansi terlalu panjang."))
    notes = _blank_to_none(data.get("notes"))
    if notes and len(notes) > MAX_NOTES_LENGTH:
        errors.append(FieldError("notes", f"Catatan maksimal {MAX_NOTES_LENGTH} karakter."))
    start = _parse_date(data.get("start_date"), "start_date", errors)
    end = _parse_date(data.get("end_date"), "end_date", errors)
    if start and end and end < start:
        errors.append(FieldError("end_date", "Tanggal selesai tidak boleh sebelum tanggal mulai."))
    if errors:
        raise ValidationFailed(errors)
    return EngagementInput(
        name=name or "",
        target_url=target_url,
        organization=organization,
        notes=notes,
        start_date=start,
        end_date=end,
    )


class IdentityHeader(BaseModel):
    name: str
    value: str = Field(max_length=256)

    @field_validator("name")
    @classmethod
    def _token(cls, value: str) -> str:
        if not _HEADER_TOKEN.match(value):
            raise ValueError("nama header tidak valid")
        return value

    @field_validator("value")
    @classmethod
    def _printable(cls, value: str) -> str:
        if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
            raise ValueError("nilai header tidak boleh berisi karakter kontrol")
        return value


class EngagementOverrides(BaseModel):
    """Per-engagement settings that override application defaults (BSD 4.1)."""

    rate_limit_rps: float | None = Field(default=None, gt=0, le=1000)
    concurrency: int | None = Field(default=None, ge=1, le=16)
    checkpoint_enabled: bool | None = None
    checkpoint_timeout_min: int | None = Field(default=None, ge=1, le=1440)
    evidence_max_bytes: int | None = Field(default=None, ge=4096, le=16_777_216)
    oob_enabled: bool | None = None
    identity_header: IdentityHeader | None = None


# --------------------------------------------------------------------------------------
# Reads
# --------------------------------------------------------------------------------------


def get(session: Session, engagement_id: int) -> Engagement:
    engagement = session.get(Engagement, engagement_id)
    if engagement is None:
        raise NotFound("Penugasan tidak ditemukan.")
    return engagement


def scope_patterns(session: Session, engagement_id: int) -> list[str]:
    return list(
        session.scalars(
            select(ScopeRule.pattern)
            .where(ScopeRule.engagement_id == engagement_id)
            .order_by(ScopeRule.id)
        )
    )


def scope_rule_rows(session: Session, engagement_id: int) -> list[ScopeRule]:
    return list(
        session.scalars(
            select(ScopeRule).where(ScopeRule.engagement_id == engagement_id).order_by(ScopeRule.id)
        )
    )


def accounts(session: Session, engagement_id: int) -> list[TargetAccount]:
    return list(
        session.scalars(
            select(TargetAccount)
            .where(TargetAccount.engagement_id == engagement_id)
            .order_by(TargetAccount.id)
        )
    )


def finding_counts(session: Session, engagement_ids: list[int]) -> dict[int, dict[str, Any]]:
    """Per engagement: accepted and pending findings by severity (merged duplicates excluded)."""
    empty = {"accepted": dict.fromkeys(SEVERITIES, 0), "pending": dict.fromkeys(SEVERITIES, 0)}
    result = {eid: {k: dict(v) for k, v in empty.items()} for eid in engagement_ids}
    if not engagement_ids:
        return result
    rows = session.execute(
        select(Finding.engagement_id, Finding.decision, Finding.severity, func.count())
        .where(
            Finding.engagement_id.in_(engagement_ids),
            Finding.merged_into_id.is_(None),
            Finding.decision.in_([Decision.ACCEPTED, Decision.PENDING]),
        )
        .group_by(Finding.engagement_id, Finding.decision, Finding.severity)
    )
    for engagement_id, decision, severity, count in rows:
        result[engagement_id][decision][severity] = count
    return result


def list_engagements(session: Session) -> list[Engagement]:
    order = case(
        (Engagement.status == EngagementStatus.ACTIVE, 0),
        (Engagement.status == EngagementStatus.READY, 1),
        (Engagement.status == EngagementStatus.DRAFT, 2),
        else_=3,
    )
    return list(session.scalars(select(Engagement).order_by(order, Engagement.updated_at.desc())))


def has_unfinished_scan(session: Session, engagement_id: int) -> bool:
    return (
        session.scalar(
            select(func.count())
            .select_from(Scan)
            .where(Scan.engagement_id == engagement_id, Scan.status.in_(_UNFINISHED_SCAN))
        )
        or 0
    ) > 0


def cipher(keystore: KeyStore, engagement: Engagement) -> FieldCipher:
    return FieldCipher(keystore, engagement.id, engagement.key_id)


def account_session(keystore: KeyStore, engagement: Engagement, account: TargetAccount) -> dict:
    if account.session_enc is None:
        return {"cookies": {}, "headers": {}}
    return cipher(keystore, engagement).decrypt_json(
        "target_account", "session_enc", account.session_enc
    )


def account_summary(
    keystore: KeyStore, engagement: Engagement, account: TargetAccount
) -> dict[str, Any]:
    data = account_session(keystore, engagement, account)
    return {
        "id": account.id,
        "label": account.label,
        "auth_method": account.auth_method,
        "session_status": account.session_status,
        "session_checked_at": account.session_checked_at,
        "cookie_names": sorted(data.get("cookies", {})),
        "header_names": sorted(data.get("headers", {})),
    }


def overrides(engagement: Engagement) -> EngagementOverrides:
    return EngagementOverrides.model_validate(engagement.settings or {})


def effective_settings(session: Session, engagement: Engagement) -> dict[str, Any]:
    """Application defaults with this engagement's overrides applied."""
    base = app_settings.load(session)
    effective = base.defaults.model_dump(mode="json")
    own = overrides(engagement).model_dump(mode="json", exclude_none=True)
    identity = own.pop("identity_header", None)
    effective.update(own)
    effective["identity_header"] = identity
    effective["block_detection"] = base.block_detection.model_dump(mode="json")
    return effective


def warnings(session: Session, engagement: Engagement) -> list[str]:
    result = []
    patterns = scope_patterns(session, engagement.id)
    if not scope_rules.url_in_scope(patterns, engagement.target_url):
        result.append("URL target berada di luar scope. Tambahkan host-nya ke scope.")
    account_rows = accounts(session, engagement.id)
    if not account_rows:
        result.append(
            "Belum ada akun. Modul yang butuh login hanya akan menguji bagian publik aplikasi."
        )
    elif len(account_rows) < 2:
        result.append("Kurang dari dua akun: modul Authorization (uji IDOR) akan dilewati.")
    if account_rows and not engagement.session_check_url:
        result.append("Cek sesi belum diatur, jadi sesi kedaluwarsa tidak akan terdeteksi.")
    return result


# --------------------------------------------------------------------------------------
# Writes
# --------------------------------------------------------------------------------------


def recompute_status(session: Session, engagement: Engagement) -> None:
    """draft ⇄ ready follows scope validity (AFD A2.4); active and done are left alone."""
    if engagement.status not in (EngagementStatus.DRAFT, EngagementStatus.READY):
        return
    session.flush()
    valid = scope_rules.url_in_scope(scope_patterns(session, engagement.id), engagement.target_url)
    engagement.status = EngagementStatus.READY if valid else EngagementStatus.DRAFT


def create(session: Session, keystore: KeyStore, data: dict[str, Any]) -> Engagement:
    values = engagement_input(data)
    key_id = keystore.create_engagement_key()  # before the row, see BSD 7
    engagement = Engagement(
        name=values.name,
        organization=values.organization,
        target_url=values.target_url,
        notes=values.notes,
        start_date=values.start_date,
        end_date=values.end_date,
        key_id=key_id,
        status=EngagementStatus.DRAFT,
        settings={},
    )
    session.add(engagement)
    session.flush()
    host = scope_rules.url_host(values.target_url)
    session.add(ScopeRule(engagement_id=engagement.id, pattern=scope_rules.normalize_pattern(host)))
    recompute_status(session, engagement)
    return engagement


def update_details(session: Session, engagement: Engagement, data: dict[str, Any]) -> None:
    values = engagement_input(data)
    engagement.name = values.name
    engagement.organization = values.organization
    engagement.target_url = values.target_url
    engagement.notes = values.notes
    engagement.start_date = values.start_date
    engagement.end_date = values.end_date
    recompute_status(session, engagement)


def set_status(session: Session, engagement: Engagement, status: str) -> None:
    """Mark done, or reopen a done engagement (AFD 3.1). Draft/ready/active are derived."""
    if status == EngagementStatus.DONE:
        if engagement.status != EngagementStatus.READY:
            raise Conflict("Hanya penugasan berstatus siap yang bisa ditandai selesai.")
        engagement.status = EngagementStatus.DONE
    elif status == "reopen":
        if engagement.status != EngagementStatus.DONE:
            raise Conflict("Hanya penugasan berstatus selesai yang bisa dibuka kembali.")
        engagement.status = EngagementStatus.DRAFT
        recompute_status(session, engagement)
    else:
        raise ValidationFailed.one("status", "Perubahan status tidak dikenal.")


def update_overrides(session: Session, engagement: Engagement, changes: dict[str, Any]) -> None:
    """Replace the engagement's overrides. Missing or null fields follow the app default."""
    try:
        validated = EngagementOverrides.model_validate(changes)
    except ValidationError as exc:
        raise ValidationFailed(app_settings.field_errors(exc, prefix="defaults.")) from exc
    engagement.settings = validated.model_dump(mode="json", exclude_none=True)


def add_scope(session: Session, engagement: Engagement, raw_pattern: str) -> ScopeRule:
    try:
        pattern = scope_rules.normalize_pattern(raw_pattern)
    except scope_rules.ScopeError as exc:
        raise ValidationFailed.one("pattern", str(exc)) from exc
    if pattern in scope_patterns(session, engagement.id):
        raise ValidationFailed.one("pattern", f"{pattern} sudah ada di scope.")
    rule = ScopeRule(engagement_id=engagement.id, pattern=pattern)
    session.add(rule)
    recompute_status(session, engagement)
    return rule


def remove_scope(session: Session, engagement: Engagement, rule_id: int) -> None:
    rule = session.get(ScopeRule, rule_id)
    if rule is None or rule.engagement_id != engagement.id:
        raise NotFound("Aturan scope tidak ditemukan.")
    remaining = [p for p in scope_patterns(session, engagement.id) if p != rule.pattern]
    if not remaining:
        raise Conflict("Scope minimal berisi satu host.")
    if not scope_rules.url_in_scope(remaining, engagement.target_url):
        raise Conflict("Aturan ini tidak bisa dihapus karena URL target akan berada di luar scope.")
    if engagement.session_check_url and not scope_rules.url_in_scope(
        remaining, engagement.session_check_url
    ):
        raise Conflict(
            "Aturan ini tidak bisa dihapus karena URL cek sesi akan berada di luar scope."
        )
    session.delete(rule)
    recompute_status(session, engagement)


def next_account_label(session: Session, engagement_id: int) -> str:
    taken = {a.label for a in accounts(session, engagement_id)}
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        label = f"Akun {letter}"
        if label not in taken:
            return label
    return f"Akun {len(taken) + 1}"


def _session_from_input(data: dict[str, Any]) -> TargetSession:
    try:
        raw = data.get("session_text")
        if isinstance(raw, str) and raw.strip():
            return parse_session_text(raw)
        session_obj = data.get("session")
        if isinstance(session_obj, dict):
            return session_from_parts(session_obj.get("cookies"), session_obj.get("headers"))
        if isinstance(session_obj, str) and session_obj.strip():
            return parse_session_text(session_obj)
        return parse_session_text("")
    except SessionParseError as exc:
        raise ValidationFailed.one("session_text", str(exc)) from exc


def _validated_label(
    session: Session, engagement: Engagement, raw: Any, exclude: int | None
) -> str:
    label = _blank_to_none(raw) or next_account_label(session, engagement.id)
    if len(label) > 50:
        raise ValidationFailed.one("label", "Label akun maksimal 50 karakter.")
    for account in accounts(session, engagement.id):
        if account.label == label and account.id != exclude:
            raise ValidationFailed.one("label", f"Label {label} sudah dipakai.")
    return label


def add_account(
    session: Session, keystore: KeyStore, engagement: Engagement, data: dict[str, Any]
) -> TargetAccount:
    method = data.get("auth_method") or AuthMethod.PASTED
    if method != AuthMethod.PASTED:
        raise ValidationFailed.one(
            "auth_method", "Saat ini hanya sesi tempel yang didukung. Auto-login hadir di F9."
        )
    label = _validated_label(session, engagement, data.get("label"), exclude=None)
    target_session = _session_from_input(data)
    account = TargetAccount(
        engagement_id=engagement.id,
        label=label,
        auth_method=AuthMethod.PASTED,
        session_enc=cipher(keystore, engagement).encrypt_json(
            "target_account", "session_enc", target_session.to_dict()
        ),
        session_status=SessionStatus.UNKNOWN,
    )
    session.add(account)
    session.flush()
    return account


def get_account(session: Session, engagement: Engagement, account_id: int) -> TargetAccount:
    account = session.get(TargetAccount, account_id)
    if account is None or account.engagement_id != engagement.id:
        raise NotFound("Akun tidak ditemukan.")
    return account


def update_account(
    session: Session,
    keystore: KeyStore,
    engagement: Engagement,
    account: TargetAccount,
    data: dict[str, Any],
) -> None:
    if "label" in data:
        account.label = _validated_label(session, engagement, data["label"], exclude=account.id)
    if data.get("session_text") or data.get("session"):
        target_session = _session_from_input(data)
        account.session_enc = cipher(keystore, engagement).encrypt_json(
            "target_account", "session_enc", target_session.to_dict()
        )
        account.session_status = SessionStatus.UNKNOWN
        account.session_checked_at = None


def check_account(
    session: Session,
    keystore: KeyStore,
    engagement: Engagement,
    account: TargetAccount,
    prober: Prober,
) -> CheckResult:
    """Run the session check for one account and record the outcome (AFD A2.3)."""
    if not engagement.session_check_url or not engagement.session_check_marker:
        raise ValidationFailed.one("session_check", "Atur URL cek sesi dan penanda login dulu.")
    result = prober(
        engagement.session_check_url,
        engagement.session_check_marker,
        account_session(keystore, engagement, account),
        engagement.id,
    )
    if result.checked:
        account.session_status = SessionStatus.VALID if result.valid else SessionStatus.INVALID
        account.session_checked_at = func.now()
    return result


def remove_account(session: Session, account: TargetAccount) -> None:
    session.delete(account)


def set_session_check(session: Session, engagement: Engagement, url: Any, marker: Any) -> None:
    url_text = _blank_to_none(url)
    marker_text = _blank_to_none(marker)
    if url_text is None:
        engagement.session_check_url = None
        engagement.session_check_marker = None
        return
    errors = []
    if not scope_rules.url_in_scope(scope_patterns(session, engagement.id), url_text):
        errors.append(FieldError("url", "URL cek sesi harus http(s) dan berada di dalam scope."))
    if marker_text is None:
        errors.append(FieldError("marker", "Penanda login wajib diisi jika URL cek sesi diisi."))
    elif len(marker_text) > 200:
        errors.append(FieldError("marker", "Penanda login maksimal 200 karakter."))
    if errors:
        raise ValidationFailed(errors)
    engagement.session_check_url = url_text
    engagement.session_check_marker = marker_text


def delete(session: Session, keystore: KeyStore, engagement: Engagement, confirm_name: Any) -> None:
    """AFD A11 and BSD 7: refuse while a scan is unfinished, then delete the key, then rows."""
    if (confirm_name or "") != engagement.name:
        raise ValidationFailed.one("confirm_name", "Nama aplikasi yang diketik tidak sama.")
    if has_unfinished_scan(session, engagement.id):
        raise Conflict("Penugasan tidak bisa dihapus selama scan atau retest belum selesai.")
    keystore.delete_engagement_key(engagement.key_id)
    session.delete(engagement)
