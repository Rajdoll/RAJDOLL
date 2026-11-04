"""Application settings stored in `app_setting` (BSD 3.3), with defaults and validation."""

from dataclasses import dataclass
from typing import Any, Literal

from pydantic import BaseModel, Field, HttpUrl, ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from rajdoll.core.models import AppSetting


class LlmSettings(BaseModel):
    base_url: HttpUrl = HttpUrl("http://host.docker.internal:1234/v1")
    model: str = Field(default="qwen3-4b", min_length=1, max_length=200)
    api_key_enc: str | None = None
    thinking: bool = False


class Defaults(BaseModel):
    rate_limit_rps: float = Field(default=10, gt=0, le=1000)
    concurrency: int = Field(default=2, ge=1, le=16)
    checkpoint_enabled: bool = True
    checkpoint_timeout_min: int = Field(default=15, ge=1, le=1440)
    evidence_max_bytes: int = Field(default=1_048_576, ge=4096, le=16_777_216)
    oob_enabled: bool = False


class BlockDetection(BaseModel):
    window_s: int = Field(default=60, ge=10, le=3600)
    throttle_ratio: float = Field(default=0.3, gt=0, le=1)
    pause_ratio: float = Field(default=0.6, gt=0, le=1)
    pause_after_s: int = Field(default=180, ge=10, le=86400)


class AppSettings(BaseModel):
    llm: LlmSettings = LlmSettings()
    llm_budget_per_scan: int = Field(default=400, ge=0, le=100_000)
    cvss_primary: Literal["3.1", "4.0", "both"] = "3.1"
    defaults: Defaults = Defaults()
    block_detection: BlockDetection = BlockDetection()
    excluded_patterns: list[str] = Field(
        default_factory=lambda: [
            "logout",
            "signout",
            "delete",
            "remove",
            "destroy",
            "reset",
            "change-password",
            "deactivate",
        ]
    )


SETTING_KEYS = tuple(AppSettings.model_fields)


FIELD_LABELS: dict[str, str] = {
    "llm.base_url": "Alamat server LLM",
    "llm.model": "Model LLM",
    "llm.thinking": "Mode berpikir LLM",
    "llm_budget_per_scan": "Anggaran panggilan LLM per scan",
    "cvss_primary": "Versi CVSS utama",
    "defaults.rate_limit_rps": "Rate limit",
    "defaults.concurrency": "Tugas paralel",
    "defaults.checkpoint_enabled": "Checkpoint",
    "defaults.checkpoint_timeout_min": "Lanjut otomatis checkpoint (menit)",
    "defaults.evidence_max_bytes": "Ukuran maksimum body evidence (KB)",
    "defaults.oob_enabled": "Pengujian out-of-band",
    "block_detection.window_s": "Jendela deteksi blokir (detik)",
    "block_detection.throttle_ratio": "Rasio blokir untuk memperlambat",
    "block_detection.pause_ratio": "Rasio blokir untuk menjeda",
    "block_detection.pause_after_s": "Jeda setelah blokir berlanjut (detik)",
    "excluded_patterns": "Pola endpoint yang dikecualikan",
}

# Values the UI shows in a different unit than the stored setting.
_DISPLAY_DIVISOR = {"defaults.evidence_max_bytes": 1024}


@dataclass(frozen=True)
class FieldError:
    field: str
    message: str


class SettingsError(Exception):
    def __init__(self, errors: list[FieldError]) -> None:
        super().__init__("; ".join(e.message for e in errors))
        self.field_errors = errors

    @property
    def errors(self) -> list[str]:
        return [e.message for e in self.field_errors]


def _number(field: str, value: Any) -> str:
    divisor = _DISPLAY_DIVISOR.get(field)
    if divisor and isinstance(value, int | float):
        value = value / divisor
    if isinstance(value, float) and value.is_integer():
        value = int(value)
    return str(value)


def _message(field: str, error: dict[str, Any]) -> str:
    kind = error["type"]
    ctx = error.get("ctx") or {}
    bounds = {
        "greater_than_equal": ("minimal", "ge"),
        "less_than_equal": ("maksimal", "le"),
        "greater_than": ("harus lebih dari", "gt"),
        "less_than": ("harus kurang dari", "lt"),
    }
    if kind in bounds:
        prefix, key = bounds[kind]
        return f"{prefix} {_number(field, ctx.get(key))}"
    if kind in ("int_parsing", "int_from_float", "int_type"):
        return "harus bilangan bulat"
    if kind in ("float_parsing", "float_type"):
        return "harus berupa angka"
    if kind in ("bool_parsing", "bool_type"):
        return "harus ya atau tidak"
    if kind.startswith("url_"):
        return "harus alamat URL yang valid (http atau https)"
    if kind == "literal_error":
        return "pilihan tidak valid"
    if kind == "string_too_short":
        return "tidak boleh kosong"
    if kind == "string_too_long":
        return f"maksimal {ctx.get('max_length')} karakter"
    if kind == "missing":
        return "wajib diisi"
    return str(error.get("msg", "tidak valid"))


def _field_errors(exc: ValidationError) -> list[FieldError]:
    result = []
    for error in exc.errors():
        field = ".".join(str(part) for part in error["loc"])
        label = FIELD_LABELS.get(field, field)
        result.append(FieldError(field, f"{label}: {_message(field, error)}"))
    return result


def load(session: Session) -> AppSettings:
    """Stored values merged over defaults. Unknown keys in the table are ignored."""
    stored = {row.key: row.value for row in session.scalars(select(AppSetting))}
    return AppSettings.model_validate({k: v for k, v in stored.items() if k in SETTING_KEYS})


def update(session: Session, changes: dict[str, Any]) -> AppSettings:
    """Validate and persist top-level setting keys. Nested objects are merged, not replaced."""
    unknown = sorted(set(changes) - set(SETTING_KEYS))
    if unknown:
        raise SettingsError(
            [FieldError(key, f"Pengaturan tidak dikenal: {key}") for key in unknown]
        )
    current = load(session).model_dump(mode="json")
    merged = dict(current)
    for key, value in changes.items():
        if isinstance(value, dict) and isinstance(current.get(key), dict):
            merged[key] = {**current[key], **value}
        else:
            merged[key] = value
    try:
        validated = AppSettings.model_validate(merged)
    except ValidationError as exc:
        raise SettingsError(_field_errors(exc)) from exc
    dumped = validated.model_dump(mode="json")
    for key in changes:
        row = session.get(AppSetting, key)
        if row is None:
            session.add(AppSetting(key=key, value=dumped[key]))
        else:
            row.value = dumped[key]
    session.flush()
    return validated
