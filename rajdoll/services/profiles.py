"""Scan profiles from profiles/*.yaml (PRD F-12; TRD 3.1)."""

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import yaml

from rajdoll.core.config import get_settings
from rajdoll.modules.registry import MODULE_LABELS
from rajdoll.services.errors import ValidationFailed


@dataclass(frozen=True)
class Profile:
    name: str
    label: str
    modules: tuple[str, ...]


@lru_cache
def load_profile(name: str) -> Profile:
    directory = Path(get_settings().profiles_dir)
    path = directory / f"{name}.yaml"
    if not name.isidentifier() or not path.is_file():
        raise ValidationFailed.one("profile", f"Profil scan tidak dikenal: {name}")
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    modules = tuple(data["modules"])
    unknown = [m for m in modules if m not in MODULE_LABELS]
    if unknown:
        raise ValueError(f"profile {name} names unknown modules: {unknown}")
    return Profile(name=data["name"], label=data["label"], modules=modules)


def resolve_modules(profile: str, chosen: list[str] | None) -> list[str]:
    """Modules for a new scan: the full profile, or a non-empty subset of it for `custom`."""
    full = load_profile("full")
    if profile == "full":
        return list(full.modules)
    if profile != "custom":
        raise ValidationFailed.one("profile", f"Profil scan tidak dikenal: {profile}")
    picked = [m for m in full.modules if m in set(chosen or [])]
    unknown = sorted(set(chosen or []) - set(full.modules))
    if unknown:
        raise ValidationFailed.one("modules", f"Modul tidak dikenal: {', '.join(unknown)}")
    if not picked:
        raise ValidationFailed.one("modules", "Pilih minimal satu modul untuk profil Kustom.")
    return picked
