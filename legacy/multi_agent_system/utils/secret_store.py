from __future__ import annotations

import base64
import hashlib
import json
import os
from typing import Any

from cryptography.fernet import Fernet, InvalidToken


def _build_key_material() -> str:
    explicit = os.getenv("RAJDOLL_SECRET_KEY") or os.getenv("APP_SECRET_KEY")
    if explicit:
        return explicit

    fallback_parts = [
        os.getenv("DATABASE_URL", ""),
        os.getenv("REDIS_URL", ""),
        os.getenv("OPENAI_API_KEY", ""),
        os.getenv("LLM_API_KEY", ""),
        os.getenv("LLM_MODEL", ""),
    ]
    return "|".join(fallback_parts)


def _build_fernet() -> Fernet:
    digest = hashlib.sha256(_build_key_material().encode("utf-8")).digest()
    key = base64.urlsafe_b64encode(digest)
    return Fernet(key)


_FERNET = _build_fernet()


def encrypt_json(value: Any) -> str:
    payload = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return _FERNET.encrypt(payload).decode("utf-8")


def decrypt_json(ciphertext: str) -> Any:
    try:
        raw = _FERNET.decrypt(ciphertext.encode("utf-8"))
    except InvalidToken as exc:
        raise ValueError("Invalid encrypted secret payload") from exc
    return json.loads(raw.decode("utf-8"))
