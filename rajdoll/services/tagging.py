"""Rule-based endpoint tags (BSD 4.4 `tags`; ported and extended from the legacy endpoint tagger).

Tags say what an endpoint is likely to be, so planning can pick the modules that test it. They are
computed from the method, path template, parameter names, content type, and source. Rules are the
fallback of the LLM classification (TRD P2); tags an assessor set (`tag_source = user`) are never
recomputed.
"""

from __future__ import annotations

import re
from typing import Any

TAG_LABELS: dict[str, str] = {
    "idor_candidate": "kandidat IDOR",
    "admin": "admin",
    "auth": "autentikasi",
    "registration": "pendaftaran",
    "password_reset": "reset password",
    "profile": "profil/akun",
    "upload": "unggah file",
    "price": "harga/jumlah",
    "state_change": "mengubah data",
    "has_params": "berparameter",
    "redirect_param": "parameter redirect",
    "file_param": "parameter file",
    "api": "API",
    "graphql": "GraphQL",
    "hidden": "tersembunyi",
}

_WRITE = {"POST", "PUT", "PATCH", "DELETE"}
_ID_SEGMENT = re.compile(r"\{(?:id|uuid|hash|[A-Za-z_]*[Ii]d)\}")
_ID_PARAM = re.compile(r"^(id|uid|.*[_-]id|.*Id|user|userid|account|akun|nik|nip|no|nomor)$", re.I)
_ADMIN = re.compile(
    r"(?:^|/)(admin|administrator|console|dashboard|manage|management|backoffice)(?:/|$|\.)", re.I
)
_AUTH = re.compile(
    r"(?:^|/)(login|signin|sign-in|masuk|authenticate|auth|oauth2?|token|sso|session)(?:/|$)", re.I
)
_REGISTER = re.compile(
    r"(?:^|/)(register|signup|sign-up|registration|daftar|pendaftaran)(?:/|$)", re.I
)
_RESET = re.compile(
    r"(reset[-_]?password|forgot[-_]?password|password[-_]?(reset|recovery)"
    r"|lupa[-_]?(kata[-_]?sandi|password)|change[-_]?password)",
    re.I,
)
_PROFILE = re.compile(r"(?:^|/)(profile|profil|account|akun|me|user|users|pengguna)(?:/|$)", re.I)
_UPLOAD = re.compile(r"(?:^|/)(upload|uploads|unggah|attachment|lampiran|import)(?:/|$)", re.I)
_PRICE_PARAM = re.compile(
    r"^(price|harga|amount|jumlah|qty|quantity|total|discount|diskon|coupon|kupon|voucher"
    r"|saldo|balance|nominal|biaya|fee|transfer|ke_rekening)$",
    re.I,
)
_REDIRECT_PARAM = re.compile(
    r"^(url|uri|redirect|redirect_uri|redirect_url|return|returnurl|return_url|next|callback"
    r"|dest|destination|continue|target|goto|link)$",
    re.I,
)
_FILE_PARAM = re.compile(
    r"^(file|filename|path|filepath|folder|dir|doc|document|template|include|page|lampiran|berkas)$",
    re.I,
)
_API = re.compile(r"(?:^|/)(api|rest|v\d+)(?:/|$)", re.I)


def _params(endpoint: dict[str, Any]) -> list[str]:
    names = list(endpoint.get("query_params") or [])
    names += [str(p.get("name")) for p in endpoint.get("body_params") or [] if p.get("name")]
    return names


def rule_tags(endpoint: dict[str, Any]) -> list[str]:
    """Tags for an endpoint dict with BSD 4.4 keys (method, path_template, params, ...)."""
    method = (endpoint.get("method") or "GET").upper()
    path = endpoint.get("path_template") or "/"
    params = _params(endpoint)
    content_type = (endpoint.get("content_type") or "").lower()
    body_locations = {p.get("location") for p in endpoint.get("body_params") or []}
    tags: set[str] = set()

    if _ID_SEGMENT.search(path) or any(_ID_PARAM.match(p) for p in params):
        tags.add("idor_candidate")
    if _ADMIN.search(path):
        tags.add("admin")
    secrets = {"password", "pass", "pwd", "kata_sandi"} & {p.lower() for p in params}
    if _AUTH.search(path) or (method in _WRITE and secrets):
        tags.add("auth")
    if _REGISTER.search(path):
        tags.add("registration")
    if _RESET.search(path):
        tags.add("password_reset")
    if _PROFILE.search(path):
        tags.add("profile")
    if _UPLOAD.search(path) or "multipart" in content_type or "multipart" in body_locations:
        tags.add("upload")
    if any(_PRICE_PARAM.match(p) for p in params):
        tags.add("price")
    if method in _WRITE:
        tags.add("state_change")
    if params:
        tags.add("has_params")
    if any(_REDIRECT_PARAM.match(p) for p in params):
        tags.add("redirect_param")
    if any(_FILE_PARAM.match(p) for p in params):
        tags.add("file_param")
    if _API.search(path) or "json" in content_type or "json" in body_locations:
        tags.add("api")
    if "graphql" in path.lower():
        tags.add("graphql")
    if endpoint.get("source") == "fuzz":
        tags.add("hidden")
    return sorted(tags)


def validate(tags: list[str]) -> list[str]:
    """Tags an assessor typed: known ones only, sorted like rule tags."""
    unknown = sorted(set(tags) - set(TAG_LABELS))
    if unknown:
        raise ValueError(", ".join(unknown))
    return sorted(set(tags))
