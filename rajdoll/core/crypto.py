"""Encryption at rest (TRD 8, BSD 1 and 7).

Key layout in the secrets directory:

    master.key                      32 random bytes, created on first start
    engagements/<key_id>.key        per-engagement data key, wrapped with the master key

Ciphertext format for every `*_enc` column and wrapped key:

    version (1 byte) | nonce (12 bytes) | AES-256-GCM ciphertext and tag

The associated data (AAD) binds a ciphertext to where it belongs, so a value copied to
another engagement, table, or column fails to decrypt.
"""

from __future__ import annotations

import json
import os
import threading
import time
import uuid
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

FORMAT_VERSION = 1
KEY_BYTES = 32
NONCE_BYTES = 12
_HEADER_BYTES = 1 + NONCE_BYTES

MASTER_KEY_FILE = "master.key"
ENGAGEMENT_KEY_DIR = "engagements"
ORPHAN_MIN_AGE_SECONDS = 600


class CryptoError(Exception):
    """Base class for encryption errors."""


class DecryptionError(CryptoError):
    """Ciphertext is malformed, was tampered with, or belongs elsewhere (wrong key or AAD)."""


class KeyNotFoundError(CryptoError):
    """The requested engagement data key does not exist (for example, it was deleted)."""


def encrypt(key: bytes, plaintext: bytes, aad: str) -> bytes:
    nonce = os.urandom(NONCE_BYTES)
    return bytes([FORMAT_VERSION]) + nonce + AESGCM(key).encrypt(nonce, plaintext, aad.encode())


def decrypt(key: bytes, blob: bytes, aad: str) -> bytes:
    if len(blob) <= _HEADER_BYTES or blob[0] != FORMAT_VERSION:
        raise DecryptionError("unsupported or truncated ciphertext")
    nonce, ciphertext = blob[1:_HEADER_BYTES], blob[_HEADER_BYTES:]
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad.encode())
    except InvalidTag as exc:
        raise DecryptionError("ciphertext failed authentication") from exc


def field_aad(engagement_id: int, table: str, column: str) -> str:
    return f"{engagement_id}:{table}:{column}"


def _write_new_file(path: Path, data: bytes) -> bool:
    """Atomically create `path` (mode 0600) only if it does not exist.

    The data is written and fsynced to a temporary file first, then hard-linked into place,
    so a concurrent reader never sees a partially written key. Returns False if `path`
    already existed.
    """
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        os.link(tmp, path)
    except FileExistsError:
        return False
    finally:
        tmp.unlink(missing_ok=True)
    return True


class KeyStore:
    """Master key and per-engagement data keys stored as files in the secrets directory."""

    def __init__(self, secrets_dir: str | Path) -> None:
        self._root = Path(secrets_dir)
        self._engagement_dir = self._root / ENGAGEMENT_KEY_DIR
        self._lock = threading.Lock()
        self._master: bytes | None = None
        self._cache: dict[uuid.UUID, bytes] = {}

    # Master key -----------------------------------------------------------------------

    @property
    def master_key(self) -> bytes:
        with self._lock:
            if self._master is None:
                self._master = self._load_or_create_master()
            return self._master

    def _load_or_create_master(self) -> bytes:
        self._root.mkdir(mode=0o700, parents=True, exist_ok=True)
        path = self._root / MASTER_KEY_FILE
        _write_new_file(path, os.urandom(KEY_BYTES))  # no-op if another process won the race
        key = path.read_bytes()
        if len(key) != KEY_BYTES:
            raise CryptoError(f"{path} is not a {KEY_BYTES}-byte key")
        return key

    def encrypt_app_secret(self, plaintext: str, name: str) -> bytes:
        """Encrypt an application-level secret (for example the LLM API key) with the master key."""
        return encrypt(self.master_key, plaintext.encode(), f"app:{name}")

    def decrypt_app_secret(self, blob: bytes, name: str) -> str:
        return decrypt(self.master_key, blob, f"app:{name}").decode()

    # Engagement data keys -------------------------------------------------------------

    def _key_path(self, key_id: uuid.UUID) -> Path:
        return self._engagement_dir / f"{key_id}.key"

    @staticmethod
    def _wrap_aad(key_id: uuid.UUID) -> str:
        return f"dek:{key_id}"

    def create_engagement_key(self) -> uuid.UUID:
        """Create a new data key file. Call before inserting the engagement row."""
        self._engagement_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        key_id = uuid.uuid4()
        data_key = os.urandom(KEY_BYTES)
        wrapped = encrypt(self.master_key, data_key, self._wrap_aad(key_id))
        if not _write_new_file(self._key_path(key_id), wrapped):
            raise CryptoError(f"key file for {key_id} already exists")
        with self._lock:
            self._cache[key_id] = data_key
        return key_id

    def engagement_key(self, key_id: uuid.UUID) -> bytes:
        with self._lock:
            cached = self._cache.get(key_id)
        if cached is not None:
            return cached
        try:
            wrapped = self._key_path(key_id).read_bytes()
        except FileNotFoundError as exc:
            raise KeyNotFoundError(str(key_id)) from exc
        data_key = decrypt(self.master_key, wrapped, self._wrap_aad(key_id))
        with self._lock:
            self._cache[key_id] = data_key
        return data_key

    def delete_engagement_key(self, key_id: uuid.UUID) -> None:
        """Step 1 of engagement deletion (BSD 7): after this, its encrypted data is unreadable."""
        with self._lock:
            self._cache.pop(key_id, None)
        self._key_path(key_id).unlink(missing_ok=True)

    def cleanup_orphans(
        self,
        known_key_ids: Iterable[uuid.UUID],
        min_age_seconds: float = ORPHAN_MIN_AGE_SECONDS,
        now: float | None = None,
    ) -> list[uuid.UUID]:
        """Delete key files with no engagement row, left over from an interrupted deletion.

        Files younger than `min_age_seconds` are kept: a key is written just before its
        engagement row is committed, so a fresh file without a row may still be in use.
        """
        if not self._engagement_dir.is_dir():
            return []
        known = set(known_key_ids)
        current = time.time() if now is None else now
        removed: list[uuid.UUID] = []
        for path in self._engagement_dir.glob("*.key"):
            try:
                key_id = uuid.UUID(path.stem)
            except ValueError:
                continue
            if key_id in known or current - path.stat().st_mtime < min_age_seconds:
                continue
            self.delete_engagement_key(key_id)
            removed.append(key_id)
        return removed


class FieldCipher:
    """Encrypts and decrypts `*_enc` column values for one engagement."""

    def __init__(self, keystore: KeyStore, engagement_id: int, key_id: uuid.UUID) -> None:
        self._key = keystore.engagement_key(key_id)
        self._engagement_id = engagement_id

    def encrypt_bytes(self, table: str, column: str, plaintext: bytes) -> bytes:
        return encrypt(self._key, plaintext, field_aad(self._engagement_id, table, column))

    def decrypt_bytes(self, table: str, column: str, blob: bytes) -> bytes:
        return decrypt(self._key, blob, field_aad(self._engagement_id, table, column))

    def encrypt_text(self, table: str, column: str, value: str) -> bytes:
        return self.encrypt_bytes(table, column, value.encode())

    def decrypt_text(self, table: str, column: str, blob: bytes) -> str:
        return self.decrypt_bytes(table, column, blob).decode()

    def encrypt_json(self, table: str, column: str, value: Any) -> bytes:
        encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        return self.encrypt_text(table, column, encoded)

    def decrypt_json(self, table: str, column: str, blob: bytes) -> Any:
        return json.loads(self.decrypt_text(table, column, blob))
