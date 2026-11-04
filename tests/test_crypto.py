import os
import stat
import threading
import time
import uuid
from pathlib import Path

import pytest

from rajdoll.core.crypto import (
    DecryptionError,
    FieldCipher,
    KeyNotFoundError,
    KeyStore,
    decrypt,
    encrypt,
)

KEY = os.urandom(32)


def test_roundtrip() -> None:
    blob = encrypt(KEY, b"secret evidence", "1:evidence:request_enc")
    assert decrypt(KEY, blob, "1:evidence:request_enc") == b"secret evidence"


def test_same_plaintext_encrypts_differently() -> None:
    assert encrypt(KEY, b"x", "a") != encrypt(KEY, b"x", "a")


def test_wrong_aad_is_rejected() -> None:
    blob = encrypt(KEY, b"secret", "1:evidence:request_enc")
    with pytest.raises(DecryptionError):
        decrypt(KEY, blob, "1:evidence:response_enc")


def test_wrong_key_is_rejected() -> None:
    blob = encrypt(KEY, b"secret", "a")
    with pytest.raises(DecryptionError):
        decrypt(os.urandom(32), blob, "a")


def test_tampering_is_detected() -> None:
    blob = bytearray(encrypt(KEY, b"secret", "a"))
    blob[-1] ^= 0x01
    with pytest.raises(DecryptionError):
        decrypt(KEY, bytes(blob), "a")


@pytest.mark.parametrize("blob", [b"", b"\x01", b"\x02" + b"\x00" * 40])
def test_malformed_or_unknown_version_is_rejected(blob: bytes) -> None:
    with pytest.raises(DecryptionError):
        decrypt(KEY, blob, "a")


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def test_master_key_is_created_private_and_reused(tmp_path: Path) -> None:
    first = KeyStore(tmp_path).master_key
    assert len(first) == 32
    assert _mode(tmp_path / "master.key") == 0o600
    assert KeyStore(tmp_path).master_key == first


def test_concurrent_master_key_creation_agrees(tmp_path: Path) -> None:
    keys: list[bytes] = []
    lock = threading.Lock()

    def create() -> None:
        key = KeyStore(tmp_path).master_key
        with lock:
            keys.append(key)

    threads = [threading.Thread(target=create) for _ in range(16)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(set(keys)) == 1
    assert not list(tmp_path.glob(".*.tmp"))


def test_engagement_key_survives_restart(tmp_path: Path) -> None:
    key_id = KeyStore(tmp_path).create_engagement_key()
    path = tmp_path / "engagements" / f"{key_id}.key"
    assert _mode(path) == 0o600
    store_a, store_b = KeyStore(tmp_path), KeyStore(tmp_path)
    assert store_a.engagement_key(key_id) == store_b.engagement_key(key_id)


def test_wrapped_key_is_bound_to_its_id(tmp_path: Path) -> None:
    store = KeyStore(tmp_path)
    key_id = store.create_engagement_key()
    other = uuid.uuid4()
    engagements = tmp_path / "engagements"
    (engagements / f"{other}.key").write_bytes((engagements / f"{key_id}.key").read_bytes())
    with pytest.raises(DecryptionError):
        KeyStore(tmp_path).engagement_key(other)


def test_deleted_key_makes_data_unreadable(tmp_path: Path) -> None:
    store = KeyStore(tmp_path)
    key_id = store.create_engagement_key()
    blob = FieldCipher(store, 7, key_id).encrypt_json("finding", "poc_spec_enc", {"path": "/x"})

    store.delete_engagement_key(key_id)

    for fresh_or_same in (store, KeyStore(tmp_path)):
        with pytest.raises(KeyNotFoundError):
            FieldCipher(fresh_or_same, 7, key_id).decrypt_json("finding", "poc_spec_enc", blob)


def test_missing_key_raises(tmp_path: Path) -> None:
    with pytest.raises(KeyNotFoundError):
        KeyStore(tmp_path).engagement_key(uuid.uuid4())


def test_field_cipher_roundtrip_and_binding(tmp_path: Path) -> None:
    store = KeyStore(tmp_path)
    key_id = store.create_engagement_key()
    cipher = FieldCipher(store, 1, key_id)
    value = {"cookies": {"session": "abc"}, "note": "Akun A — pegawai"}
    blob = cipher.encrypt_json("target_account", "session_enc", value)

    assert cipher.decrypt_json("target_account", "session_enc", blob) == value
    with pytest.raises(DecryptionError):
        cipher.decrypt_json("target_account", "credentials_enc", blob)
    with pytest.raises(DecryptionError):
        FieldCipher(store, 2, key_id).decrypt_json("target_account", "session_enc", blob)


def test_app_secret_roundtrip_and_binding(tmp_path: Path) -> None:
    store = KeyStore(tmp_path)
    blob = store.encrypt_app_secret("sk-test", "llm.api_key")
    assert store.decrypt_app_secret(blob, "llm.api_key") == "sk-test"
    with pytest.raises(DecryptionError):
        store.decrypt_app_secret(blob, "other")


def test_cleanup_orphans_respects_known_ids_and_age(tmp_path: Path) -> None:
    store = KeyStore(tmp_path)
    known = store.create_engagement_key()
    old_orphan = store.create_engagement_key()
    fresh_orphan = store.create_engagement_key()
    now = time.time()
    hour_ago = now - 3600
    for key_id in (known, old_orphan):
        os.utime(tmp_path / "engagements" / f"{key_id}.key", (hour_ago, hour_ago))
    (tmp_path / "engagements" / "not-a-uuid.key").write_bytes(b"ignored")

    removed = store.cleanup_orphans([known], min_age_seconds=600, now=now)

    assert removed == [old_orphan]
    remaining = {p.stem for p in (tmp_path / "engagements").glob("*.key")}
    assert remaining == {str(known), str(fresh_orphan), "not-a-uuid"}


def test_cleanup_without_engagement_dir_is_noop(tmp_path: Path) -> None:
    assert KeyStore(tmp_path).cleanup_orphans([]) == []
