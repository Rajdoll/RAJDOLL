"""Tests for pause/resume feature."""
from multi_agent_system.models.models import JobStatus, Job


def test_jobstatus_has_paused():
    assert JobStatus.paused.value == "paused"


def test_job_has_paused_state_column():
    assert hasattr(Job, "paused_state")


from unittest.mock import patch, MagicMock
from multi_agent_system.utils import pause_manager


def test_set_pause_requested_writes_redis_key():
    fake = MagicMock()
    with patch.object(pause_manager, "_get_client", return_value=fake):
        pause_manager.set_pause_requested(job_id=42)
    fake.set.assert_called_once_with("pause_requested:42", "1")


def test_is_pause_requested_returns_true_when_key_exists():
    fake = MagicMock()
    fake.exists.return_value = 1
    with patch.object(pause_manager, "_get_client", return_value=fake):
        assert pause_manager.is_pause_requested(job_id=42) is True
    fake.exists.assert_called_once_with("pause_requested:42")


def test_is_pause_requested_returns_false_when_key_absent():
    fake = MagicMock()
    fake.exists.return_value = 0
    with patch.object(pause_manager, "_get_client", return_value=fake):
        assert pause_manager.is_pause_requested(job_id=42) is False


def test_clear_pause_flag_deletes_key():
    fake = MagicMock()
    with patch.object(pause_manager, "_get_client", return_value=fake):
        pause_manager.clear_pause_flag(job_id=42)
    fake.delete.assert_called_once_with("pause_requested:42")


def test_is_pause_requested_returns_false_on_redis_error():
    """If Redis is down, pause is advisory — return False (don't block scan)."""
    fake = MagicMock()
    fake.exists.side_effect = RuntimeError("redis down")
    with patch.object(pause_manager, "_get_client", return_value=fake):
        assert pause_manager.is_pause_requested(job_id=42) is False
