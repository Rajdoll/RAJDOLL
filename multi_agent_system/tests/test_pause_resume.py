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


def test_save_paused_state_writes_step_idx_and_updates_status():
    """_save_paused_state should write paused_state JSON and flip status to paused."""
    from multi_agent_system.orchestrator import Orchestrator

    fake_job = MagicMock()
    fake_db = MagicMock()
    fake_db.query.return_value.get.return_value = fake_job

    with patch("multi_agent_system.orchestrator.get_db") as mock_get_db:
        mock_get_db.return_value.__enter__.return_value = fake_db
        orch = Orchestrator.__new__(Orchestrator)  # bypass __init__
        orch.job_id = 99
        orch._save_paused_state(step_idx=5)

    assert fake_job.paused_state["step_idx"] == 5
    assert "paused_at" in fake_job.paused_state
    assert fake_job.paused_state["paused_by"] == "api"
    from multi_agent_system.models.models import JobStatus
    assert fake_job.status == JobStatus.paused
    fake_db.commit.assert_called_once()


def test_orchestrator_init_stores_resume_step_idx():
    from multi_agent_system.orchestrator import Orchestrator
    with patch("multi_agent_system.orchestrator.SharedContextManager"), \
         patch("multi_agent_system.orchestrator.HITLManager"), \
         patch.object(Orchestrator, "_load_plan_metadata", return_value={"options": {}}), \
         patch.object(Orchestrator, "_get_target", return_value="http://example.com"):
        orch = Orchestrator(job_id=1, resume_from_step_idx=7)
    assert orch.resume_from_step_idx == 7


def test_orchestrator_default_resume_step_idx_is_none():
    from multi_agent_system.orchestrator import Orchestrator
    with patch("multi_agent_system.orchestrator.SharedContextManager"), \
         patch("multi_agent_system.orchestrator.HITLManager"), \
         patch.object(Orchestrator, "_load_plan_metadata", return_value={"options": {}}), \
         patch.object(Orchestrator, "_get_target", return_value="http://example.com"):
        orch = Orchestrator(job_id=1)
    assert orch.resume_from_step_idx is None


def test_run_phase_3_returns_true_on_pause():
    """_run_phase_3 should return True when pause is triggered mid-loop."""
    from multi_agent_system.orchestrator import Orchestrator
    from multi_agent_system.utils import pause_manager as pm

    orch = Orchestrator.__new__(Orchestrator)
    orch.job_id = 99
    orch._save_paused_state = MagicMock()
    orch._load_plan_metadata = MagicMock(return_value={"options": {}})
    orch._is_job_cancelled = MagicMock(return_value=False)
    orch._get_failures = MagicMock(return_value=0)

    with patch.object(pm, "is_pause_requested", return_value=True), \
         patch.object(pm, "clear_pause_flag"):
        result = orch._run_phase_3(["AgentA", "AgentB"], start_idx=0)

    assert result is True
    orch._save_paused_state.assert_called_once_with(step_idx=0)
