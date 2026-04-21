"""Tests for pause/resume feature."""
from multi_agent_system.models.models import JobStatus, Job


def test_jobstatus_has_paused():
    assert JobStatus.paused.value == "paused"


def test_job_has_paused_state_column():
    assert hasattr(Job, "paused_state")
