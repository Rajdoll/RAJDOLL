"""Module registry, scan profiles, and the first Information Gathering increment."""

import threading
from typing import Any

import pytest

from rajdoll.modules.base import TaskCancelled, TaskContext
from rajdoll.modules.registry import MODULE_LABELS, available_modules, label
from rajdoll.services.errors import ValidationFailed
from rajdoll.services.profiles import load_profile, resolve_modules


def test_full_profile_lists_all_twelve_modules_in_order() -> None:
    profile = load_profile("full")
    assert profile.label == "Lengkap"
    assert list(profile.modules) == list(MODULE_LABELS)
    assert len(profile.modules) == 12


@pytest.mark.parametrize("name", ["custom", "../full", "missing"])
def test_unknown_profiles_are_rejected(name: str) -> None:
    with pytest.raises(ValidationFailed):
        load_profile(name)


def test_resolve_modules() -> None:
    assert resolve_modules("full", None) == list(MODULE_LABELS)
    # Custom keeps the profile order, whatever order the form sent.
    assert resolve_modules("custom", ["session", "authentication"]) == [
        "authentication",
        "session",
    ]
    with pytest.raises(ValidationFailed, match="minimal satu"):
        resolve_modules("custom", [])
    with pytest.raises(ValidationFailed, match="tidak dikenal: sqlmap"):
        resolve_modules("custom", ["sqlmap", "session"])
    with pytest.raises(ValidationFailed):
        resolve_modules("quick", None)


def test_registry_and_extra_modules(monkeypatch: pytest.MonkeyPatch) -> None:
    assert set(available_modules()) == {"information_gathering", "input_validation"}
    monkeypatch.setenv("RAJDOLL_EXTRA_MODULES", "tests.dummy_module")
    assert available_modules()["information_gathering"].label == "Dummy"
    assert label("input_validation") == "Input Validation"
    assert label("other") == "other"


def _task(result: dict[str, Any], logs: list[str]) -> TaskContext:
    def run_tool(tool: str, params: dict, timeout_s: int = 600) -> dict:
        return result

    return TaskContext(
        task_id=1,
        scan_id=1,
        engagement_id=1,
        target_url="https://app.test/",
        scope=["app.test"],
        settings={},
        engine="httpx",
        target={"urls": ["https://app.test/"]},
        params={},
        cancel_event=threading.Event(),
        run_tool=run_tool,
        log=logs.append,
    )


def test_check_cancelled() -> None:
    ctx = _task({}, [])
    ctx.check_cancelled()
    ctx.cancel_event.set()
    with pytest.raises(TaskCancelled):
        ctx.check_cancelled()
