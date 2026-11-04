"""tools/entrypoint.py stops the whole container when either process dies."""

import subprocess
import sys
import time

from tests.helpers import REPO, clean_env

DRIVER = """
import sys, tools.entrypoint as e
e.COMMANDS = {{
    "proxy": [sys.executable, "-c", "import time; time.sleep({proxy_seconds})"],
    "runner": [sys.executable, "-c", "import sys, time; time.sleep({runner_seconds}); sys.exit(3)"],
}}
sys.exit(e.main())
"""


def _run(proxy_seconds: float, runner_seconds: float) -> tuple[int, float]:
    started = time.monotonic()
    code = subprocess.run(  # noqa: S603
        [
            sys.executable,
            "-c",
            DRIVER.format(proxy_seconds=proxy_seconds, runner_seconds=runner_seconds),
        ],
        cwd=REPO,
        env=clean_env(PYTHONPATH=str(REPO)),
        timeout=60,
        check=False,
    ).returncode
    return code, time.monotonic() - started


def test_one_process_dying_stops_the_other_and_fails() -> None:
    code, elapsed = _run(proxy_seconds=60, runner_seconds=0.5)
    assert code == 1
    assert elapsed < 20  # the long-running proxy was terminated, not waited for
