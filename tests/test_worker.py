import threading

from rajdoll.worker.main import run


def test_worker_stops_after_max_iterations() -> None:
    assert run(threading.Event(), heartbeat_seconds=0, max_iterations=3) == 3


def test_worker_exits_immediately_when_stop_is_set() -> None:
    stop = threading.Event()
    stop.set()
    assert run(stop, heartbeat_seconds=0) == 0


def test_worker_stops_when_signalled_from_another_thread() -> None:
    stop = threading.Event()
    timer = threading.Timer(0.05, stop.set)
    timer.start()
    beats = run(stop, heartbeat_seconds=0.01)
    timer.join()
    assert beats >= 1
