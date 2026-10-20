"""
Self-check for etw_monitor.py's event-pump/scoring decoupling and task-name
filtering. No real elevated ETW trace session - callback is invoked directly
with synthetic (event_id, event_dict) tuples shaped like pywintrace's actual
output. Run: python test_etw_monitor.py
"""

import logging
import queue
import threading
import time

import etw_monitor as em


class _FakeEngine:
    def __init__(self, on_evaluate=None):
        self.calls = []
        self.on_evaluate = on_evaluate

    def evaluate_etw_process_start(self, pid, parent_pid, image_name, create_time):
        self.calls.append((pid, parent_pid, image_name, create_time))
        if self.on_evaluate:
            self.on_evaluate()


def _wait_until(predicate, timeout=2.0, interval=0.01):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


def _process_start_event(pid=1234, parent_pid=1, image_name="evil.exe", create_time=100.0, task_name="PROCESSSTART"):
    return (1, {
        "Task Name": task_name,
        "EventHeader": {"EventDescriptor": {"Task": em.TASK_PROCESS_START}},
        "ProcessID": pid,
        "ParentProcessID": parent_pid,
        "ImageName": image_name,
        "CreateTime": create_time,
    })


def test_pywintrace_internal_warnings_are_silenced():
    # Confirmed on a real elevated run: pywintrace's own logger
    # (etw/etw.py -> "etw.etw") emits a WARNING for every single field TDH
    # fails to format (e.g. Flags/SecurityMitigations on a real
    # ProcessStart event) - harmless per pywintrace's own handling, but
    # without this suppression every process launch on the system would
    # add these as dashboard alerts via AlertLogHandler on the root logger.
    # An ERROR from the same logger (e.g. a real exception inside the
    # callback) must still get through.
    noisy = logging.getLogger('etw.etw')
    assert noisy.getEffectiveLevel() >= logging.ERROR
    assert not noisy.isEnabledFor(logging.WARNING)
    assert noisy.isEnabledFor(logging.ERROR)


def test_process_start_event_is_enqueued():
    q = queue.Queue()
    em._on_etw_event(_process_start_event(), q)
    assert q.get_nowait() == (1234, 1, "evil.exe", 100.0)


def test_task_name_matches_regardless_of_spacing():
    # pywintrace uppercases the manifest string but the exact spacing of the
    # raw manifest text isn't verified live - normalized matching must still
    # work whether it comes through as "PROCESSSTART" or "PROCESS START".
    q = queue.Queue()
    em._on_etw_event(_process_start_event(task_name="Process Start"), q)
    assert q.get_nowait() == (1234, 1, "evil.exe", 100.0)


def test_falls_back_to_numeric_task_id_when_name_is_unrecognized():
    q = queue.Queue()
    em._on_etw_event(_process_start_event(task_name="SOMETHING-ELSE"), q)
    assert q.get_nowait() == (1234, 1, "evil.exe", 100.0)


def test_non_process_start_events_are_ignored():
    q = queue.Queue()
    event = (2, {
        "Task Name": "PROCESSSTOP",
        "EventHeader": {"EventDescriptor": {"Task": 2}},
        "ProcessID": 1234,
    })
    em._on_etw_event(event, q)
    assert q.empty()


def test_malformed_event_does_not_raise():
    q = queue.Queue()
    em._on_etw_event((1, {"Task Name": "PROCESSSTART"}), q)  # missing EventHeader entirely -> must not raise
    assert q.empty() or q.get_nowait()[0] is None


def test_queue_full_drops_and_does_not_raise():
    q = queue.Queue(maxsize=1)
    q.put_nowait((1, 1, "already-here.exe", 1.0))
    em._on_etw_event(_process_start_event(), q)  # must not raise
    assert q.qsize() == 1


def test_on_heartbeat_fires_for_a_matched_event():
    q = queue.Queue()
    calls = []
    em._on_etw_event(_process_start_event(), q, on_heartbeat=lambda: calls.append(1))
    assert calls == [1]


def test_on_heartbeat_does_not_fire_for_an_ignored_event():
    q = queue.Queue()
    calls = []
    event = (2, {"Task Name": "PROCESSSTOP", "EventHeader": {"EventDescriptor": {"Task": 2}}})
    em._on_etw_event(event, q, on_heartbeat=lambda: calls.append(1))
    assert calls == []


def test_heartbeat_requires_a_process_id():
    # A ProcessStart-shaped event with no ProcessID is unusable (the worker
    # logs an error scoring it), so it must not prove the sensor is alive -
    # but it is still queued so that error is recorded.
    q = queue.Queue()
    calls = []
    em._on_etw_event((1, {"Task Name": "PROCESSSTART"}), q, on_heartbeat=lambda: calls.append(1))
    assert calls == []
    assert q.qsize() == 1


def test_on_drop_fires_when_the_queue_is_full_and_only_then():
    full = queue.Queue(maxsize=1)
    full.put_nowait((1, 1, "already-here.exe", 1.0))
    drops = []
    em._on_etw_event(_process_start_event(), full, on_drop=lambda: drops.append(1))  # must not raise
    assert drops == [1]
    assert full.qsize() == 1

    drops = []
    em._on_etw_event(_process_start_event(), queue.Queue(maxsize=5), on_drop=lambda: drops.append(1))
    assert drops == []


def test_a_dropped_event_still_counts_as_liveness():
    full = queue.Queue(maxsize=1)
    full.put_nowait((1, 1, "already-here.exe", 1.0))
    beats, drops = [], []
    em._on_etw_event(_process_start_event(), full, on_heartbeat=lambda: beats.append(1), on_drop=lambda: drops.append(1))
    assert beats == [1] and drops == [1], "overloaded is not dead: both signals must fire"


def test_ignored_and_malformed_events_are_never_counted_as_drops():
    full = queue.Queue(maxsize=1)
    full.put_nowait((1, 1, "already-here.exe", 1.0))
    drops = []
    em._on_etw_event((2, {"Task Name": "PROCESSSTOP", "EventHeader": {"EventDescriptor": {"Task": 2}}}), full,
                     on_drop=lambda: drops.append(1))
    em._on_etw_event("garbage", full, on_drop=lambda: drops.append(1))
    assert drops == [], "only an event that was actually lost to a full queue is a drop"


def test_scoring_worker_drains_queue_on_its_own_thread():
    engine = _FakeEngine()
    q = queue.Queue()
    q.put((1234, 1, "evil.exe", 100.0))
    threading.Thread(target=em._scoring_worker, args=(engine, q), daemon=True).start()
    assert _wait_until(lambda: engine.calls == [(1234, 1, "evil.exe", 100.0)])


def test_slow_scoring_does_not_block_the_callback_thread():
    release = threading.Event()

    def _slow_evaluate():
        release.wait(timeout=2)

    engine = _FakeEngine(on_evaluate=_slow_evaluate)
    q = queue.Queue()
    threading.Thread(target=em._scoring_worker, args=(engine, q), daemon=True).start()

    start = time.monotonic()
    em._on_etw_event(_process_start_event(), q)
    elapsed = time.monotonic() - start
    release.set()  # let the worker's slow call finish so the test process can exit cleanly

    assert elapsed < 0.2, f"_on_etw_event took {elapsed}s - it must never block on scoring"


# ---- stop_etw_monitor ---------------------------------------------------------

class _Consumer:
    def __init__(self, error=None):
        self.stop_calls = 0
        self.error = error

    def stop(self):
        self.stop_calls += 1
        if self.error:
            raise self.error


class _Session:
    """Stands in for pywintrace's ETW object: stop() may raise, and `consumer`
    (the thread owner) exists only if the test gives it one."""

    def __init__(self, stop_error=None, consumer=None):
        self.stop_calls = 0
        self.stop_error = stop_error
        if consumer is not None:
            self.consumer = consumer

    def stop(self):
        self.stop_calls += 1
        if self.stop_error:
            raise self.stop_error


class _LogCapture(logging.Handler):
    def __init__(self):
        super().__init__(logging.DEBUG)
        self.records = []

    def emit(self, record):
        self.records.append((record.levelno, record.getMessage()))


def _capturing_logs(fn):
    root = logging.getLogger()
    capture, original_level = _LogCapture(), root.level
    root.addHandler(capture)
    root.setLevel(logging.INFO)
    try:
        fn()
    finally:
        root.removeHandler(capture)
        root.setLevel(original_level)
    return capture.records


def test_stop_etw_monitor_with_no_session_is_a_noop():
    assert em.stop_etw_monitor(None) is None  # sensor never started: nothing to stop, must not raise


def test_stop_etw_monitor_stops_the_session_exactly_once():
    consumer = _Consumer()
    session = _Session(consumer=consumer)
    records = _capturing_logs(lambda: em.stop_etw_monitor(session))
    assert session.stop_calls == 1
    assert consumer.stop_calls == 0, "a clean stop must not also stop the consumer a second time"
    assert (logging.INFO, "[*] ETW kernel-process capture stopped.") in records


def test_stop_etw_monitor_falls_back_to_the_consumer_when_session_stop_raises():
    # pywintrace's ETW.stop() raises before it ever stops its consumer thread if
    # disabling the provider fails - the fallback is what keeps the process
    # from hanging in that case.
    consumer = _Consumer()
    session = _Session(stop_error=OSError("EnableTraceEx2 failed"), consumer=consumer)
    records = _capturing_logs(lambda: em.stop_etw_monitor(session))
    assert session.stop_calls == 1 and consumer.stop_calls == 1
    assert any(level == logging.ERROR and "did not stop cleanly" in msg and "EnableTraceEx2" in msg
               for level, msg in records)
    assert not any("capture stopped" in msg for _, msg in records), "must not claim a clean stop"


def test_stop_etw_monitor_never_raises_even_if_everything_fails():
    sessions = (
        _Session(stop_error=OSError("a")),                                        # no consumer attribute at all
        _Session(stop_error=OSError("a"), consumer=_Consumer(error=OSError("b"))),  # consumer fails too
        _Session(stop_error=RuntimeError("c"), consumer=_Consumer()),
    )
    _capturing_logs(lambda: [em.stop_etw_monitor(s) for s in sessions])  # must not raise


# The real pywintrace ETW/EventProvider/EventConsumer classes run in a child
# process (so nothing leaks into this one); only the six Windows API calls in
# etw.evntrace are stubbed, since a live trace needs Administrator. The real,
# non-daemon consumer thread blocks in the stub ProcessTrace() until the stub
# CloseTrace() releases it - exactly what keeps a real process from exiting.
_REAL_PYWINTRACE_CHILD = r'''
import sys
import threading

sys.path.insert(0, sys.argv[1])
mode = sys.argv[2]

import etw_monitor
from etw import ETW, GUID, ProviderInfo
from etw import evntrace as et

closed = threading.Event()
DISABLE = et.EVENT_CONTROL_CODE_DISABLE_PROVIDER


def start_trace(handle_ref, name, props):
    handle_ref._obj.value = 1234  # a live-looking session handle
    return 0


def enable_trace(handle, guid, code, level, any_kw, all_kw, timeout, params):
    if code == DISABLE and mode in ("provider_stop_fails", "plain_stop_provider_fails"):
        return 5  # ERROR_ACCESS_DENIED: pywintrace raises before it stops its consumer thread
    return 0


def open_trace(logfile_ref):
    return 5678


def process_trace(handles, count, start, end):
    closed.wait()  # like the real ProcessTrace: blocks until CloseTrace
    return 0


def close_trace(handle):
    closed.set()
    return 0


et.StartTraceW, et.EnableTraceEx2, et.OpenTraceW = start_trace, enable_trace, open_trace
et.ProcessTrace, et.CloseTrace, et.ControlTraceW = process_trace, close_trace, lambda *a: 0

provider = ProviderInfo("lab", GUID("{22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}"), any_keywords=0x10)
session = ETW(providers=[provider], event_callback=lambda e: None)
session.start()
thread = session.consumer.process_thread
assert thread.is_alive() and not thread.daemon, "premise changed: pywintrace's consumer thread is no longer a live non-daemon thread"

if mode == "plain_stop_provider_fails":
    try:
        session.stop()  # what a naive fix would do: no fallback when provider teardown raises
    except Exception:
        pass
elif mode != "nostop":
    etw_monitor.stop_etw_monitor(session)
    assert not thread.is_alive(), "consumer thread must be gone once the session is stopped"
# main thread ends here; the interpreter now waits for non-daemon threads
'''


def _run_real_pywintrace_child(mode, timeout):
    import os
    import subprocess
    import sys
    src_dir = os.path.dirname(os.path.abspath(__file__))
    proc = subprocess.Popen([sys.executable, "-c", _REAL_PYWINTRACE_CHILD, src_dir, mode],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
    try:
        return proc.wait(timeout=timeout), False
    except subprocess.TimeoutExpired:
        return None, True
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=10)


def test_control_process_hangs_at_exit_if_the_real_consumer_thread_is_never_stopped():
    # Reproduces the reported bug with the real pywintrace classes: Ctrl+C
    # left the non-daemon consumer thread running, so the process couldn't exit.
    _, timed_out = _run_real_pywintrace_child("nostop", timeout=4)
    assert timed_out, "expected a hang without a stop - the control no longer reproduces the bug"


def test_process_exits_once_stop_etw_monitor_stops_the_real_session():
    returncode, timed_out = _run_real_pywintrace_child("stop", timeout=30)
    assert not timed_out, "the process still hangs even though stop_etw_monitor() was called"
    assert returncode == 0


def test_process_exits_even_when_pywintrace_provider_teardown_fails():
    returncode, timed_out = _run_real_pywintrace_child("provider_stop_fails", timeout=30)
    assert not timed_out, "the consumer-thread fallback did not release the process"
    assert returncode == 0


def test_a_plain_session_stop_is_not_enough_when_provider_teardown_fails():
    # Proves the fallback is necessary, not decoration: ETW.stop() raises before
    # it stops its consumer thread, so without the fallback the process hangs.
    _, timed_out = _run_real_pywintrace_child("plain_stop_provider_fails", timeout=4)
    assert timed_out, "expected a hang from a plain session.stop() - the fallback may no longer be needed"


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"OK ({len(tests)} checks)")
