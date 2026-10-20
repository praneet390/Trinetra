"""Self-check for self_test.py. Spawns real (but inert - `cmd.exe /c exit
0`) child processes; no real Sysmon/ETW sensors needed. Run:
python test_self_test.py"""

import logging
import time

import self_test as st


# ---- RecentPidSightings ---------------------------------------------------

def test_recent_pid_sightings_ignores_non_process_create():
    sightings = st.RecentPidSightings()
    sightings.observe(10, {"ProcessId": 999})  # not event_id 1
    assert not sightings.seen(999)


def test_recent_pid_sightings_sees_recorded_pid_regardless_of_type():
    sightings = st.RecentPidSightings()
    sightings.observe(1, {"ProcessId": "4242"})  # Sysmon-style string
    assert sightings.seen(4242)  # queried as int
    sightings.observe(1, {"ProcessId": 1234})  # ETW-style int
    assert sightings.seen("1234")  # queried as string


def test_recent_pid_sightings_bounded():
    sightings = st.RecentPidSightings(maxlen=2)
    sightings.observe(1, {"ProcessId": 1})
    sightings.observe(1, {"ProcessId": 2})
    sightings.observe(1, {"ProcessId": 3})
    assert not sightings.seen(1), "oldest entry must have been evicted"
    assert sightings.seen(2) and sightings.seen(3)


# ---- check_process_visibility ---------------------------------------------

def test_check_process_visibility_true_when_pid_is_seen():
    seen_pids = []

    def pid_seen_fn(pid):
        seen_pids.append(pid)
        return True  # pretend telemetry already caught it

    ok, pid = st.check_process_visibility(pid_seen_fn, timeout=5, poll_interval=0.05)
    assert ok is True
    assert isinstance(pid, int) and pid > 0
    assert seen_pids[0] == pid


def test_check_process_visibility_false_on_timeout():
    ok, pid = st.check_process_visibility(lambda pid: False, timeout=0.3, poll_interval=0.05)
    assert ok is False
    assert isinstance(pid, int) and pid > 0


def test_check_process_visibility_only_reports_true_for_the_real_spawned_pid():
    # A pid_seen_fn that's seen some *other* pid must not be fooled into
    # reporting success for this run's actual spawned process.
    ok, pid = st.check_process_visibility(lambda p: p == -1, timeout=0.3, poll_interval=0.05)
    assert ok is False


# ---- check_alert_pipeline --------------------------------------------------

class _CapturingHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self.messages = []

    def emit(self, record):
        self.messages.append(record.getMessage())


class _HandlerBackedSink:
    """Mimics web_server.AlertStore's .snapshot() shape, backed by a real
    logging.Handler attached to the root logger - exercises the real
    logging call check_alert_pipeline makes, not a mocked stand-in."""

    def __init__(self, handler):
        self.handler = handler

    def snapshot(self):
        return [{"message": m} for m in self.handler.messages]


def test_check_alert_pipeline_true_when_canary_round_trips_through_real_logging():
    # Both real entrypoints (main.py's basicConfig, web_server.py's
    # Backend.__init__) set the root logger to INFO before anything else
    # runs - match that here, since check_alert_pipeline's canary is
    # logged at INFO specifically so a passing run never inflates the
    # dashboard's WARNING/CRITICAL tiles.
    root = logging.getLogger()
    original_level = root.level
    handler = _CapturingHandler()
    root.addHandler(handler)
    root.setLevel(logging.INFO)
    try:
        assert st.check_alert_pipeline(_HandlerBackedSink(handler), timeout=2, poll_interval=0.05) is True
    finally:
        root.removeHandler(handler)
        root.setLevel(original_level)


def test_check_alert_pipeline_false_when_sink_never_sees_it():
    class _EmptySink:
        def snapshot(self):
            return []
    assert st.check_alert_pipeline(_EmptySink(), timeout=0.2, poll_interval=0.05) is False


# ---- run_once ---------------------------------------------------------------

def test_run_once_skips_alert_check_when_no_sink_given():
    results = st.run_once(lambda pid: True, alert_sink=None, timeout=2)
    assert 'process_visibility' in results
    assert 'alert_generation' not in results


def test_run_once_includes_alert_check_when_sink_given():
    root = logging.getLogger()
    original_level = root.level
    handler = _CapturingHandler()
    root.addHandler(handler)
    root.setLevel(logging.INFO)
    try:
        results = st.run_once(lambda pid: True, alert_sink=_HandlerBackedSink(handler), timeout=2)
        assert results['process_visibility'][0] is True
        assert results['alert_generation'][0] is True
    finally:
        root.removeHandler(handler)
        root.setLevel(original_level)


def test_run_once_never_raises_even_if_a_check_is_broken():
    def _broken_pid_seen_fn(pid):
        raise RuntimeError("boom")
    results = st.run_once(_broken_pid_seen_fn, alert_sink=None, timeout=0.2)
    ok, detail = results['process_visibility']
    assert ok is False
    assert "boom" in detail


# ---- self_test_loop ---------------------------------------------------------

class _StopLoop(Exception):
    pass


def _run_self_test_loop_ticks(results_per_tick, calls):
    """Drives self_test_loop for len(results_per_tick) ticks using fakes
    for both `run_once` (so no real subprocess/logging/timing happens -
    those are already covered by the run_once-level tests above) and
    `time.sleep` (so the test needs no real sleeping). Patching run_once
    rather than time.sleep alone matters: self_test_loop's own
    time.sleep(interval) call and check_process_visibility's *internal*
    polling sleep share the same time.sleep reference, so patching sleep
    without also replacing run_once would make the real subprocess-based
    check spin instead of block."""
    original_run_once, original_sleep = st.run_once, st.time.sleep
    original_critical, original_info = st.logging.critical, st.logging.info
    st.logging.critical = lambda msg: calls.append(("CRITICAL", msg))
    st.logging.info = lambda msg: calls.append(("INFO", msg))

    tick = {"n": 0}

    def _fake_run_once(pid_seen_fn, alert_sink=None, timeout=None):
        return results_per_tick[tick["n"] - 1]  # sleep() below already incremented for this tick

    def _fake_sleep(seconds):
        tick["n"] += 1
        if tick["n"] > len(results_per_tick):
            raise _StopLoop()

    st.run_once, st.time.sleep = _fake_run_once, _fake_sleep
    try:
        st.self_test_loop(lambda pid: True, alert_sink=None, interval=1, timeout=0.1)
    except _StopLoop:
        pass
    finally:
        st.run_once, st.time.sleep = original_run_once, original_sleep
        st.logging.critical, st.logging.info = original_critical, original_info


def test_self_test_loop_logs_immediately_on_first_run_failure():
    # Baseline is assumed passing, so a check failing on tick 1 must be
    # logged right away rather than waiting for a "transition".
    calls = []
    failing = {'process_visibility': (False, 'PID 1')}
    _run_self_test_loop_ticks([failing, failing], calls)
    critical_calls = [c for c in calls if c[0] == "CRITICAL"]
    assert len(critical_calls) == 1
    assert "process_visibility" in critical_calls[0][1]


def test_self_test_loop_does_not_repeat_log_for_same_result():
    calls = []
    failing = {'process_visibility': (False, 'PID 1')}
    _run_self_test_loop_ticks([failing, failing, failing, failing], calls)
    assert len(calls) == 1, f"repeated identical failures must log once, not every tick, got {calls}"


def test_self_test_loop_logs_recovery_transition():
    calls = []
    failing = {'process_visibility': (False, 'PID 1')}
    passing = {'process_visibility': (True, 'PID 1')}
    _run_self_test_loop_ticks([failing, passing, passing], calls)
    levels = [c[0] for c in calls]
    assert levels == ["CRITICAL", "INFO"], f"expected fail then recover, got {calls}"


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"OK ({len(tests)} checks)")
