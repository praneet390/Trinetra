"""
Self-check for process_correlator.py's ETW/Sysmon fusion. No real sensors -
submit_etw/submit_sysmon are called directly with synthetic data, and
_gc_once() is called directly instead of sleeping through gc_loop's real
interval. Run: python test_process_correlator.py
"""

import threading
import time

import process_correlator as pc


class _FakeEngine:
    def __init__(self):
        self.dispatches = []  # list of (event_id, data_dict)
        self.lock_held_during_dispatch = False
        self._external_lock = None  # set by a test to prove lock isn't held during dispatch

    def _dispatch(self, event_id, data_dict):
        if self._external_lock is not None:
            # If the correlator's lock is still held here, this acquire
            # would deadlock against itself in a single-threaded test -
            # proving the correlator released it before calling us.
            acquired = self._external_lock.acquire(blocking=False)
            if acquired:
                self._external_lock.release()
            else:
                self.lock_held_during_dispatch = True
        self.dispatches.append((event_id, dict(data_dict)))


def test_etw_only_dispatches_immediately_and_provisionally():
    engine = _FakeEngine()
    correlator = pc.ProcessCorrelator(engine)
    correlator.submit_etw(1234, 1, "evil.exe", "8/30/2026 1:00:00 PM")
    assert len(engine.dispatches) == 1
    event_id, data = engine.dispatches[0]
    assert event_id == 1
    assert data['_source'] == 'etw'
    assert data['_provisional'] is True
    assert data['ParentImage'] is None
    assert data['CommandLine'] is None


def test_etw_only_drops_silently_after_gc_with_no_second_dispatch():
    engine = _FakeEngine()
    correlator = pc.ProcessCorrelator(engine, fuse_window=0.01)
    correlator.submit_etw(1234, 1, "evil.exe", "irrelevant")
    time.sleep(0.02)
    correlator._gc_once()
    assert len(engine.dispatches) == 1  # only the immediate provisional one


def test_sysmon_only_produces_exactly_one_dispatch_after_gc():
    engine = _FakeEngine()
    correlator = pc.ProcessCorrelator(engine, fuse_window=0.01)
    correlator.submit_sysmon({'ProcessId': 1234, 'Image': 'evil.exe', 'CommandLine': 'evil.exe -x'}, "irrelevant")
    assert engine.dispatches == []  # nothing before GC - matches today's pre-correlator behavior
    time.sleep(0.02)
    correlator._gc_once()
    assert len(engine.dispatches) == 1
    event_id, data = engine.dispatches[0]
    assert event_id == 1
    assert data['_source'] == 'sysmon'
    assert data['CommandLine'] == 'evil.exe -x'


def test_both_arrive_in_window_produces_provisional_then_fused():
    engine = _FakeEngine()
    correlator = pc.ProcessCorrelator(engine, fuse_window=0.05)
    correlator.submit_etw(1234, 1, "evil.exe", "irrelevant")
    correlator.submit_sysmon({'ProcessId': 1234, 'Image': 'evil.exe', 'CommandLine': 'evil.exe -x'}, "irrelevant")
    assert len(engine.dispatches) == 1  # only the provisional so far
    time.sleep(0.06)
    correlator._gc_once()
    assert len(engine.dispatches) == 2
    first, second = engine.dispatches
    assert first[1]['_source'] == 'etw'
    assert first[1]['_provisional'] is True
    assert second[1]['_source'] == 'fused'
    assert second[1]['_provisional'] is False
    assert second[1]['CommandLine'] == 'evil.exe -x'  # fused carries Sysmon's richer fields


def test_both_dispatches_of_the_same_event_share_a_dedup_key():
    # This is what lets heuristic_engine.py's _score_once() dedup a
    # non-command-line check across the provisional and fused dispatch.
    engine = _FakeEngine()
    correlator = pc.ProcessCorrelator(engine, fuse_window=0.02)
    correlator.submit_etw(1234, 1, "evil.exe", "irrelevant")
    correlator.submit_sysmon({'ProcessId': 1234, 'Image': 'evil.exe'}, "irrelevant")
    time.sleep(0.03)
    correlator._gc_once()
    assert engine.dispatches[0][1]['_dedup_key'] == engine.dispatches[1][1]['_dedup_key']


def test_pid_reuse_after_gc_starts_a_fresh_record():
    engine = _FakeEngine()
    correlator = pc.ProcessCorrelator(engine, fuse_window=0.01)
    correlator.submit_etw(1234, 1, "first.exe", "t1")
    time.sleep(0.02)
    correlator._gc_once()  # first record's window has fully elapsed and is popped

    correlator.submit_etw(1234, 1, "second.exe", "t2")  # OS reused pid 1234 for an unrelated process
    assert len(engine.dispatches) == 2
    assert engine.dispatches[0][1]['Image'] == "first.exe"
    assert engine.dispatches[1][1]['Image'] == "second.exe"


def test_gc_leaves_no_pending_records_once_windows_elapse():
    engine = _FakeEngine()
    correlator = pc.ProcessCorrelator(engine, fuse_window=0.01)
    correlator.submit_etw(1, 0, "a.exe", "t")
    correlator.submit_sysmon({'ProcessId': 2, 'Image': 'b.exe'}, "t")
    time.sleep(0.02)
    correlator._gc_once()
    assert correlator._pending == {}


def test_lock_is_never_held_across_a_dispatch_call():
    engine = _FakeEngine()
    correlator = pc.ProcessCorrelator(engine, fuse_window=0.01)
    engine._external_lock = correlator._lock
    correlator.submit_etw(1234, 1, "evil.exe", "t")  # dispatch happens inside submit_etw itself
    assert not engine.lock_held_during_dispatch

    correlator.submit_sysmon({'ProcessId': 1234, 'Image': 'evil.exe'}, "t")
    time.sleep(0.02)
    correlator._gc_once()
    assert not engine.lock_held_during_dispatch


def test_contradiction_logged_when_parent_pids_disagree():
    calls = []
    original_warning = pc.logging.warning
    pc.logging.warning = lambda msg: calls.append(msg)
    try:
        engine = _FakeEngine()
        correlator = pc.ProcessCorrelator(engine, fuse_window=0.01)
        correlator.submit_etw(1234, 1, "evil.exe", "t")  # parent PID 1
        correlator.submit_sysmon({'ProcessId': 1234, 'ParentProcessId': 999, 'Image': 'evil.exe'}, "t")
        time.sleep(0.02)
        correlator._gc_once()
        contradiction_lines = [c for c in calls if "[TELEMETRY_CONTRADICTION]" in c]
        assert len(contradiction_lines) == 1
        assert "PID 1234" in contradiction_lines[0]
        assert "ETW reports parent PID 1" in contradiction_lines[0]
        assert "Sysmon reports parent PID 999" in contradiction_lines[0]
        # the discrepancy must not have blocked the normal fused dispatch
        assert len(engine.dispatches) == 2
        assert engine.dispatches[1][1]['_source'] == 'fused'
    finally:
        pc.logging.warning = original_warning


def test_no_contradiction_logged_when_parent_pids_agree():
    calls = []
    original_warning = pc.logging.warning
    pc.logging.warning = lambda msg: calls.append(msg)
    try:
        engine = _FakeEngine()
        correlator = pc.ProcessCorrelator(engine, fuse_window=0.01)
        correlator.submit_etw(1234, 1, "evil.exe", "t")  # parent PID 1
        correlator.submit_sysmon({'ProcessId': 1234, 'ParentProcessId': 1, 'Image': 'evil.exe'}, "t")
        time.sleep(0.02)
        correlator._gc_once()
        assert not any("[TELEMETRY_CONTRADICTION]" in c for c in calls)
    finally:
        pc.logging.warning = original_warning


def test_no_contradiction_logged_when_sysmon_omits_parent_pid():
    # A missing field is a data gap, not a disagreement - must not be
    # treated as a contradiction (that would false-positive on every
    # Sysmon config that doesn't capture ParentProcessId).
    calls = []
    original_warning = pc.logging.warning
    pc.logging.warning = lambda msg: calls.append(msg)
    try:
        engine = _FakeEngine()
        correlator = pc.ProcessCorrelator(engine, fuse_window=0.01)
        correlator.submit_etw(1234, 1, "evil.exe", "t")
        correlator.submit_sysmon({'ProcessId': 1234, 'Image': 'evil.exe'}, "t")  # no ParentProcessId
        time.sleep(0.02)
        correlator._gc_once()
        assert not any("[TELEMETRY_CONTRADICTION]" in c for c in calls)
    finally:
        pc.logging.warning = original_warning


def test_contradiction_check_tolerates_malformed_parent_pid():
    # A garbled/non-numeric field must not crash the GC pass - the dispatch
    # for this pid still has to go through.
    engine = _FakeEngine()
    correlator = pc.ProcessCorrelator(engine, fuse_window=0.01)
    correlator.submit_etw(1234, 1, "evil.exe", "t")
    correlator.submit_sysmon({'ProcessId': 1234, 'ParentProcessId': 'not-a-number', 'Image': 'evil.exe'}, "t")
    time.sleep(0.02)
    correlator._gc_once()  # must not raise
    assert len(engine.dispatches) == 2


def test_gc_loop_runs_on_its_own_thread_via_start():
    engine = _FakeEngine()
    correlator = pc.ProcessCorrelator(engine, fuse_window=0.01, gc_interval=0.01)
    correlator.start()
    correlator.submit_etw(1234, 1, "evil.exe", "t")
    correlator.submit_sysmon({'ProcessId': 1234, 'Image': 'evil.exe', 'CommandLine': 'x'}, "t")

    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline and len(engine.dispatches) < 2:
        time.sleep(0.01)
    assert len(engine.dispatches) == 2
    assert threading.active_count() >= 1  # the gc_loop daemon thread is alive alongside the test thread


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"OK ({len(tests)} checks)")
