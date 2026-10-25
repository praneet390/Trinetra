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


def test_submit_kernel_dispatches_immediately_with_kernel_fields():
    # Kernel-sourced process-create (see kernel_sensor.py/sensor.c) - like
    # ETW's provisional dispatch, this is deliberately NOT merged into the
    # pending etw/sysmon fusion dict (see submit_kernel's own docstring):
    # one dispatch, right away, every time.
    engine = _FakeEngine()
    correlator = pc.ProcessCorrelator(engine)
    correlator.submit_kernel(1234, 1, 999, "evil.exe", ppid_spoof_detected=True)
    assert len(engine.dispatches) == 1
    event_id, data = engine.dispatches[0]
    assert event_id == 1
    assert data['ProcessId'] == 1234
    assert data['ParentProcessId'] == 1
    assert data['Image'] == "evil.exe"
    assert data['ParentImage'] is None
    assert data['CommandLine'] is None
    assert data['_source'] == 'kernel'
    assert data['_kernel_real_creator_pid'] == 999
    assert data['_kernel_ppid_spoof_detected'] is True


def test_submit_kernel_sets_dedup_key_to_pid():
    # Regression test for a real bug found via reports/evasion_matrix.md's
    # live testing: submit_kernel used to omit '_dedup_key' entirely, which
    # HeuristicEngine._score_once() reads as "no correlator in front of
    # this dispatch, score unconditionally" - the exact opposite of what's
    # true here. That silently double-scored every _score_once-routed
    # check (staging_dir, defender_tamper, powershell_abuse, office_lolbin)
    # for every real process the kernel sensor and ETW/Sysmon both observe,
    # which is the normal case whenever the kernel driver is running, not
    # an edge case. kernel_ppid_spoof itself was never double-scored (it's
    # gated to only ever run on this dispatch), so this bug had no test
    # already covering it.
    engine = _FakeEngine()
    correlator = pc.ProcessCorrelator(engine)
    correlator.submit_kernel(1234, 1, 999, "evil.exe", ppid_spoof_detected=True)
    assert engine.dispatches[0][1]['_dedup_key'] == 1234


def test_kernel_and_etw_dispatches_for_the_same_pid_share_a_dedup_key():
    # The actual cross-sensor guarantee the bug above broke: a kernel
    # dispatch and an ETW dispatch for the SAME real pid must land in the
    # same dedup bucket, the same way two etw/sysmon dispatches already do
    # (test_both_dispatches_of_the_same_event_share_a_dedup_key above) -
    # otherwise HeuristicEngine._score_once() can't tell they're the same
    # real process-create event.
    engine = _FakeEngine()
    correlator = pc.ProcessCorrelator(engine)
    correlator.submit_etw(1234, 1, "evil.exe", "irrelevant")
    correlator.submit_kernel(1234, 1, 999, "evil.exe", ppid_spoof_detected=False)
    assert engine.dispatches[0][1]['_dedup_key'] == engine.dispatches[1][1]['_dedup_key']


def test_submit_kernel_never_merges_with_a_pending_etw_or_sysmon_record():
    # A kernel event and an ETW/Sysmon event for the SAME pid arriving close
    # together must not fuse into one record the way etw+sysmon do for each
    # other - the kernel path is independent corroboration, not a third
    # input to that fusion (see submit_kernel's docstring).
    engine = _FakeEngine()
    correlator = pc.ProcessCorrelator(engine, fuse_window=0.01)
    correlator.submit_etw(1234, 1, "evil.exe", "irrelevant")
    correlator.submit_kernel(1234, 1, 999, "evil.exe", ppid_spoof_detected=False)
    time.sleep(0.02)
    correlator._gc_once()
    # etw's own provisional dispatch, plus kernel's own immediate dispatch -
    # two independent dispatches (sysmon never arrived, so etw drops
    # silently after gc per test_etw_only_drops_silently_after_gc_with_no_
    # second_dispatch - never a merged third).
    assert len(engine.dispatches) == 2
    sources = [d['_source'] for _, d in engine.dispatches]
    assert sources.count('kernel') == 1
    assert sources.count('etw') == 1


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


def test_etw_int_pid_and_sysmon_str_pid_still_fuse():
    # Regression test for a real bug found via reports/evasion_matrix.md's
    # live testing, one level deeper than the submit_kernel dedup_key bug
    # above: evaluate_event()'s real XML parsing (src/heuristic_engine.py)
    # reads 'ProcessId' straight from an ElementTree .text node, which is
    # ALWAYS a str - never cast to int anywhere before reaching
    # submit_sysmon. Every other test in this file (including the one
    # right below) passes submit_sysmon a synthetic dict with an int
    # ProcessId, which never exercises this - int 1234 and str '1234' are
    # different dict keys, so without normalizing, this would silently
    # produce two independent dispatches (etw-provisional + sysmon-only)
    # instead of one real fused one, and skip _check_ancestry_contradiction
    # entirely. Confirmed via a direct realistic-type repro before this
    # fix: exactly that - 2 dispatches, '_dedup_key' of mismatched types.
    engine = _FakeEngine()
    correlator = pc.ProcessCorrelator(engine, fuse_window=0.01)
    correlator.submit_etw(1234, 1, "evil.exe", "irrelevant")  # realistic: int
    correlator.submit_sysmon({'ProcessId': '1234', 'Image': 'evil.exe'}, "irrelevant")  # realistic: str
    time.sleep(0.02)
    correlator._gc_once()
    sources = [d[1]['_source'] for d in engine.dispatches]
    assert sources == ['etw', 'fused'], f"expected a real fused dispatch, got {sources}"
    assert engine.dispatches[0][1]['_dedup_key'] == engine.dispatches[1][1]['_dedup_key']


def test_kernel_int_pid_and_sysmon_str_pid_share_a_dedup_key():
    # Same type mismatch as above, for the kernel sensor's always-genuine
    # int (struct.unpack) against Sysmon's always-str (XML .text) pid.
    engine = _FakeEngine()
    correlator = pc.ProcessCorrelator(engine, fuse_window=0.01)
    correlator.submit_kernel(5678, 1, 999, "evil.exe", ppid_spoof_detected=False)
    correlator.submit_sysmon({'ProcessId': '5678', 'Image': 'evil.exe'}, "irrelevant")
    time.sleep(0.02)
    correlator._gc_once()
    kernel_dispatch = next(d for d in engine.dispatches if d[1]['_source'] == 'kernel')
    sysmon_dispatch = next(d for d in engine.dispatches if d[1]['_source'] == 'sysmon')
    assert kernel_dispatch[1]['_dedup_key'] == sysmon_dispatch[1]['_dedup_key']


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
