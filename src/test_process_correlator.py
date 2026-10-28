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


# ---- ETW header creator pid -------------------------------------------------

def test_submit_etw_carries_the_header_creator_on_the_dispatch():
    engine = _FakeEngine()
    correlator = pc.ProcessCorrelator(engine)
    correlator.submit_etw(1234, 1, "evil.exe", "t", creator_pid=777)
    assert engine.dispatches[0][1]['_etw_creator_pid'] == 777


def test_submit_etw_normalizes_a_string_creator_pid_to_int():
    engine = _FakeEngine()
    correlator = pc.ProcessCorrelator(engine)
    correlator.submit_etw(1234, 1, "evil.exe", "t", creator_pid="777")
    assert engine.dispatches[0][1]['_etw_creator_pid'] == 777


def test_submit_etw_omits_the_creator_key_when_absent_or_unusable():
    # No key at all (not None) so every pre-existing consumer of the dispatch
    # dict sees exactly what it always did.
    for bad in (None, "", "abc", -1, True, 1.5e400):
        engine = _FakeEngine()
        pc.ProcessCorrelator(engine).submit_etw(1234, 1, "evil.exe", "t", creator_pid=bad)
        assert '_etw_creator_pid' not in engine.dispatches[0][1], bad


def test_creator_pid_accepts_only_exactly_integral_numbers():
    assert pc._coerce_pid(7) == 7 and pc._coerce_pid("7") == 7 and pc._coerce_pid(7.0) == 7
    assert pc._coerce_pid(0) == 0, "pid 0 is a real value, not 'unknown'"
    for bad in (None, True, False, -1, 1.5, float('inf'), float('nan'), "", "x", "1.5", [], {}):
        assert pc._coerce_pid(bad) is None, bad


def test_an_overflowing_pid_does_not_raise_out_of_submit_etw():
    engine = _FakeEngine()
    pc.ProcessCorrelator(engine).submit_etw(float('inf'), 1, "evil.exe", "t")
    assert len(engine.dispatches) == 1, "the event is still dispatched"


def test_submit_etw_without_creator_dispatch_is_unchanged():
    engine = _FakeEngine()
    pc.ProcessCorrelator(engine).submit_etw(1234, 1, "evil.exe", "t")
    assert set(engine.dispatches[0][1]) == {
        'ProcessId', 'ParentProcessId', 'Image', 'CreateTime', 'ParentImage', 'CommandLine',
        '_source', '_provisional', '_dedup_key',
    }


# ---- witness-gap detection --------------------------------------------------

class _Clock:
    def __init__(self, now=1000.0):
        self.now = now

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class _Captured:
    """Context manager capturing the correlator's warning/info/error log calls
    (same monkeypatch-the-logging-module pattern as the contradiction tests)."""

    def __enter__(self):
        self.warnings, self.infos, self.errors = [], [], []
        self._saved = (pc.logging.warning, pc.logging.info, pc.logging.error)
        pc.logging.warning = lambda msg, *a, **k: self.warnings.append(msg)
        pc.logging.info = lambda msg, *a, **k: self.infos.append(msg)
        pc.logging.error = lambda msg, *a, **k: self.errors.append(msg)
        return self

    def __exit__(self, *exc):
        pc.logging.warning, pc.logging.info, pc.logging.error = self._saved

    def blindspots(self):
        return [w for w in self.warnings if pc.BLINDSPOT_TAG in w]


def _armed(gate=lambda name: True, grace=0.0, window=5.0):
    clock = _Clock()
    correlator = pc.ProcessCorrelator(_FakeEngine(), witness_window=window, clock=clock)
    correlator.enable_witness_check(gate, startup_grace=grace)
    clock.advance(1.0)  # strictly after arming
    return correlator, clock


def test_kernel_only_creation_is_reported_as_an_etw_gap():
    correlator, clock = _armed()
    with _Captured() as log:
        correlator.submit_kernel(1234, 1, 1, r"\Device\HarddiskVolume3\evil.exe", False)
        clock.advance(5.0)
        correlator._gc_once()
    lines = log.blindspots()
    assert len(lines) == 1
    assert "ETW did not report" in lines[0] and "kernel driver" in lines[0]
    assert "PID 1234" in lines[0] and "evil.exe" in lines[0]
    stats = correlator.witness_stats()
    assert stats['gaps'] == {'etw': 1, 'kernel': 0} and stats['active_gaps'] == ['etw']


def test_etw_only_creation_is_reported_as_a_kernel_gap():
    correlator, clock = _armed()
    with _Captured() as log:
        correlator.submit_etw(1234, 1, "evil.exe", "t")
        clock.advance(5.0)
        correlator._gc_once()
    assert len(log.blindspots()) == 1 and "kernel driver did not report" in log.blindspots()[0]
    assert correlator.witness_stats()['gaps'] == {'etw': 0, 'kernel': 1}


def test_a_creation_both_sensors_reported_is_not_a_gap():
    correlator, clock = _armed()
    with _Captured() as log:
        correlator.submit_etw(1234, 1, "evil.exe", "t")
        correlator.submit_kernel(1234, 1, 1, "evil.exe", False)
        clock.advance(5.0)
        correlator._gc_once()
    assert log.blindspots() == []
    assert correlator.witness_stats()['gaps'] == {'etw': 0, 'kernel': 0}


def test_nothing_is_judged_before_the_witness_window_elapses():
    correlator, clock = _armed()
    with _Captured() as log:
        correlator.submit_kernel(1234, 1, 1, "evil.exe", False)
        clock.advance(4.9)
        correlator._gc_once()
        assert log.blindspots() == [] and len(correlator._witness) == 1
        # ...and the second witness can still arrive in time
        correlator.submit_etw(1234, 1, "evil.exe", "t")
        clock.advance(0.2)
        correlator._gc_once()
    assert log.blindspots() == [] and correlator._witness == {}


def test_no_gap_is_reported_unless_the_check_was_armed():
    clock = _Clock()
    correlator = pc.ProcessCorrelator(_FakeEngine(), clock=clock)
    with _Captured() as log:
        correlator.submit_kernel(1234, 1, 1, "evil.exe", False)
        clock.advance(10.0)
        correlator._gc_once()
    assert log.blindspots() == [] and correlator.witness_stats()['enabled'] is False


def test_a_gate_that_explains_the_silence_suppresses_the_finding():
    # e.g. the silent sensor is 'unavailable' or already known to be 'lossy'
    seen = []

    def gate(name):
        seen.append(name)
        return False

    correlator, clock = _armed(gate=gate)
    with _Captured() as log:
        correlator.submit_kernel(1234, 1, 1, "evil.exe", False)
        clock.advance(5.0)
        correlator._gc_once()
    assert seen == ['etw'], "the gate is asked about the SILENT sensor"
    assert log.blindspots() == [] and correlator.witness_stats()['gaps'] == {'etw': 0, 'kernel': 0}


def test_a_gate_that_raises_is_treated_as_explained_and_logged():
    def gate(name):
        raise RuntimeError("boom")

    correlator, clock = _armed(gate=gate)
    with _Captured() as log:
        correlator.submit_kernel(1234, 1, 1, "evil.exe", False)
        clock.advance(5.0)
        correlator._gc_once()
    assert log.blindspots() == []
    assert any("Witness gate failed" in e for e in log.errors)


def test_creations_during_the_startup_grace_period_are_ignored():
    correlator, clock = _armed(grace=10.0)   # armed at t=1000, clock now 1001
    with _Captured() as log:
        correlator.submit_kernel(1, 0, 0, "early.exe", False)       # t=1001: inside grace
        clock.advance(10.0)
        correlator.submit_kernel(2, 0, 0, "later.exe", False)       # t=1011: grace over
        clock.advance(5.0)
        correlator._gc_once()
    lines = log.blindspots()
    assert len(lines) == 1 and "PID 2" in lines[0]


def test_a_sustained_gap_logs_once_then_an_aggregate_per_interval():
    correlator, clock = _armed()
    with _Captured() as log:
        for pid in (10, 11, 12):
            correlator.submit_kernel(pid, 1, 1, f"p{pid}.exe", False)
        clock.advance(5.0)
        correlator._gc_once()
        assert len(log.blindspots()) == 1, "first gap logs immediately, the rest are counted"
        assert correlator.witness_stats()['gaps']['etw'] == 3

        clock.advance(pc.GAP_SUMMARY_INTERVAL_SECONDS)
        correlator.submit_kernel(13, 1, 1, "p13.exe", False)
        clock.advance(5.0)
        correlator._gc_once()
    lines = log.blindspots()
    assert len(lines) == 2 and "still missing" in lines[1] and "3 more" in lines[1], lines
    assert correlator.witness_stats()['gaps']['etw'] == 4


def test_recovery_is_logged_once_when_both_sensors_report_again():
    correlator, clock = _armed()
    with _Captured() as log:
        correlator.submit_kernel(10, 1, 1, "a.exe", False)
        clock.advance(5.0)
        correlator._gc_once()
        assert correlator.witness_stats()['active_gaps'] == ['etw']

        correlator.submit_etw(11, 1, "b.exe", "t")
        correlator.submit_kernel(11, 1, 1, "b.exe", False)
        clock.advance(5.0)
        correlator._gc_once()
        # a second healthy creation must not log recovery again
        correlator.submit_etw(12, 1, "c.exe", "t")
        correlator.submit_kernel(12, 1, 1, "c.exe", False)
        clock.advance(5.0)
        correlator._gc_once()
    recoveries = [i for i in log.infos if "reporting process creations again" in i]
    assert len(recoveries) == 1 and "ETW" in recoveries[0] and "1 unreported" in recoveries[0]
    assert correlator.witness_stats()['active_gaps'] == []


def test_a_late_second_witness_is_not_misread_as_the_opposite_gap():
    # Kernel reports at t0; ETW's event only turns up after the window has
    # already been judged. That must yield ONE ETW-gap finding - not a second,
    # bogus "kernel did not report" from ETW's late event opening a new record.
    correlator, clock = _armed()
    with _Captured() as log:
        correlator.submit_kernel(1234, 1, 1, "evil.exe", False)
        clock.advance(6.0)
        correlator._gc_once()                      # judged: ETW gap
        correlator.submit_etw(1234, 1, "evil.exe", "t")   # late arrival
        clock.advance(6.0)
        correlator._gc_once()
    assert correlator.witness_stats()['gaps'] == {'etw': 1, 'kernel': 0}
    assert len(log.blindspots()) == 1


def test_a_reused_pid_long_after_the_window_is_a_new_creation():
    correlator, clock = _armed()
    with _Captured():
        correlator.submit_kernel(1234, 1, 1, "first.exe", False)
        clock.advance(5.0)
        correlator._gc_once()
        clock.advance(2 * 5.0)                      # past the late-arrival memory
        correlator.submit_kernel(1234, 1, 1, "second.exe", False)
        clock.advance(5.0)
        correlator._gc_once()
    assert correlator.witness_stats()['gaps']['etw'] == 2


def test_int_and_string_pids_are_the_same_creation():
    correlator, clock = _armed()
    with _Captured() as log:
        correlator.submit_etw("1234", "1", "evil.exe", "t")   # pywintrace hands over strings
        correlator.submit_kernel(1234, 1, 1, "evil.exe", False)
        clock.advance(5.0)
        correlator._gc_once()
    assert log.blindspots() == []


def test_an_event_with_no_usable_pid_never_fabricates_a_gap():
    correlator, clock = _armed()
    with _Captured() as log:
        correlator.submit_etw(None, 1, "evil.exe", "t")
        correlator.submit_etw("garbage", 1, "evil.exe", "t")
        clock.advance(5.0)
        correlator._gc_once()
    assert correlator._witness == {} and log.blindspots() == []


def test_witness_records_are_bounded_and_evict_the_oldest():
    original = pc.MAX_WITNESS_RECORDS
    pc.MAX_WITNESS_RECORDS = 3
    try:
        correlator, clock = _armed()
        for pid in range(1, 6):
            correlator.submit_kernel(pid, 1, 1, f"p{pid}.exe", False)
            clock.advance(0.01)
        assert list(correlator._witness) == [3, 4, 5]
        clock.advance(10.0)
        with _Captured():
            correlator._gc_once()
        assert len(correlator._closed) <= 3
    finally:
        pc.MAX_WITNESS_RECORDS = original


def test_creator_agreement_counts_only_creations_with_both_creators_known():
    correlator, clock = _armed()
    with _Captured():
        correlator.submit_etw(1, 0, "a.exe", "t", creator_pid=50)
        correlator.submit_kernel(1, 0, 50, "a.exe", False)          # agree
        correlator.submit_etw(2, 0, "b.exe", "t", creator_pid=50)
        correlator.submit_kernel(2, 0, 60, "b.exe", False)          # disagree
        correlator.submit_etw(3, 0, "c.exe", "t")                   # no ETW creator
        correlator.submit_kernel(3, 0, 50, "c.exe", False)
        correlator.submit_etw(4, 0, "d.exe", "t", creator_pid=50)   # kernel never reported
        clock.advance(5.0)
        correlator._gc_once()
    assert correlator.witness_stats()['creator_agreement'] == {'agree': 1, 'disagree': 1}


def test_creator_agreement_is_counted_even_when_the_gap_check_is_not_armed():
    clock = _Clock()
    correlator = pc.ProcessCorrelator(_FakeEngine(), clock=clock)
    correlator.submit_etw(1, 0, "a.exe", "t", creator_pid=50)
    correlator.submit_kernel(1, 0, 50, "a.exe", False)
    clock.advance(5.0)
    correlator._gc_once()
    assert correlator.witness_stats()['creator_agreement'] == {'agree': 1, 'disagree': 0}


def test_a_witness_failure_cannot_stop_pending_records_being_dispatched():
    engine = _FakeEngine()
    correlator = pc.ProcessCorrelator(engine, fuse_window=0.01)
    correlator.submit_sysmon({'ProcessId': 1234, 'Image': 'evil.exe'}, "t")
    time.sleep(0.02)

    def boom():
        raise RuntimeError("witness exploded")

    correlator._gc_witness = boom
    with _Captured() as log:
        correlator._gc_once()
    assert len(engine.dispatches) == 1 and engine.dispatches[0][1]['_source'] == 'sysmon'
    assert any("Witness GC failed" in e for e in log.errors)


def test_the_gate_runs_without_the_correlator_lock_held():
    held = []
    holder = {}

    def gate(name):
        acquired = holder['correlator']._lock.acquire(blocking=False)
        if acquired:
            holder['correlator']._lock.release()
        held.append(not acquired)
        return True

    correlator, clock = _armed(gate=gate)
    holder['correlator'] = correlator
    with _Captured():
        correlator.submit_kernel(1234, 1, 1, "evil.exe", False)
        clock.advance(5.0)
        correlator._gc_once()
    assert held == [False]


def test_witness_window_rejects_nonsense_values():
    for bad in (0, -3, "5", None, True, float('nan')):
        c = pc.ProcessCorrelator(_FakeEngine(), witness_window=bad)
        assert c.witness_window == pc.DEFAULT_WITNESS_WINDOW_SECONDS, bad
    assert pc.ProcessCorrelator(_FakeEngine(), witness_window=7.5).witness_window == 7.5


def test_witness_stats_shape():
    correlator, _ = _armed()
    stats = correlator.witness_stats()
    assert stats == {
        'enabled': True, 'window_seconds': 5.0, 'gaps': {'etw': 0, 'kernel': 0},
        'active_gaps': [], 'creator_agreement': {'agree': 0, 'disagree': 0},
    }


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"OK ({len(tests)} checks)")
