"""Self-check for sensor_health.py - uses a fake monotonic clock, no real
sleeps. Run: python test_sensor_health.py"""

import sensor_health as sh
import threading

from sensor_health import (
    SensorHealth, watchdog_loop, sensor_label, compute_blind_state,
    current_blind_state, negative_evidence_caveat,
    BLIND_STATE_HEALTHY, BLIND_STATE_DEGRADED, BLIND_STATE_PARTIALLY_BLIND,
    BLIND_STATE_CRITICALLY_BLIND,
)


class _FakeClock:
    def __init__(self, start=0.0):
        self.t = start

    def __call__(self):
        return self.t

    def advance(self, seconds):
        self.t += seconds


def test_never_touched_is_stale():
    sensor = SensorHealth("test")
    assert sensor.is_stale() is True
    assert sensor.seconds_since_heartbeat() is None


def test_touch_then_fresh():
    clock = _FakeClock()
    original = sh.time.monotonic
    sh.time.monotonic = clock
    try:
        sensor = SensorHealth("test", stale_after=60)
        sensor.touch()
        assert sensor.is_stale() is False
        clock.advance(30)
        assert sensor.is_stale() is False
        assert sensor.seconds_since_heartbeat() == 30
    finally:
        sh.time.monotonic = original


def test_goes_stale_after_threshold():
    clock = _FakeClock()
    original = sh.time.monotonic
    sh.time.monotonic = clock
    try:
        sensor = SensorHealth("test", stale_after=60)
        sensor.touch()
        clock.advance(61)
        assert sensor.is_stale() is True
    finally:
        sh.time.monotonic = original


def test_touch_resets_staleness():
    clock = _FakeClock()
    original = sh.time.monotonic
    sh.time.monotonic = clock
    try:
        sensor = SensorHealth("test", stale_after=60)
        sensor.touch()
        clock.advance(61)
        assert sensor.is_stale() is True
        sensor.touch()
        assert sensor.is_stale() is False
    finally:
        sh.time.monotonic = original


def test_watchdog_logs_once_on_transition_into_stale():
    # Exercises the real watchdog_loop() - never touched, so it's stale
    # from tick 1. A fake time.sleep counts ticks and breaks the
    # otherwise-infinite loop after N ticks via a sentinel exception.
    calls = []
    original_sleep = sh.time.sleep
    original_warning = sh.logging.warning
    sh.logging.warning = lambda msg: calls.append(msg)

    tick_count = {"n": 0}

    class _StopLoop(Exception):
        pass

    def _fake_sleep(seconds):
        tick_count["n"] += 1
        if tick_count["n"] > 3:
            raise _StopLoop()

    sh.time.sleep = _fake_sleep

    try:
        sensor = SensorHealth("etw")
        try:
            watchdog_loop([sensor], interval=1)
        except _StopLoop:
            pass
        assert len(calls) == 1, f"must log once on the transition, not once per poll tick, got {calls}"
        assert "etw" in calls[0]
    finally:
        sh.time.sleep = original_sleep
        sh.logging.warning = original_warning


def test_watchdog_does_not_log_for_a_healthy_sensor():
    original_sleep = sh.time.sleep
    original_warning = sh.logging.warning
    calls = []
    sh.logging.warning = lambda msg: calls.append(msg)

    clock = _FakeClock()
    original_monotonic = sh.time.monotonic
    sh.time.monotonic = clock

    tick_count = {"n": 0}

    class _StopLoop(Exception):
        pass

    def _fake_sleep(seconds):
        tick_count["n"] += 1
        if tick_count["n"] > 3:
            raise _StopLoop()

    sh.time.sleep = _fake_sleep

    try:
        sensor = SensorHealth("sysmon", stale_after=60)
        sensor.touch()  # healthy, well under stale_after
        try:
            watchdog_loop([sensor], interval=1)
        except _StopLoop:
            pass
        assert calls == [], f"a healthy sensor must never trigger a watchdog warning, got {calls}"
    finally:
        sh.time.sleep = original_sleep
        sh.logging.warning = original_warning
        sh.time.monotonic = original_monotonic


def test_sensor_label_no_handle_is_unavailable():
    assert sensor_label(None, SensorHealth("x")) == "unavailable"
    assert sensor_label(False, SensorHealth("x")) == "unavailable"


def test_sensor_label_handle_but_never_touched_is_stale():
    assert sensor_label(object(), SensorHealth("x")) == "stale"


def test_sensor_label_handle_and_fresh_touch_is_live():
    sensor = SensorHealth("x", stale_after=60)
    sensor.touch()
    assert sensor_label(object(), sensor) == "live"


def test_blind_state_all_live_is_healthy():
    assert compute_blind_state(["live", "live"], ever_seen_event=True) == BLIND_STATE_HEALTHY


def test_blind_state_one_down_is_degraded_regardless_of_which_kind():
    assert compute_blind_state(["live", "stale"], ever_seen_event=True) == BLIND_STATE_DEGRADED
    assert compute_blind_state(["live", "unavailable"], ever_seen_event=True) == BLIND_STATE_DEGRADED
    assert compute_blind_state(["unavailable", "live"], ever_seen_event=False) == BLIND_STATE_DEGRADED


def test_blind_state_none_live_but_previously_seen_events_is_partially_blind():
    assert compute_blind_state(["stale", "stale"], ever_seen_event=True) == BLIND_STATE_PARTIALLY_BLIND
    assert compute_blind_state(["stale", "unavailable"], ever_seen_event=True) == BLIND_STATE_PARTIALLY_BLIND


def test_blind_state_none_live_and_never_seen_events_is_critically_blind():
    assert compute_blind_state(["unavailable", "unavailable"], ever_seen_event=False) == BLIND_STATE_CRITICALLY_BLIND
    assert compute_blind_state(["stale", "stale"], ever_seen_event=False) == BLIND_STATE_CRITICALLY_BLIND


def test_blind_state_no_sensors_configured_is_critically_blind():
    assert compute_blind_state([], ever_seen_event=True) == BLIND_STATE_CRITICALLY_BLIND
    assert compute_blind_state([], ever_seen_event=False) == BLIND_STATE_CRITICALLY_BLIND


def test_ever_seen_false_until_first_touch_and_stays_true_when_stale():
    clock = _FakeClock()
    original = sh.time.monotonic
    sh.time.monotonic = clock
    try:
        sensor = SensorHealth("x", stale_after=60)
        assert sensor.ever_seen() is False
        sensor.touch()
        assert sensor.ever_seen() is True
        clock.advance(600)
        assert sensor.is_stale() is True
        assert sensor.ever_seen() is True, "going stale must not erase the fact that it once delivered"
    finally:
        sh.time.monotonic = original


def test_current_blind_state_all_live_is_healthy():
    a, b = SensorHealth("a"), SensorHealth("b")
    a.touch()
    b.touch()
    assert current_blind_state([(object(), a), (object(), b)]) == BLIND_STATE_HEALTHY


def test_current_blind_state_never_seen_anything_is_critically_blind():
    assert current_blind_state([(None, SensorHealth("a")), (None, SensorHealth("b"))]) == BLIND_STATE_CRITICALLY_BLIND


def test_current_blind_state_counts_a_sensor_heartbeat_as_telemetry_seen():
    # ETW-only deployment: no Sysmon, and the engine's own event counter
    # stays 0 because ETW events reach it via the correlator's _dispatch,
    # which never increments total_events_seen. The ETW sensor had
    # delivered, then died: that is PARTIALLY_BLIND (mid-run loss), not
    # CRITICALLY_BLIND ("never worked").
    clock = _FakeClock()
    original = sh.time.monotonic
    sh.time.monotonic = clock
    try:
        etw = SensorHealth("etw", stale_after=60)
        etw.touch()
        clock.advance(61)
        state = current_blind_state([(None, SensorHealth("sysmon")), (object(), etw)], engine_events_seen=0)
        assert state == BLIND_STATE_PARTIALLY_BLIND
    finally:
        sh.time.monotonic = original


def test_current_blind_state_still_honors_the_engine_counter():
    stale = SensorHealth("x")  # never touched
    assert current_blind_state([(object(), stale)], engine_events_seen=5) == BLIND_STATE_PARTIALLY_BLIND
    assert current_blind_state([(object(), stale)], engine_events_seen=0) == BLIND_STATE_CRITICALLY_BLIND


def test_partially_blind_transition_is_logged_at_critical():
    # dashboard_data.severity_of() shows anything below CRITICAL as at most
    # WARNING, so total loss of visibility must not be logged at ERROR.
    calls = []
    original_sleep = sh.time.sleep
    original_log = sh.logging.log
    sh.logging.log = lambda level, msg: calls.append((level, msg))

    class _StopLoop(Exception):
        pass

    ticks = {"n": 0}

    def _fake_sleep(seconds):
        ticks["n"] += 1
        if ticks["n"] > 1:
            raise _StopLoop()

    sh.time.sleep = _fake_sleep
    try:
        try:
            watchdog_loop([], interval=1, blind_state_fn=lambda: BLIND_STATE_PARTIALLY_BLIND)
        except _StopLoop:
            pass
        assert calls == [(sh.logging.CRITICAL, "[BLIND-STATE] HEALTHY -> PARTIALLY_BLIND")]
    finally:
        sh.time.sleep = original_sleep
        sh.logging.log = original_log


def test_watchdog_loop_returns_promptly_when_stop_event_is_set():
    stop = threading.Event()
    thread = threading.Thread(target=watchdog_loop, args=([SensorHealth("x")],),
                              kwargs={"interval": 0.01, "stop_event": stop}, daemon=True)
    thread.start()
    stop.set()
    thread.join(timeout=2.0)
    assert not thread.is_alive(), "watchdog_loop must exit once stop_event is set"


def test_watchdog_loop_with_stop_event_still_logs_transitions():
    calls = []
    original_warning = sh.logging.warning
    sh.logging.warning = lambda msg: calls.append(msg)
    stop = threading.Event()
    thread = threading.Thread(target=watchdog_loop, args=([SensorHealth("etw")],),
                              kwargs={"interval": 0.01, "stop_event": stop}, daemon=True)
    try:
        thread.start()
        deadline = sh.time.monotonic() + 2.0
        while not calls and sh.time.monotonic() < deadline:
            sh.time.sleep(0.01)
    finally:
        stop.set()
        thread.join(timeout=2.0)
        sh.logging.warning = original_warning
    assert len(calls) == 1 and "etw" in calls[0]


def _with_fake_clock(fn):
    clock = _FakeClock()
    original = sh.time.monotonic
    sh.time.monotonic = clock
    try:
        return fn(clock)
    finally:
        sh.time.monotonic = original


def test_a_sensor_that_never_dropped_is_not_lossy():
    sensor = SensorHealth("x")
    assert sensor.is_lossy() is False
    assert sensor.drops_total() == 0


def test_record_drop_makes_a_sensor_lossy_until_the_window_passes():
    def scenario(clock):
        sensor = SensorHealth("x", drop_window=10)
        sensor.record_drop()
        assert sensor.is_lossy() is True and sensor.drops_total() == 1
        clock.advance(10)
        assert sensor.is_lossy() is True, "exactly at the window edge is still inside it"
        clock.advance(0.01)
        assert sensor.is_lossy() is False, "once the window has passed with no new drop, the sensor recovers"
        assert sensor.drops_total() == 1, "the all-time count never resets"
        sensor.record_drop()
        assert sensor.is_lossy() is True and sensor.drops_total() == 2, "a new drop starts a new window"
    _with_fake_clock(scenario)


def test_a_drop_does_not_affect_staleness():
    def scenario(clock):
        sensor = SensorHealth("x", stale_after=60)
        sensor.touch()
        sensor.record_drop()
        assert sensor.is_stale() is False
        clock.advance(61)
        assert sensor.is_stale() is True
    _with_fake_clock(scenario)


def test_sensor_label_reports_lossy_for_a_live_sensor_that_is_dropping():
    def scenario(clock):
        sensor = SensorHealth("x", stale_after=60, drop_window=30)
        sensor.touch()
        assert sensor_label(object(), sensor) == "live"
        sensor.record_drop()
        assert sensor_label(object(), sensor) == "lossy"
        clock.advance(31)
        sensor.touch()
        assert sensor_label(object(), sensor) == "live", "recovers once drops stop"
    _with_fake_clock(scenario)


def test_sensor_label_stale_and_unavailable_outrank_lossy():
    def scenario(clock):
        sensor = SensorHealth("x", stale_after=5, drop_window=100)
        sensor.touch()
        sensor.record_drop()
        clock.advance(6)  # stopped delivering, but its last drop is still inside the window
        assert sensor_label(object(), sensor) == "stale", "a stopped sensor is worse than an overloaded one"
        assert sensor_label(None, sensor) == "unavailable", "a sensor that never started is unavailable, whatever its counters say"
    _with_fake_clock(scenario)


def test_blind_state_lossy_sensor_degrades_but_never_blinds():
    # a lossy sensor is still delivering, so on its own it can only DEGRADE
    assert compute_blind_state(["live", "lossy"], ever_seen_event=True) == BLIND_STATE_DEGRADED
    assert compute_blind_state(["lossy", "live"], ever_seen_event=False) == BLIND_STATE_DEGRADED
    assert compute_blind_state(["lossy", "lossy"], ever_seen_event=True) == BLIND_STATE_DEGRADED
    assert compute_blind_state(["lossy", "lossy"], ever_seen_event=False) == BLIND_STATE_DEGRADED
    assert compute_blind_state(["lossy"], ever_seen_event=True) == BLIND_STATE_DEGRADED
    # ...alongside a sensor that is down it is the one still delivering
    assert compute_blind_state(["lossy", "stale"], ever_seen_event=True) == BLIND_STATE_DEGRADED
    assert compute_blind_state(["unavailable", "lossy"], ever_seen_event=False) == BLIND_STATE_DEGRADED
    # ...and it never rescues a state with nothing delivering
    assert compute_blind_state(["stale", "unavailable"], ever_seen_event=True) == BLIND_STATE_PARTIALLY_BLIND
    assert compute_blind_state(["live", "live"], ever_seen_event=True) == BLIND_STATE_HEALTHY


def test_current_blind_state_degrades_when_a_live_sensor_is_dropping_events():
    def scenario(clock):
        a, b = SensorHealth("a", drop_window=10), SensorHealth("b", drop_window=10)
        a.touch()
        b.touch()
        pairs = [(object(), a), (object(), b)]
        assert current_blind_state(pairs) == BLIND_STATE_HEALTHY
        b.record_drop()
        assert current_blind_state(pairs) == BLIND_STATE_DEGRADED
        clock.advance(11)
        a.touch()
        b.touch()
        assert current_blind_state(pairs) == BLIND_STATE_HEALTHY, "recovers by itself once the drops stop"
    _with_fake_clock(scenario)


def _run_watchdog_ticks(sensor, before_tick, ticks):
    """Drive watchdog_loop for `ticks` ticks with a fake sleep; before_tick(n)
    runs at the start of tick n (1-based). Returns the warnings logged."""
    warnings = []
    original_sleep, original_warning = sh.time.sleep, sh.logging.warning
    sh.logging.warning = lambda msg: warnings.append(msg)
    state = {"n": 0}

    class _Stop(Exception):
        pass

    def _fake_sleep(seconds):
        state["n"] += 1
        if state["n"] > ticks:
            raise _Stop()
        before_tick(state["n"])

    sh.time.sleep = _fake_sleep
    try:
        try:
            watchdog_loop([sensor], interval=1)
        except _Stop:
            pass
    finally:
        sh.time.sleep, sh.logging.warning = original_sleep, original_warning
    return warnings


def test_watchdog_logs_each_transition_into_lossy_once_and_names_the_count():
    def scenario(clock):
        sensor = SensorHealth("etw", stale_after=1000, drop_window=10)
        sensor.touch()

        def before_tick(n):
            if n == 1:
                for _ in range(3):
                    sensor.record_drop()   # tick 1: becomes lossy (3 dropped)
            elif n == 3:
                clock.advance(11)          # tick 3: window has passed -> recovers silently
                sensor.touch()
            elif n == 4:
                sensor.record_drop()       # tick 4: a fresh transition into lossy

        warnings = _run_watchdog_ticks(sensor, before_tick, ticks=5)
        lossy = [w for w in warnings if "dropping events" in w]
        assert len(lossy) == 2, f"one log per transition into lossy, not per tick: {warnings}"
        assert "etw" in lossy[0] and "3 dropped so far" in lossy[0]
        assert "4 dropped so far" in lossy[1], "the count is the all-time total"
        assert not any("stale" in w for w in warnings), "dropping events is not the same as being stale"
    _with_fake_clock(scenario)


def test_degraded_caveat_covers_a_sensor_that_is_dropping_events():
    caveat = negative_evidence_caveat(BLIND_STATE_DEGRADED)
    assert "dropping events" in caveat and "down" in caveat
    assert caveat != negative_evidence_caveat(BLIND_STATE_CRITICALLY_BLIND)


def test_negative_evidence_caveat_none_when_healthy():
    assert negative_evidence_caveat(BLIND_STATE_HEALTHY) is None


def test_negative_evidence_caveat_present_and_distinct_for_each_degraded_state():
    degraded = negative_evidence_caveat(BLIND_STATE_DEGRADED)
    partially_blind = negative_evidence_caveat(BLIND_STATE_PARTIALLY_BLIND)
    critically_blind = negative_evidence_caveat(BLIND_STATE_CRITICALLY_BLIND)
    for caveat in (degraded, partially_blind, critically_blind):
        assert isinstance(caveat, str) and caveat  # non-empty, real guidance
        assert "absence" in caveat.lower() or "may not reflect" in caveat.lower() \
            or "detections may be" in caveat.lower()
    # each state's caveat must actually be distinct text, not one generic
    # line reused everywhere - a DEGRADED endpoint and a CRITICALLY_BLIND
    # one warrant different confidence, not the same warning.
    assert len({degraded, partially_blind, critically_blind}) == 3


def test_negative_evidence_caveat_unknown_state_still_returns_a_caveat():
    # Must fail safe: an unrecognized state must never be silently trusted
    # as if it were HEALTHY (i.e. must never return None).
    assert negative_evidence_caveat("SOME_FUTURE_STATE") is not None


def test_watchdog_logs_blind_state_transition():
    calls = []
    original_sleep = sh.time.sleep
    original_log = sh.logging.log
    sh.logging.log = lambda level, msg: calls.append((level, msg))

    tick_count = {"n": 0}

    class _StopLoop(Exception):
        pass

    def _fake_sleep(seconds):
        tick_count["n"] += 1
        if tick_count["n"] > 2:
            raise _StopLoop()

    sh.time.sleep = _fake_sleep

    # Immediately CRITICALLY_BLIND from tick 1 (baseline is assumed
    # HEALTHY, mirroring the per-sensor staleness convention above), then
    # stays there - must log exactly once, not once per tick.
    states_fn = lambda: BLIND_STATE_CRITICALLY_BLIND

    try:
        try:
            watchdog_loop([], interval=1, blind_state_fn=states_fn)
        except _StopLoop:
            pass
        assert len(calls) == 1, f"must log once on the transition, not once per poll tick, got {calls}"
        level, msg = calls[0]
        assert level == sh.logging.CRITICAL
        assert "HEALTHY -> CRITICALLY_BLIND" in msg
    finally:
        sh.time.sleep = original_sleep
        sh.logging.log = original_log


def test_watchdog_logs_blind_state_recovery():
    calls = []
    original_sleep = sh.time.sleep
    original_log = sh.logging.log
    sh.logging.log = lambda level, msg: calls.append((level, msg))

    tick_count = {"n": 0}
    state = {"value": BLIND_STATE_CRITICALLY_BLIND}

    class _StopLoop(Exception):
        pass

    def _fake_sleep(seconds):
        tick_count["n"] += 1
        if tick_count["n"] == 2:
            state["value"] = BLIND_STATE_HEALTHY  # recovers before tick 2's check
        if tick_count["n"] > 3:
            raise _StopLoop()

    sh.time.sleep = _fake_sleep

    try:
        try:
            watchdog_loop([], interval=1, blind_state_fn=lambda: state["value"])
        except _StopLoop:
            pass
        assert len(calls) == 2, f"must log both the drop and the recovery, got {calls}"
        assert calls[0] == (sh.logging.CRITICAL, "[BLIND-STATE] HEALTHY -> CRITICALLY_BLIND")
        assert calls[1] == (sh.logging.INFO, "[BLIND-STATE] CRITICALLY_BLIND -> HEALTHY")
    finally:
        sh.time.sleep = original_sleep
        sh.logging.log = original_log


def test_watchdog_without_blind_state_fn_behaves_exactly_as_before():
    # blind_state_fn defaults to None - existing call sites (and the tests
    # above it in this file) that never pass it must see zero behavior
    # change, and specifically never call logging.log.
    calls = []
    original_sleep = sh.time.sleep
    original_log = sh.logging.log
    sh.logging.log = lambda level, msg: calls.append((level, msg))

    tick_count = {"n": 0}

    class _StopLoop(Exception):
        pass

    def _fake_sleep(seconds):
        tick_count["n"] += 1
        if tick_count["n"] > 3:
            raise _StopLoop()

    sh.time.sleep = _fake_sleep

    try:
        try:
            watchdog_loop([], interval=1)
        except _StopLoop:
            pass
        assert calls == []
    finally:
        sh.time.sleep = original_sleep
        sh.logging.log = original_log


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"OK ({len(tests)} checks)")
