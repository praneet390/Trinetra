"""
Passive liveness tracking for Sysmon, ETW, and kernel driver sensors.
Observe-only: never restarts a dead sensor - safe handle teardown for
EvtSubscribe/ETW requires live-fire testing that a dev shell can't do.
Derives aggregate blind state (HEALTHY/DEGRADED/PARTIALLY_BLIND/CRITICALLY_BLIND):
silence from HEALTHY = no activity; silence from CRITICALLY_BLIND = nothing observed.
"""

import logging
import threading
import time

DEFAULT_STALE_AFTER_SECONDS = 60
DEFAULT_WATCHDOG_INTERVAL_SECONDS = 15
# Any drop means the bounded queue was full; a single drop is enough to call visibility incomplete.
DEFAULT_DROP_WINDOW_SECONDS = 60

BLIND_STATE_HEALTHY = "HEALTHY"
BLIND_STATE_DEGRADED = "DEGRADED"
BLIND_STATE_PARTIALLY_BLIND = "PARTIALLY_BLIND"
BLIND_STATE_CRITICALLY_BLIND = "CRITICALLY_BLIND"

# PARTIALLY_BLIND is CRITICAL not ERROR: severity_of() maps ERROR → WARNING,
# so logging it at ERROR made a mid-run visibility loss show as a warning.
# failure_lab.py's total_silence scenario caught that.
_BLIND_STATE_LOG_LEVEL = {
    BLIND_STATE_HEALTHY: logging.INFO,
    BLIND_STATE_DEGRADED: logging.WARNING,
    BLIND_STATE_PARTIALLY_BLIND: logging.CRITICAL,
    BLIND_STATE_CRITICALLY_BLIND: logging.CRITICAL,
}

# Human-readable caveat per blind state; None for HEALTHY means trust the silence.
_BLIND_STATE_CAVEATS = {
    BLIND_STATE_HEALTHY: None,
    BLIND_STATE_DEGRADED: (
        "A telemetry sensor is down or dropping events - process visibility "
        "continues from what remains, but some detections may be delayed or missed."
    ),
    BLIND_STATE_PARTIALLY_BLIND: (
        "No behavioral sensor is currently live. Alert counts may not "
        "reflect current activity - absence of alerts is not evidence of absence."
    ),
    BLIND_STATE_CRITICALLY_BLIND: (
        "No telemetry has been observed this session. Alert counts reflect "
        "nothing about current activity - absence of alerts is not evidence of absence."
    ),
}


def negative_evidence_caveat(state):
    """None when HEALTHY (silence can be trusted). Otherwise a human-readable caveat
    explaining why absence of alerts isn't evidence of absence, scaled to degradation."""
    return _BLIND_STATE_CAVEATS.get(
        state, "Visibility state unknown - alert counts cannot be trusted as complete."
    )


class SensorHealth:
    def __init__(self, name, stale_after=DEFAULT_STALE_AFTER_SECONDS, drop_window=DEFAULT_DROP_WINDOW_SECONDS):
        self.name = name
        self.stale_after = stale_after
        self.drop_window = drop_window
        self._lock = threading.Lock()
        self._last_heartbeat = None
        self._last_drop = None
        self._drops_total = 0

    def touch(self):
        with self._lock:
            self._last_heartbeat = time.monotonic()

    def record_drop(self):
        """The sensor observed an event but had to discard it (its bounded
        queue was full). Called from the sensor's OS callback thread."""
        with self._lock:
            self._last_drop = time.monotonic()
            self._drops_total += 1

    def is_lossy(self):
        """True if an event was dropped within the last `drop_window` seconds:
        the sensor is alive and delivering, but visibility is incomplete."""
        with self._lock:
            return self._last_drop is not None and (time.monotonic() - self._last_drop) <= self.drop_window

    def drops_total(self):
        with self._lock:
            return self._drops_total

    def seconds_since_heartbeat(self):
        with self._lock:
            if self._last_heartbeat is None:
                return None
            return time.monotonic() - self._last_heartbeat

    def is_stale(self):
        age = self.seconds_since_heartbeat()
        return age is None or age > self.stale_after

    def ever_seen(self):
        """True once this sensor has delivered at least one event, ever."""
        with self._lock:
            return self._last_heartbeat is not None


def sensor_label(handle, health):
    """'unavailable' = never started (startup condition, e.g. no elevation).
    'stale' = was live, stopped mid-run. 'lossy' = live but dropping events (queue full).
    Stale wins over lossy: stopped is worse than overloaded."""
    if not handle:
        return "unavailable"
    if health.is_stale():
        return "stale"
    return "lossy" if health.is_lossy() else "live"


def compute_blind_state(sensor_states, ever_seen_event):
    """Reduce sensor labels to one aggregate visibility state.
    HEALTHY: all live. DEGRADED: ≥1 down but ≥1 still delivering.
    PARTIALLY_BLIND: none delivering, but at least one worked this session.
    CRITICALLY_BLIND: none delivering and nothing was ever seen (startup condition).
    Empty sensor_states → CRITICALLY_BLIND."""
    states = list(sensor_states)
    if not states:
        return BLIND_STATE_CRITICALLY_BLIND
    live_count = sum(1 for s in states if s == "live")
    if live_count == len(states):
        return BLIND_STATE_HEALTHY
    delivering_count = sum(1 for s in states if s in ("live", "lossy"))
    if delivering_count > 0:
        return BLIND_STATE_DEGRADED
    return BLIND_STATE_PARTIALLY_BLIND if ever_seen_event else BLIND_STATE_CRITICALLY_BLIND


def current_blind_state(sensors, engine_events_seen=0):
    """Compute blind state from live sensor objects.
    "Telemetry seen" checks engine counter OR sensor heartbeat: the engine counter
    only increments on the Sysmon path, so an ETW-only deployment via ProcessCorrelator
    would otherwise report CRITICALLY_BLIND instead of PARTIALLY_BLIND (found by
    failure_lab.py's etw_only_total_loss)."""
    pairs = list(sensors)
    labels = [sensor_label(handle, health) for handle, health in pairs]
    ever_seen = engine_events_seen > 0 or any(health.ever_seen() for _, health in pairs)
    return compute_blind_state(labels, ever_seen_event=ever_seen)


def watchdog_loop(sensors, interval=DEFAULT_WATCHDOG_INTERVAL_SECONDS, blind_state_fn=None, stop_event=None):
    """Runs forever on a daemon thread. stop_event is only for failure_lab.py to
    avoid leaking a polling thread per isolated scenario.
    Logs once per staleness/lossy transition (not every tick) to avoid spamming
    the feed when a sensor stays dead for a long time."""
    was_stale = {sensor.name: False for sensor in sensors}
    was_lossy = {sensor.name: False for sensor in sensors}
    last_blind_state = BLIND_STATE_HEALTHY
    while True:
        if stop_event is None:
            time.sleep(interval)
        elif stop_event.wait(interval):
            return
        for sensor in sensors:
            stale_now = sensor.is_stale()
            if stale_now and not was_stale[sensor.name]:
                age = sensor.seconds_since_heartbeat()
                age_desc = "no events ever received" if age is None else f"last event {round(age)}s ago"
                logging.warning(f"[WATCHDOG] {sensor.name} sensor stale - {age_desc}")
            was_stale[sensor.name] = stale_now

            lossy_now = sensor.is_lossy()
            if lossy_now and not was_lossy[sensor.name]:
                logging.warning(
                    f"[WATCHDOG] {sensor.name} sensor dropping events - {sensor.drops_total()} "
                    f"dropped so far (its queue is full; scoring is falling behind)"
                )
            was_lossy[sensor.name] = lossy_now

        if blind_state_fn is not None:
            state = blind_state_fn()
            if state != last_blind_state:
                level = _BLIND_STATE_LOG_LEVEL.get(state, logging.WARNING)
                logging.log(level, f"[BLIND-STATE] {last_blind_state} -> {state}")
                last_blind_state = state
