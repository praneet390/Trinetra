"""
Passive liveness tracking for the two independent telemetry sensors
(Sysmon, ETW) - each sensor's start_monitor()/start_etw_monitor() calls
touch() every time it actually delivers an event, so a dead/tampered
sensor is visibly distinguishable from one that's merely quiet.

Deliberately observe-only: this watchdog logs staleness transitions and
exposes them to the dashboard, it never tries to restart a dead sensor.
Tearing down and re-establishing an EvtSubscribe handle or an ETW trace
session safely needs real handle-lifecycle care and live-fire testing
against genuine sensor death - both beyond what a non-elevated dev shell
can responsibly exercise. Auto-restart is a deliberate, separate follow-on.

Also derives one aggregate "blind state" (HEALTHY/DEGRADED/PARTIALLY_BLIND/
CRITICALLY_BLIND) from the two sensors' liveness - the point isn't "is the
watchdog thread alive" (it always is, once started), it's "how much of the
endpoint's behavioral telemetry can currently be trusted." Detection logic
should treat a lack of alerts differently depending on this state: silence
from a HEALTHY endpoint is evidence of no activity, silence from a
CRITICALLY_BLIND one is evidence of nothing at all.
"""

import logging
import threading
import time

DEFAULT_STALE_AFTER_SECONDS = 60
DEFAULT_WATCHDOG_INTERVAL_SECONDS = 15
# How long after its last dropped event a sensor still counts as "lossy".
# Any drop means the bounded queue was completely full - scoring is far
# behind - so a single drop is enough to call visibility incomplete.
DEFAULT_DROP_WINDOW_SECONDS = 60

BLIND_STATE_HEALTHY = "HEALTHY"
BLIND_STATE_DEGRADED = "DEGRADED"
BLIND_STATE_PARTIALLY_BLIND = "PARTIALLY_BLIND"
BLIND_STATE_CRITICALLY_BLIND = "CRITICALLY_BLIND"

# Log level per state on a transition - escalates with how blind the
# endpoint is, so a total loss of visibility can't get lost among INFO
# noise the way a plain "state changed" log would. Both no-sensor-live
# states are CRITICAL: dashboard_data.severity_of() maps ERROR to WARNING,
# so logging a mid-run total loss (PARTIALLY_BLIND) at ERROR - as this
# originally did - showed the more urgent of the two states as merely a
# warning. failure_lab.py's total_silence scenario is what caught that.
_BLIND_STATE_LOG_LEVEL = {
    BLIND_STATE_HEALTHY: logging.INFO,
    BLIND_STATE_DEGRADED: logging.WARNING,
    BLIND_STATE_PARTIALLY_BLIND: logging.CRITICAL,
    BLIND_STATE_CRITICALLY_BLIND: logging.CRITICAL,
}

# Negative-evidence protection: what a viewer of "0 alerts"/"0 critical"
# should be told about how much to trust that silence, per blind state.
# None for HEALTHY means exactly that - trust it, no caveat needed. Every
# other state gets an explicit reminder that absence of alerts is not
# evidence of absence, scaled to how much visibility is actually gone.
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
    """None when `state` is BLIND_STATE_HEALTHY - alert counts can be
    trusted as "no activity observed". Otherwise a short, human-readable
    explanation of why they can't be fully trusted as that, scaled to how
    degraded `state` is.

    This is the codebase's single answer to threat-model item #19
    (negative-evidence protection): detection logic - and anything that
    reports detection results to a person - must distinguish "no activity
    observed" from "activity could not be observed", and reduce confidence
    in the former whenever visibility is degraded. Centralized here (next
    to compute_blind_state, the thing that decides *how* degraded) so every
    caller reports the exact same caveat for the exact same state."""
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
    """Classify one sensor's current state for the blind-state calculation
    and the dashboard's sensor badges. `handle` is whatever start_monitor()/
    start_etw_monitor() returned at startup (None/falsy means the sensor
    never came up at all - a permanent condition for this run, e.g. no
    Administrator elevation); `health` is that sensor's SensorHealth.
    'unavailable' is a startup condition, deliberately distinct from a
    heartbeat merely going 'stale' after having been 'live' - the latter
    means something died mid-run, the former means it never ran. 'lossy'
    means the sensor is delivering but recently had to drop events because
    its queue was full: alive, yet its picture of the endpoint has holes.
    Stale wins over lossy - a sensor that has stopped is worse than one
    that is merely overloaded."""
    if not handle:
        return "unavailable"
    if health.is_stale():
        return "stale"
    return "lossy" if health.is_lossy() else "live"


def compute_blind_state(sensor_states, ever_seen_event):
    """Reduce every behavioral sensor's label ('live'/'lossy'/'stale'/
    'unavailable', see sensor_label()) to one aggregate visibility state:

    - HEALTHY: every sensor live.
    - DEGRADED: visibility is reduced but not gone - at least one sensor is
      down or dropping events (lossy), yet at least one is still delivering.
      A lossy sensor still delivers, so it never makes the endpoint worse
      than DEGRADED on its own.
    - PARTIALLY_BLIND / CRITICALLY_BLIND: no sensor delivering at all (every
      sensor stale or unavailable; a lossy one still counts as delivering). Split by
      `ever_seen_event` (pass e.g. `engine.total_events_seen > 0`) because
      "every sensor is down after having worked" (a live, in-session loss of
      visibility - PARTIALLY_BLIND) is a meaningfully different, more
      urgent situation than "no sensor has ever come up this session" (a
      known startup condition, e.g. running non-elevated - still total
      blindness, so CRITICALLY_BLIND, but not a fresh failure to react to).

    An empty sensor_states (no behavioral sensors configured at all) is
    CRITICALLY_BLIND - there is nothing to be live."""
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
    """The one place that turns live sensor objects into a blind state, so
    every caller (main.py, web_server.py, failure_lab.py) composes it
    identically instead of each re-deriving the labels by hand.

    `sensors` is an iterable of (handle, SensorHealth) pairs - `handle` is
    whatever start_monitor()/start_etw_monitor() returned (see
    sensor_label()). `engine_events_seen` is HeuristicEngine.total_events_seen.

    "Telemetry has been seen" is true if the engine counted an event OR any
    sensor has ever heartbeated. The sensors have to count too because the
    engine's counter only increments on the Sysmon path (and the no-
    correlator ETW path): with the ProcessCorrelator wired in, ETW events
    reach the engine via _dispatch and are never counted. Relying on the
    counter alone made an ETW-only deployment (no Sysmon) report a mid-run
    total loss as CRITICALLY_BLIND ("never worked") instead of
    PARTIALLY_BLIND - found by failure_lab.py's etw_only_total_loss."""
    pairs = list(sensors)
    labels = [sensor_label(handle, health) for handle, health in pairs]
    ever_seen = engine_events_seen > 0 or any(health.ever_seen() for _, health in pairs)
    return compute_blind_state(labels, ever_seen_event=ever_seen)


def watchdog_loop(sensors, interval=DEFAULT_WATCHDOG_INTERVAL_SECONDS, blind_state_fn=None, stop_event=None):
    """Runs forever (call on a daemon thread) unless `stop_event` (a
    threading.Event) is given, in which case it returns promptly once that
    is set - only failure_lab.py needs this, so it can run many isolated
    scenarios without leaking a polling thread per scenario. With
    stop_event=None (every production call site) this still sleeps via
    time.sleep(interval), exactly as before.

    Logs once on each fresh -> stale transition per sensor, not on every
    poll tick, so a long-dead sensor doesn't spam the alert feed every
    `interval` seconds. Likewise once on each transition into "lossy" (a
    live sensor that has started dropping events), naming how many it has
    dropped so far - that count is the "how much visibility was lost".

    If `blind_state_fn` is given, it's called with no arguments each tick
    and must return one of the BLIND_STATE_* constants (see
    compute_blind_state()) - the loop additionally logs every time that
    aggregate state *changes*, in either direction (getting worse or
    recovering), at a level that escalates with severity. Baseline is
    assumed HEALTHY, matching the per-sensor staleness tracking below: if
    the very first tick already isn't healthy, that's logged immediately
    rather than treated as an already-known starting condition."""
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
